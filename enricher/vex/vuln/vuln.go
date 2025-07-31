// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package vuln contains an Enricher that adds vuln matching data
// to software packages by querying deps.dev
package vuln

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/depsdev"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	depsdevpb "deps.dev/api/v3"
)

const (
	// Name is the unique name of this Enricher.
	Name    = "vex/vuln"
	version = 1
)

const maxConcurrentRequests = 1000

var _ enricher.Enricher = &Enricher{}

type Enricher struct {
	client Client
}

// New creates a new Enricher
func New() enricher.Enricher {
	return &Enricher{}
}

// NewWithClient creates a new Enricher with the specified client
func NewWithClient(client Client) enricher.Enricher {
	return &Enricher{
		client: client,
	}
}

// Name of the Enricher.
func (Enricher) Name() string {
	return Name
}

// Version of the Enricher.
func (Enricher) Version() int {
	return version
}

// Requirements of the Enricher.
// Needs network access so it can query deps.dev.
func (Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network: plugin.NetworkOnline,
	}
}

// RequiredPlugins returns the plugins that are required to be enabled for this
// Enricher to run. While it works on the results of other extractors,
// the Enricher itself can run independently.
func (Enricher) RequiredPlugins() []string {
	return []string{}
}

func (e *Enricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	if e.client == nil {
		// TODO: cannot use scalibr.ScannerVersion in the user agent due to an import cycle.
		// To fix move the ScannerVersion inside a `version package`
		depsDevAPIClient, err := datasource.NewCachedInsightsClient(depsdev.DepsdevAPI, "osv-scalibr")
		if err != nil {
			return fmt.Errorf("cannot connect with deps.dev %w", err)
		}
		e.client = depsDevAPIClient
	}

	versionQueries := make([]*depsdevpb.GetVersionRequest, 0, len(inv.Packages))
	for _, pkg := range inv.Packages {
		if err := ctx.Err(); err != nil {
			return err
		}

		ecoSystem, ok := depsdev.System[pkg.PURLType]
		if !ok {
			continue
		}
		versionQueries = append(versionQueries, versionQuery(ecoSystem, pkg.Name, pkg.Version))
	}

	advisoryKeys, err := e.makeAdvisoryKeysRequest(ctx, versionQueries)
	if err != nil {
		return err
	}

	advToPkgs := map[string][]*extractor.Package{}
	for i, keys := range advisoryKeys {
		for _, key := range keys {
			// TODO: recheck this
			advToPkgs[key] = append(advToPkgs[key], inv.Packages[i])
		}
	}

	orderedAdvisoryKeys := slices.Collect(maps.Keys(advToPkgs))
	advisoryQueries := make([]*depsdevpb.GetAdvisoryRequest, 0, len(inv.Packages))
	for _, key := range orderedAdvisoryKeys {
		if err := ctx.Err(); err != nil {
			return err
		}
		advisoryQueries = append(advisoryQueries, &depsdevpb.GetAdvisoryRequest{
			AdvisoryKey: &depsdevpb.AdvisoryKey{Id: key},
		})
	}

	advisories, err := e.makeAdvisoryRequest(ctx, advisoryQueries)
	if err != nil {
		return err
	}

	for i, advKey := range orderedAdvisoryKeys {
		if err := ctx.Err(); err != nil {
			return err
		}

		pkgs := advToPkgs[advKey]
		adv := advisories[i]
		signals := []*vex.FindingExploitabilitySignal{}

		var severity osvschema.Severity

		if adv.GetCvss3Vector() != "" {
			severity = osvschema.Severity{
				Type:  "CVSS_V3",
				Score: adv.GetCvss3Vector(),
			}
		}

		vuln := osvschema.Vulnerability{
			ID:       advKey,
			Summary:  adv.GetTitle(),
			Aliases:  adv.GetAliases(),
			Severity: []osvschema.Severity{severity},
		}

		for _, pkg := range pkgs {
			vuln.Affected = append(vuln.Affected, inventory.PackageToAffected(pkg, "UNKNOWN", &severity)...)
			signals = append(signals, vex.FindingVEXFromPackageVEX(vuln.ID, pkg.ExploitabilitySignals)...)
		}

		inv.PackageVulns = append(inv.PackageVulns, &inventory.PackageVuln{
			Vulnerability:         vuln,
			Packages:              pkgs,
			Plugins:               []string{Name},
			ExploitabilitySignals: signals,
		})
	}

	return nil
}

func (e *Enricher) makeAdvisoryKeysRequest(ctx context.Context, queries []*depsdevpb.GetVersionRequest) ([][]string, error) {
	advisories := make([][]string, len(queries))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for i := range queries {
		if queries[i] == nil {
			// This may be a private package.
			advisories[i] = []string{}
			continue
		}
		g.Go(func() error {
			resp, err := e.client.GetVersion(ctx, queries[i])
			if err != nil {
				if status.Code(err) == codes.NotFound {
					advisories[i] = []string{}
					return nil
				}
				return err
			}

			advs := make([]string, 0, len(resp.GetAdvisoryKeys()))
			for _, adv := range resp.GetAdvisoryKeys() {
				advs = append(advs, adv.GetId())
			}
			advisories[i] = advs

			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	return advisories, nil
}

func (e *Enricher) makeAdvisoryRequest(ctx context.Context, queries []*depsdevpb.GetAdvisoryRequest) ([]*depsdevpb.Advisory, error) {
	advisories := make([]*depsdevpb.Advisory, len(queries))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for i := range queries {
		if queries[i] == nil {
			// This may be a private package.
			continue
		}
		g.Go(func() error {
			resp, err := e.client.GetAdvisory(ctx, queries[i])
			if err != nil {
				if status.Code(err) == codes.NotFound {
					return nil
				}
				return err
			}
			advisories[i] = resp
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	return advisories, nil
}

func versionQuery(system depsdevpb.System, name string, version string) *depsdevpb.GetVersionRequest {
	if system == depsdevpb.System_GO {
		version = "v" + version
	}

	return &depsdevpb.GetVersionRequest{
		VersionKey: &depsdevpb.VersionKey{
			System:  system,
			Name:    name,
			Version: version,
		},
	}
}
