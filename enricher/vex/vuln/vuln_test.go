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

package vuln_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/vex/vuln"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
)

func TestEnrich(t *testing.T) {
	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()

	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	// TODO: add a mock client
	e := vuln.New()

	var (
		jsPkg      = &extractor.Package{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM}
		pyPkg      = &extractor.Package{Name: "requests", Version: "2.26.0", PURLType: purl.TypePyPi}
		goPkg      = &extractor.Package{Name: "github.com/gin-gonic/gin", Version: "1.8.1", PURLType: purl.TypeGolang}
		fzfPkg     = &extractor.Package{Name: "fzf", Version: "0.63.0", PURLType: purl.TypeBrew}
		unknownPkg = &extractor.Package{Name: "unknown", PURLType: purl.TypeGolang}
	)

	tests := []struct {
		name     string
		packages []*extractor.Package
		//nolint:containedctx
		ctx              context.Context
		wantErr          error
		wantPackageVulns []*inventory.PackageVuln
	}{
		{
			name:     "ctx_cancelled",
			ctx:      cancelledContext,
			wantErr:  cmpopts.AnyError,
			packages: []*extractor.Package{jsPkg, pyPkg, goPkg},
		},
		{
			name:     "simple_test",
			packages: []*extractor.Package{goPkg},
			wantPackageVulns: []*inventory.PackageVuln{
				{
					Vulnerability: osvschema.Vulnerability{
						ID: "GHSA-2c4m-59x9-fr2g",
						Aliases: []string{
							"CVE-2023-29401",
							"GO-2023-1737",
						},
						Summary:    "Gin Web Framework does not properly sanitize filename parameter of Context.FileAttachment function",
						Severity:   []osvschema.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"}},
						References: []osvschema.Reference{{Type: "ADVISORY", URL: "https://osv.dev/vulnerability/GHSA-2c4m-59x9-fr2g"}},
					},
					Packages: []*extractor.Package{goPkg},
					Plugins:  []string{"vex/vuln"},
				},
				{
					Vulnerability: osvschema.Vulnerability{
						ID:         "GHSA-3vp4-m3rf-835h",
						Aliases:    []string{"CVE-2023-26125"},
						Summary:    "Improper input validation in github.com/gin-gonic/gin",
						Severity:   []osvschema.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"}},
						References: []osvschema.Reference{{Type: "ADVISORY", URL: "https://osv.dev/vulnerability/GHSA-3vp4-m3rf-835h"}},
					},
					Packages: []*extractor.Package{goPkg},
					Plugins:  []string{"vex/vuln"},
				},
				{
					// TODO: i don't like this why are aliases returned?
					Vulnerability: osvschema.Vulnerability{
						ID: "GO-2023-1737",
						Aliases: []string{
							"CVE-2023-29401",
							"GHSA-2c4m-59x9-fr2g",
						},
						Summary: "Improper handling of filenames in Content-Disposition HTTP header in github.com/gin-gonic/gin",
						// TODO: i don't like this, make it
						// Severity: []osvschema.Severity{},
						Severity:   []osvschema.Severity{{}},
						References: []osvschema.Reference{{Type: "ADVISORY", URL: "https://osv.dev/vulnerability/GO-2023-1737"}},
					},
					Packages: []*extractor.Package{goPkg},
					Plugins:  []string{"vex/vuln"},
				},
			},
		},
		{
			name:     "not_covered_purl_type",
			packages: []*extractor.Package{fzfPkg},
		},
		{
			name:     "unknown_package",
			packages: []*extractor.Package{unknownPkg},
		},
		{
			name: "interleaving_covered_not_coverdd",
			// TODO: implement
		},
		{
			name: "not_empty_local_inventory_vulns",
			// TODO: implement
		},
		{
			name: "one_local_one_remote__same_pkg_same_cve",
			// TODO: implement
		},
		{
			name: "one_local_one_remote__different_pkg_same_cve",
			// TODO: implement
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ctx == nil {
				tt.ctx = context.Background()
			}

			var input *enricher.ScanInput

			packages := copier.Copy(tt.packages).([]*extractor.Package)
			inv := &inventory.Inventory{Packages: packages}

			err := e.Enrich(tt.ctx, input, inv)
			if !cmp.Equal(tt.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("Enrich(%v) error: %v, want %v", tt.packages, err, tt.wantErr)
			}

			sortPkgVulns := cmpopts.SortSlices(func(a, b *inventory.PackageVuln) bool {
				return a.Vulnerability.ID < b.Vulnerability.ID
			})

			want := &inventory.Inventory{
				PackageVulns: tt.wantPackageVulns,
				Packages:     tt.packages,
			}

			// TODO: since []osvschema.Affected{} is ignored, maybe add some test in there
			if diff := cmp.Diff(want, inv, sortPkgVulns, cmpopts.IgnoreTypes([]osvschema.Affected{})); diff != "" {
				t.Errorf("Enrich(%v): unexpected diff (-want +got): %v", tt.packages, diff)
			}
		})
	}
}
