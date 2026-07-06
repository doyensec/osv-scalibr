// Copyright 2026 Google LLC
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

// Package composerjson extracts composer.json files.
package composerjson

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "php/composerjson"
)

type composerJSON struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

// Extractor extracts composer.json files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches composer.json files.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "composer.json"
}

// isPlatformPackage reports whether name refers to a Composer platform
// pseudo-package (the PHP runtime, an extension, a bundled library, or the
// Composer runtime itself) rather than a real Packagist package.
func isPlatformPackage(name string) bool {
	if name == "php" || name == "hhvm" || name == "composer" {
		return true
	}
	return strings.HasPrefix(name, "php-") ||
		strings.HasPrefix(name, "ext-") ||
		strings.HasPrefix(name, "lib-") ||
		strings.HasPrefix(name, "composer-")
}

// parseSystem is the semver system used to parse Composer constraints.
//
// We use NPM rather than semver.Composer for two reasons:
//
//  1. deps.dev's semver.Composer parses versions but not constraints: its
//     operators table has no Composer entry, so semver.Composer.ParseConstraint
//     panics for every input.
//  2. NPM is the closest working proxy for Composer. Their constraint syntaxes
//     are compatible for our needs (^, ~, ||, ranges, wildcards), and NPM's
//     tokenizer matches Composer's leniencies (stripping a leading "v"/"V",
//     allowing leading zeros) where the generic DefaultSystem would reject
//     those. While Composer's ~ and ^ upper bounds differ slightly from NPM's,
//     the lower bound is identical, and we only read the lower bound (the
//     minimum satisfying version), so the resolved version is the same.
//
// Switch this back to semver.Composer if upstream gains Composer constraint support.
// @todo is this the best option?
const parseSystem = semver.NPM

// resolveMinVersion returns the minimum version satisfying the Composer constraint
func resolveMinVersion(constraint string) (version string, ok bool) {
	c, err := parseSystem.ParseConstraint(constraint)
	if err != nil {
		return "", false
	}
	v, err := c.CalculateMinVersion()
	if err != nil {
		return "", false
	}
	// Ignore the build value. It's not relevant for version comparison.
	return v.Canon(false), true
}

func buildPackage(input *filesystem.ScanInput, name string, constraint string, groups []string) *extractor.Package {
	// @todo how to handle version parsing failures?
	version := constraint
	if v, ok := resolveMinVersion(constraint); ok {
		version = v
	}
	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypeComposer,
		Location: extractor.LocationFromPath(input.Path),
		Metadata: &osv.DepGroupMetadata{
			DepGroupVals: groups,
		},
	}
}

// Extract extracts packages from a composer.json file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedManifest *composerJSON

	err := json.NewDecoder(input.Reader).Decode(&parsedManifest)

	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	if parsedManifest == nil {
		return inventory.Inventory{}, errors.New("could not extract: decoded null JSON value")
	}

	packages := make(
		[]*extractor.Package,
		0,
		uint64(len(parsedManifest.Require))+uint64(len(parsedManifest.RequireDev)),
	)

	for name, constraint := range parsedManifest.Require {
		if isPlatformPackage(name) {
			continue
		}
		packages = append(packages, buildPackage(input, name, constraint, []string{}))
	}

	for name, constraint := range parsedManifest.RequireDev {
		if isPlatformPackage(name) {
			continue
		}
		packages = append(packages, buildPackage(input, name, constraint, []string{"dev"}))
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
