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

// Package extensions extracts Firefox extensions.
package extensions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

// Name is the name for the Firefox extensions extractor.
const Name = "firefox/extensions"

var (
	windowsExtensionsPattern = regexp.MustCompile(`(?m)\/Mozilla\/Firefox\/Profiles\/[^\/]+\/extensions\.json$`)
	// Match only the canonical user profile paths on macOS. The same files are
	// also visible through /System/Volumes/Data/Users/... APFS firmlinks, and
	// matching both paths causes duplicate packages for the same Firefox profile.
	macosExtensionsPattern = regexp.MustCompile(`(?m)(?:^~|^\/?Users\/[^\/]+)\/Library\/Application Support\/Firefox\/Profiles\/[^\/]+\/extensions\.json$`)
	linuxExtensionsPattern = regexp.MustCompile(`(?m)\/(?:\.mozilla\/firefox|snap\/firefox\/common\/\.mozilla\/firefox|\.var\/app\/org\.mozilla\.firefox\/\.mozilla\/firefox)\/[^\/]+\/extensions\.json$`)
)

type extensionsJSON struct {
	Addons []addon `json:"addons"`
}

type addon struct {
	Active        bool   `json:"active"`
	AppDisabled   bool   `json:"appDisabled"`
	DefaultLocale locale `json:"defaultLocale"`
	Descriptor    string `json:"descriptor"`
	ID            string `json:"id"`
	InstallDate   int64  `json:"installDate"`
	Location      string `json:"location"`
	Path          string `json:"path"`
	SignedState   int64  `json:"signedState"`
	SourceURI     string `json:"sourceURI"`
	Type          string `json:"type"`
	UpdateDate    int64  `json:"updateDate"`
	UserDisabled  bool   `json:"userDisabled"`
	Version       string `json:"version"`
}

type locale struct {
	Creator     string `json:"creator"`
	Description string `json:"description"`
	HomepageURL string `json:"homepageURL"`
	Name        string `json:"name"`
}

func (a *addon) validate() error {
	if a.ID == "" {
		return errors.New("addon 'ID' cannot be empty")
	}
	if a.Version == "" {
		return errors.New("addon 'Version' cannot be empty")
	}
	return nil
}

// Extractor extracts Firefox extensions.
type Extractor struct{}

// New returns a Firefox extensions extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		RunningSystem: true,
	}
}

// FileRequired returns true if the file contains Firefox extensions information.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())

	// Pre-check to improve performance.
	if !strings.HasSuffix(path, "extensions.json") {
		return false
	}

	switch runtime.GOOS {
	case "windows":
		return windowsExtensionsPattern.MatchString(path)
	case "linux":
		return linuxExtensionsPattern.MatchString(path)
	case "darwin":
		return macosExtensionsPattern.MatchString(path)
	default:
		return false
	}
}

// Extract extracts Firefox extensions.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var exts extensionsJSON
	if err := json.NewDecoder(input.Reader).Decode(&exts); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract extensions: %w", err)
	}

	pkgs := make([]*extractor.Package, 0, len(exts.Addons))
	for _, ext := range exts.Addons {
		// Themes, dictionaries, and langpacks also appear in extensions.json, but
		// this extractor inventories only installed WebExtension add-ons.
		if ext.Type != "extension" {
			continue
		}
		// Firefox-managed bundled and system add-ons use locations such as
		// "app-builtin" and "app-system-defaults". Keep only profile add-ons,
		// which are the user-installed or profile-managed extension inventory.
		if ext.Location != "app-profile" {
			continue
		}
		if err := ext.validate(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("bad format: %w", err)
		}

		// Firefox usually records the add-on filesystem location in path, but
		// some extension records only populate descriptor with the same purpose.
		extPath := ext.Path
		if extPath == "" {
			extPath = ext.Descriptor
		}
		// Firefox stores staged rollout and feature experiment add-ons under the
		// profile's features directory. They are managed by Firefox, not installed
		// by the user as normal profile extensions.
		if strings.Contains(filepath.ToSlash(extPath), "/features/") {
			continue
		}

		descriptor := location.FromPath(extPath)

		pkgs = append(pkgs, &extractor.Package{
			Name:     ext.ID,
			Version:  ext.Version,
			PURLType: purl.TypeGeneric,
			Location: extractor.PackageLocation{
				Descriptor: &descriptor,
				Related:    []location.Location{location.FromPath(input.Path)},
			},
			Metadata: &Metadata{
				Name:         ext.DefaultLocale.Name,
				Description:  ext.DefaultLocale.Description,
				Creator:      ext.DefaultLocale.Creator,
				HomepageURL:  ext.DefaultLocale.HomepageURL,
				Type:         ext.Type,
				Location:     ext.Location,
				SourceURI:    ext.SourceURI,
				InstallDate:  ext.InstallDate,
				UpdateDate:   ext.UpdateDate,
				SignedState:  ext.SignedState,
				Active:       ext.Active,
				UserDisabled: ext.UserDisabled,
				AppDisabled:  ext.AppDisabled,
			},
		})
	}

	return inventory.Inventory{Packages: pkgs}, nil
}
