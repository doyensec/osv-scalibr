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

package extensions_test

import (
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/firefox/extensions"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		inputPath string
		want      bool
		GOOS      string
	}{
		{inputPath: "", want: false},
		{GOOS: "windows", inputPath: `%APPDATA%\Mozilla\Firefox\Profiles\abcd1234.default-release\extensions.json`, want: true},
		{GOOS: "windows", inputPath: `%APPDATA%\Mozilla\Firefox\Profiles\abcd1234.default-release\addonStartup.json.lz4`, want: false},
		{GOOS: "windows", inputPath: `%APPDATA%\Mozilla\Firefox\Profiles\abcd1234.default-release\extensions\extensions.json`, want: false},

		{GOOS: "darwin", inputPath: `~/Library/Application Support/Firefox/Profiles/abcd1234.default-release/extensions.json`, want: true},
		{GOOS: "darwin", inputPath: `/Users/username/Library/Application Support/Firefox/Profiles/abcd1234.default-release/extensions.json`, want: true},
		{GOOS: "darwin", inputPath: `Users/username/Library/Application Support/Firefox/Profiles/abcd1234.default-release/extensions.json`, want: true},
		{GOOS: "darwin", inputPath: `/System/Volumes/Data/Users/username/Library/Application Support/Firefox/Profiles/abcd1234.default-release/extensions.json`, want: false},
		{GOOS: "darwin", inputPath: `~/Library/Application Support/Firefox/Profiles/abcd1234.default-release/extensions/extensions.json`, want: false},

		{GOOS: "linux", inputPath: `~/.mozilla/firefox/abcd1234.default-release/extensions.json`, want: true},
		{GOOS: "linux", inputPath: `/home/username/.mozilla/firefox/abcd1234.default-release/extensions.json`, want: true},
		{GOOS: "linux", inputPath: `/home/username/snap/firefox/common/.mozilla/firefox/abcd1234.default-release/extensions.json`, want: true},
		{GOOS: "linux", inputPath: `/home/username/.var/app/org.mozilla.firefox/.mozilla/firefox/abcd1234.default-release/extensions.json`, want: true},
		{GOOS: "linux", inputPath: `/home/username/.mozilla/firefox/abcd1234.default-release/extensions/extensions.json`, want: false},
		{GOOS: "linux", inputPath: `/home/username/.var/app/org.mozilla.firefox/cache/firefox/abcd1234.default-release/extensions.json`, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			if tt.GOOS != "" && tt.GOOS != runtime.GOOS {
				t.Skipf("Skipping test for unsupported OS %q", runtime.GOOS)
			}
			e, err := extensions.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("extensions.New failed: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.json",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract extensions"},
		},
		{
			Name: "invalid extension",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-extension.json",
			},
			WantErr: extracttest.ContainsErrStr{Str: "bad format"},
		},
		{
			Name: "theme is ignored",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/theme-only.json",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "managed add-ons are ignored without filtering mozilla ids",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/managed-addons.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "profile-extension@mozilla.org",
					Version:  "1.2.3",
					PURLType: purl.TypeGeneric,
					Location: extractor.PackageLocation{
						Descriptor: &location.Location{File: &location.File{
							Path: "/home/username/.mozilla/firefox/abcd1234.default-release/extensions/profile-extension@mozilla.org.xpi",
						}},
						Related: []location.Location{location.FromPath("testdata/managed-addons.json")},
					},
					Metadata: &extensions.Metadata{
						Name:         "Mozilla Profile Extension",
						Description:  "A user profile extension with a Mozilla-looking ID.",
						Creator:      "Example Publisher",
						HomepageURL:  "https://example.com/profile-extension",
						Type:         "extension",
						Location:     "app-profile",
						SourceURI:    "https://example.com/profile-extension.xpi",
						InstallDate:  1740566188000,
						UpdateDate:   1740566188000,
						SignedState:  2,
						Active:       true,
						UserDisabled: false,
						AppDisabled:  false,
					},
				},
			},
		},
		{
			Name: "extensions only",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/extensions.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "uBlock0@raymondhill.net",
					Version:  "1.63.2",
					PURLType: purl.TypeGeneric,
					Location: extractor.PackageLocation{
						Descriptor: &location.Location{File: &location.File{
							Path: "/home/username/.mozilla/firefox/abcd1234.default-release/extensions/uBlock0@raymondhill.net.xpi",
						}},
						Related: []location.Location{location.FromPath("testdata/extensions.json")},
					},
					Metadata: &extensions.Metadata{
						Name:         "uBlock Origin",
						Description:  "Finally, an efficient wide-spectrum content blocker. Easy on CPU and memory.",
						Creator:      "Raymond Hill",
						HomepageURL:  "https://github.com/gorhill/uBlock#ublock-origin",
						Type:         "extension",
						Location:     "app-profile",
						SourceURI:    "https://addons.mozilla.org/firefox/downloads/file/4435274/ublock_origin-1.63.2.xpi",
						InstallDate:  1740566188000,
						UpdateDate:   1740566188000,
						SignedState:  2,
						Active:       true,
						UserDisabled: false,
						AppDisabled:  false,
					},
				},
				{
					Name:     "extension-no-path@example.com",
					Version:  "2.1.0",
					PURLType: purl.TypeGeneric,
					Location: extractor.PackageLocation{
						Descriptor: &location.Location{File: &location.File{
							Path: "/home/username/.mozilla/firefox/abcd1234.default-release/extensions/extension-no-path@example.com.xpi",
						}},
						Related: []location.Location{location.FromPath("testdata/extensions.json")},
					},
					Metadata: &extensions.Metadata{
						Name:         "No Path Extension",
						Description:  "Uses descriptor when path is unavailable.",
						Creator:      "Example Publisher",
						HomepageURL:  "https://example.com/no-path",
						Type:         "extension",
						Location:     "app-profile",
						SourceURI:    "https://example.com/extension-no-path.xpi",
						InstallDate:  1740567000000,
						UpdateDate:   1740568000000,
						SignedState:  2,
						Active:       false,
						UserDisabled: true,
						AppDisabled:  false,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := extensions.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("extensions.New failed: %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			if diff := cmp.Diff(tt.WantPackages, got.Packages, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
