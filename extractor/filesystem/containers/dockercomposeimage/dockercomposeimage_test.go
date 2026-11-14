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

package dockercomposeimage_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/dockercomposeimage"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	extr, err := dockercomposeimage.New(&cpb.PluginConfig{MaxFileSizeBytes: 1024})
	if err != nil {
		t.Fatalf("dockercomposeimage.New failed: %v", err)
	}

	tests := []struct {
		name string
		path string
		info fs.FileInfo
		want bool
	}{
		{
			name: "compose.yaml",
			path: "testdata/compose.yaml",
			info: fakefs.FakeFileInfo{FileName: "compose.yaml", FileMode: fs.ModePerm, FileSize: 100},
			want: true,
		},
		{
			name: "docker_compose_file_with_yml_extension",
			path: "testdata/docker-compose-1.yml",
			info: fakefs.FakeFileInfo{FileName: "docker-compose-1.yml", FileMode: fs.ModePerm, FileSize: 100},
			want: true,
		},
		{
			name: "docker_compose_file_with_yaml_extension",
			path: "testdata/docker-compose-extending.yaml",
			info: fakefs.FakeFileInfo{FileName: "docker-compose-extending.yaml", FileMode: fs.ModePerm, FileSize: 100},
			want: true,
		},
		{
			name: "virtual_path_not_on_host",
			path: "nonexistent/virtual/compose.yaml",
			info: fakefs.FakeFileInfo{FileName: "compose.yaml", FileMode: fs.ModePerm, FileSize: 100},
			want: true,
		},
		{
			name: "directory_ignored",
			path: "compose.yaml",
			info: fakefs.FakeFileInfo{FileName: "compose.yaml", FileMode: fs.ModeDir | fs.ModePerm, FileSize: 100},
			want: false,
		},
		{
			name: "oversized_file_ignored",
			path: "compose.yaml",
			info: fakefs.FakeFileInfo{FileName: "compose.yaml", FileMode: fs.ModePerm, FileSize: 2048},
			want: false,
		},
		{
			name: "not_a_docker_compose_file",
			path: "testdata/docker.conf",
			info: fakefs.FakeFileInfo{FileName: "docker.conf", FileMode: fs.ModePerm, FileSize: 100},
			want: false,
		},
		{
			name: "non_compose_yaml_file",
			path: "testdata/deployment.yaml",
			info: fakefs.FakeFileInfo{FileName: "deployment.yaml", FileMode: fs.ModePerm, FileSize: 100},
			want: false,
		},
		{
			name: "non_compose_yml_file",
			path: "testdata/config.yml",
			info: fakefs.FakeFileInfo{FileName: "config.yml", FileMode: fs.ModePerm, FileSize: 100},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isRequired := extr.FileRequired(simplefileapi.New(tc.path, tc.info))
			if isRequired != tc.want {
				t.Fatalf("FileRequired(%s): got %v, want %v", tc.path, isRequired, tc.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		maxFileSizeBytes int64
		wantPackages     []*extractor.Package
	}{
		{
			name: "single_stage_docker_compose_file",
			path: "testdata/docker-compose-extending.yaml",
			wantPackages: []*extractor.Package{
				{
					Name:     "ghcr.io/acme/api",
					Version:  "1.2.0",
					Location: extractor.LocationFromPath("testdata/docker-compose-extending.yaml"),
					PURLType: "docker",
				},
			},
		},
		{
			name: "multi_stage_docker_compose_file",
			path: "testdata/docker-compose-1.yml",
			wantPackages: []*extractor.Package{
				// "image3" and "image6" are not expected because
				// the version values are set(partially) via environment variables,
				// the responsible environment variable values are not known at extraction time,
				// and the version values are imperfectly extracted.
				{
					Name:     "image1",
					Version:  "1.1.1",
					Location: extractor.LocationFromPath("testdata/docker-compose-1.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "image2",
					Version:  "2.2.2",
					Location: extractor.LocationFromPath("testdata/docker-compose-1.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "image4",
					Version:  "4.4.4",
					Location: extractor.LocationFromPath("testdata/docker-compose-1.yml"),
					PURLType: purl.TypeDocker,
				},
				{
					Name:     "image5",
					Version:  "5.5.5",
					Location: extractor.LocationFromPath("testdata/docker-compose-1.yml"),
					PURLType: purl.TypeDocker,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := dockercomposeimage.New(&cpb.PluginConfig{MaxFileSizeBytes: tc.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("dockercomposeimage.New failed: %v", err)
			}

			input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
				Path: tc.path,
			})
			defer extracttest.CloseTestScanInput(t, input)

			got, err := extr.Extract(t.Context(), &input)
			if err != nil {
				t.Fatalf("%s.Extract(%q) failed: %v", extr.Name(), tc.path, err)
			}

			wantInv := inventory.Inventory{Packages: tc.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tc.path, diff)
			}
		})
	}
}

func TestExtract_failures(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "invalid_docker_compose_file",
			path: "testdata/docker-compose-yaml-parse-error.yaml",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := dockercomposeimage.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("dockercomposeimage.New failed: %v", err)
			}

			input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
				Path: tc.path,
			})
			defer extracttest.CloseTestScanInput(t, input)

			got, _ := extr.Extract(t.Context(), &input)
			if diff := cmp.Diff(inventory.Inventory{}, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tc.path, diff)
			}
		})
	}
}

func TestExtract_SymlinkEscapeIgnored(t *testing.T) {
	scanRoot, outsidePath := fakefs.CreateSymlinkEscapeFixture(t, ".env")
	if err := os.WriteFile(outsidePath, []byte("TAG=leaked-from-outside\n"), 0600); err != nil {
		t.Fatalf("os.WriteFile(%q): %v", outsidePath, err)
	}
	composeContent := []byte("name: test\nservices:\n  app:\n    image: myapp:${TAG}\n")
	if err := os.WriteFile(filepath.Join(scanRoot, "compose.yaml"), composeContent, 0600); err != nil {
		t.Fatalf("os.WriteFile(compose.yaml): %v", err)
	}

	root, err := os.OpenRoot(scanRoot)
	if err != nil {
		t.Fatalf("os.OpenRoot(%q): %v", scanRoot, err)
	}
	defer root.Close()

	extr, err := dockercomposeimage.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("dockercomposeimage.New failed: %v", err)
	}

	input := &filesystem.ScanInput{
		FS:     root.FS().(scalibrfs.FS),
		Path:   "compose.yaml",
		Root:   scanRoot,
		Info:   fakefs.FakeFileInfo{FileName: "compose.yaml", FileMode: fs.ModePerm, FileSize: int64(len(composeContent))},
		Reader: bytes.NewReader(composeContent),
	}
	got, err := extr.Extract(t.Context(), input)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if len(got.Packages) != 0 {
		t.Errorf("Extract returned packages %v from escaped .env symlink, want empty", got.Packages)
	}
}

func TestExtract_ExternalRefs(t *testing.T) {
	for _, directive := range []string{"include", "include_only", "extends"} {
		for _, reference := range []string{"relative", "absolute", "outside_scan_root"} {
			for _, mode := range []string{"default", "disabled", "enabled"} {
				t.Run(directive+"_"+reference+"_"+mode, func(t *testing.T) {
					root := t.TempDir()
					scanRoot := filepath.Join(root, "scan")
					manifestDir := filepath.Join(scanRoot, "deploy")
					if err := os.MkdirAll(manifestDir, 0700); err != nil {
						t.Fatal(err)
					}
					basePath := filepath.Join(manifestDir, "base.yaml")
					ref := "base.yaml"
					switch reference {
					case "absolute":
						ref = filepath.ToSlash(basePath)
					case "outside_scan_root":
						basePath = filepath.Join(root, "base.yaml")
						ref = "../../base.yaml"
					}
					base := "services:\n  base:\n    image: external:2\n"
					if err := os.WriteFile(basePath, []byte(base), 0600); err != nil {
						t.Fatal(err)
					}
					manifest := fmt.Sprintf("name: test\ninclude:\n  - %q\nservices:\n  app:\n    image: local:1\n", ref)
					wantPackages := []*extractor.Package{{
						Name: "local", Version: "1", PURLType: purl.TypeDocker,
						Location: extractor.LocationFromPath("deploy/compose.yaml"),
					}}
					if directive == "extends" {
						manifest = fmt.Sprintf("name: test\nservices:\n  app:\n    extends:\n      file: %q\n      service: base\n", ref)
						// Without resolving extends, this service has no image.
						wantPackages = nil
					}
					if directive == "include_only" {
						manifest = fmt.Sprintf("name: test\ninclude:\n  - %q\n", ref)
						wantPackages = nil
					}
					if mode == "enabled" {
						wantPackages = append(wantPackages, &extractor.Package{
							Name: "external", Version: "2", PURLType: purl.TypeDocker,
							Location: extractor.LocationFromPath("deploy/compose.yaml"),
						})
					}
					cfg := &cpb.PluginConfig{}
					if mode != "default" {
						cfg.PluginSpecific = []*cpb.PluginSpecificConfig{{
							Config: &cpb.PluginSpecificConfig_DockerComposeImage{
								DockerComposeImage: &cpb.DockerComposeImageConfig{ResolveExternalRefs: mode == "enabled"},
							},
						}}
					}
					extr, err := dockercomposeimage.New(cfg)
					if err != nil {
						t.Fatalf("New failed: %v", err)
					}
					input := &filesystem.ScanInput{
						Root: scanRoot, Path: "deploy/compose.yaml",
						Info:   fakefs.FakeFileInfo{FileName: "compose.yaml", FileSize: int64(len(manifest))},
						Reader: bytes.NewBufferString(manifest),
					}
					got, err := extr.Extract(t.Context(), input)
					if err != nil {
						t.Fatalf("Extract failed: %v", err)
					}
					want := inventory.Inventory{Packages: wantPackages}
					if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
						t.Errorf("Extract diff (-want +got):\n%s", diff)
					}
				})
			}
		}
	}
}

func TestExtract_ExternalRefsEnvironment(t *testing.T) {
	t.Setenv("SCALIBR_COMPOSE_HOST_TAG", "host-secret")
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("resolve_external_refs_%t", enabled), func(t *testing.T) {
			cfg := &cpb.PluginConfig{PluginSpecific: []*cpb.PluginSpecificConfig{{
				Config: &cpb.PluginSpecificConfig_DockerComposeImage{
					DockerComposeImage: &cpb.DockerComposeImageConfig{ResolveExternalRefs: enabled},
				},
			}}}
			extr, err := dockercomposeimage.New(cfg)
			if err != nil {
				t.Fatalf("New failed: %v", err)
			}
			manifest := `name: test
services:
  app:
    image: local:${TAG}
    env_file: nonexistent.env
    label_file: nonexistent.labels
  unresolved:
    image: secret:${SCALIBR_COMPOSE_HOST_TAG}
`
			input := &filesystem.ScanInput{
				Root: t.TempDir(), Path: "compose.yaml",
				FS:     fstest.MapFS{".env": {Data: []byte("TAG=from-scan\n")}},
				Info:   fakefs.FakeFileInfo{FileName: "compose.yaml", FileSize: int64(len(manifest))},
				Reader: bytes.NewBufferString(manifest),
			}
			got, err := extr.Extract(t.Context(), input)
			if err != nil {
				t.Fatalf("Extract failed: %v", err)
			}
			want := inventory.Inventory{Packages: []*extractor.Package{{
				Name: "local", Version: "from-scan", PURLType: purl.TypeDocker,
				Location: extractor.LocationFromPath("compose.yaml"),
			}}}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Extract diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtract_ExternalRefsVirtualFS(t *testing.T) {
	extr, err := dockercomposeimage.New(&cpb.PluginConfig{PluginSpecific: []*cpb.PluginSpecificConfig{{
		Config: &cpb.PluginSpecificConfig_DockerComposeImage{
			DockerComposeImage: &cpb.DockerComposeImageConfig{ResolveExternalRefs: true},
		},
	}}})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	manifest := "name: test\nservices:\n  app:\n    image: local:1\n"
	input := &filesystem.ScanInput{
		Path:   "compose.yaml",
		Info:   fakefs.FakeFileInfo{FileName: "compose.yaml", FileSize: int64(len(manifest))},
		Reader: bytes.NewBufferString(manifest),
	}
	got, err := extr.Extract(t.Context(), input)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if diff := cmp.Diff(inventory.Inventory{}, got); diff != "" {
		t.Errorf("Extract diff (-want +got):\n%s", diff)
	}
}
