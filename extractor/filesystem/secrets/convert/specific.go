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

package convert

import (
	"github.com/google/osv-scalibr/extractor/filesystem"
)

// detectorSpecificWrapper is a wrapper around the veles.Detector interface that
// implements the additional functions of the filesystem Extractor interface.
type detectorSpecificWrapper struct {
	filesystem.Extractor
	fileRequired func(api filesystem.FileAPI) bool
}

func (d *detectorSpecificWrapper) IsRequirer() bool {
	return true
}

// FileRequired is a dummy function to satisfy the interface requirements.
// It always returns false since wrapped secret scanner plugins all run through the
// central veles FilesystemExtractor plugin.
func (d *detectorSpecificWrapper) FileRequired(api filesystem.FileAPI) bool {
	return d.fileRequired(api)
}

func FromVelesDetectorWithRequired(ex filesystem.Extractor, fileRequired func(api filesystem.FileAPI) bool) func() filesystem.Extractor {
	return func() filesystem.Extractor {
		return &detectorSpecificWrapper{
			Extractor:    ex,
			fileRequired: fileRequired,
		}
	}
}
