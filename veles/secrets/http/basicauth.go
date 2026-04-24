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

package http

import (
	"bytes"
	"encoding/base64"
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// headerRe matches Basic Authorization headers in http dumps and json file
	//
	// ref: https://www.rfc-editor.org/rfc/rfc7617
	headerRe = regexp.MustCompile(`(?i)\bAuthorization["'\s=:]*Basic\s+([A-Za-z0-9+/]+={0,2})`)
)

// NewBasicAuthDetector extract the Basic Authorization from the provided input
func NewBasicAuthDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: 1000,
		Re:     headerRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			matches := headerRe.FindSubmatch(b)
			if len(matches) < 2 {
				return nil, false
			}

			decoded, err := base64.StdEncoding.DecodeString(string(matches[1]))
			if err != nil {
				return nil, false
			}

			parts := bytes.SplitN(decoded, []byte(":"), 2)
			if len(parts) != 2 {
				return nil, false
			}

			return BasicAuthCredentials{
				Username: string(parts[0]),
				Password: string(parts[1]),
			}, true
		},
	}
}
