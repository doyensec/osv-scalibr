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

package basicauth_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/http/basicauth"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	testTargetURL = "https://api.production.internal/v1"
	testUsername  = "admin"
	testPassword  = "password"

	testBase64        = "YWRtaW46cGFzc3dvcmQ="
	testComplexBase64 = "dXNlcjEyMzpzdXBlcjpzZWNyZXQ6cGFzcw=="
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		basicauth.NewDetector(),
		"Authorization: Basic "+testBase64,
		basicauth.Credentials{
			Username: testUsername,
			Password: testPassword,
		},
	)
}

func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{basicauth.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple_matching_string_in_proximity",
		input: "Target: " + testTargetURL + " Authorization: Basic " + testBase64,
		want: []veles.Secret{
			basicauth.Credentials{
				Metadata: &basicauth.Metadata{
					TargetURL: testTargetURL,
				},
				Username: testUsername,
				Password: testPassword,
			},
		},
	}, {
		name:  "match_with_internal_colons_in_password",
		input: "Connecting to https://github.com/api/v3 using Authorization: Basic " + testComplexBase64,
		want: []veles.Secret{
			basicauth.Credentials{
				Metadata: &basicauth.Metadata{
					TargetURL: "https://github.com/api/v3",
				},
				Username: "user123",
				Password: "super:secret:pass",
			},
		},
	}, {
		name: "match_with_curl_command_format",
		input: `curl -v -X POST ` + testTargetURL + ` \
  -H "Authorization: Basic ` + testBase64 + `" \
  -F from='User'`,
		want: []veles.Secret{
			basicauth.Credentials{
				Metadata: &basicauth.Metadata{
					TargetURL: testTargetURL,
				},
				Username: testUsername,
				Password: testPassword,
			},
		},
	}, {
		name:  "match_within_flat_json_log",
		input: `{"url":"` + testTargetURL + `","headers":{"Authorization":"Basic ` + testBase64 + `"}}`,
		want: []veles.Secret{
			basicauth.Credentials{
				Metadata: &basicauth.Metadata{
					TargetURL: testTargetURL,
				},
				Username: testUsername,
				Password: testPassword,
			},
		},
	}, {
		name:  "multiple_matches_in_single_payload_picks_closest_url",
		input: testTargetURL + "\nAuthorization: Basic " + testBase64 + "\n\nhttp://other.local\nAuthorization: Basic " + testBase64,
		want: []veles.Secret{
			basicauth.Credentials{
				Metadata: &basicauth.Metadata{
					TargetURL: testTargetURL,
				},
				Username: testUsername,
				Password: testPassword,
			},
			basicauth.Credentials{
				Metadata: &basicauth.Metadata{
					TargetURL: "http://other.local",
				},
				Username: testUsername,
				Password: testPassword,
			},
		},
	}, {
		name:  "url_exceeds_maxdistance_still_extracts_secret",
		input: testTargetURL + strings.Repeat(" ", 2500) + "Authorization: Basic " + testBase64,
		want: []veles.Secret{
			basicauth.Credentials{
				Metadata: nil,
				Username: testUsername,
				Password: testPassword,
			},
		},
	}, {
		name:  "valid_header_but_no_url_in_proximity",
		input: "Just a random log entry without a URL\nAuthorization: Basic " + testBase64,
		want: []veles.Secret{
			basicauth.Credentials{
				Metadata: nil,
				Username: testUsername,
				Password: testPassword,
			},
		},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{basicauth.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "empty_input",
		input: "",
	}, {
		name:  "valid_base64_but_missing_colon_delimiter_in_decoded_string",
		input: "Target: " + testTargetURL + "\nAuthorization: Basic bm9jb2xvbmhlcmU=",
	}, {
		name:  "invalid_characters_in_base64_payload",
		input: "Target: " + testTargetURL + "\nAuthorization: Basic !@#invalid_chars$$%",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
