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

package ussocialsecuritynumber

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validSSN         = "111-22-3333"
	validSSNNoDashes = "111223333"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		fmt.Sprintf(`ssn:%s`, validSSN),
		USSocialSecurityNumber{Value: validSSN},
	)
}

func TestDetectorAcceptance_NoDashes(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		fmt.Sprintf(`ssn:%s`, validSSNNoDashes),
		USSocialSecurityNumber{Value: validSSNNoDashes},
	)
}

func TestDetector(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "valid ssn",
			input: fmt.Sprintf("ssn:%s", validSSN),
			want:  []veles.Secret{USSocialSecurityNumber{Value: validSSN}},
		},
		{
			name:  "valid ssn no dashes",
			input: fmt.Sprintf("ssn:%s", validSSNNoDashes),
			want:  []veles.Secret{USSocialSecurityNumber{Value: validSSNNoDashes}},
		},
	}

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

func TestDetector_NoMatch(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "ssn with dashes with missing context",
			input: validSSN,
		},
		{
			name:  "ssn without dashes with missing context",
			input: validSSNNoDashes,
		},
		{
			name:  "ssn with single dash",
			input: "ssn:111-223333",
		},
		{
			name:  "ssn starting with 9",
			input: "ssn:911-22-3333",
		},
		{
			name:  "ssn starting with 9 no dashes",
			input: "ssn:911223333",
		},
		{
			name:  "ssn with zeroes in first group",
			input: "ssn:000-22-3333",
		},
		{
			name:  "ssn with zeroes in first group no dashes",
			input: "ssn:000223333",
		},
		{
			name:  "ssn with sixes in first group",
			input: "ssn:666-22-3333",
		},
		{
			name:  "ssn with sixes in first group no dashes",
			input: "ssn:666223333",
		},
		{
			name:  "ssn with zeroes in second group",
			input: "ssn:111-00-3333",
		},
		{
			name:  "ssn with zeroes in second group no dashes",
			input: "ssn:111003333",
		},
		{
			name:  "ssn with zeroes in third group",
			input: "ssn:111-22-0000",
		},
		{
			name:  "ssn with zeroes in third group no dashes",
			input: "ssn:111220000",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if len(got) != 0 {
				t.Errorf("Detect() got %v secrets, want 0", len(got))
			}
		})
	}
}
