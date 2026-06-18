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

package uspassport

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/velestest"
)

const testPassport = "A12345678"

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		testPassport,
		passportFinding([]byte(testPassport)),
	)
}

func TestDetect_truePositives(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		in   []byte
		want []veles.Secret
	}{
		{
			name: "match_only",
			in:   []byte("A12345678"),
			want: []veles.Secret{
				passportFinding([]byte("A12345678")),
			},
		},
		{
			name: "numeric_first_character",
			in:   []byte("123456789"),
			want: []veles.Secret{
				passportFinding([]byte("123456789")),
			},
		},
		{
			name: "keyword_before",
			in:   []byte("us passport: A12345678"),
			want: []veles.Secret{
				passportFindingWithLikelihood([]byte("A12345678"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "keyword_after",
			in:   []byte("A12345678 passport number"),
			want: []veles.Secret{
				passportFindingWithLikelihood([]byte("A12345678"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "travel_document_keyword",
			in:   []byte("travel document number: A12345678"),
			want: []veles.Secret{
				passportFindingWithLikelihood([]byte("A12345678"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "multiple_matches",
			in:   []byte("A12345678 123456789 Z98765432"),
			want: []veles.Secret{
				passportFinding([]byte("A12345678")),
				passportFinding([]byte("123456789")),
				passportFinding([]byte("Z98765432")),
			},
		},
		{
			name: "multiple_matches_long_gap",
			in:   []byte("A12345678" + strings.Repeat(" ", 50000) + "Z98765432"),
			want: []veles.Secret{
				passportFinding([]byte("A12345678")),
				passportFinding([]byte("Z98765432")),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, derr := e.Detect(t.Context(), bytes.NewBuffer(tc.in))
			if derr != nil {
				t.Fatal(derr)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetect_keywordMatches(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		in   []byte
	}{
		{
			name: "us_passport",
			in:   []byte("us passport: A12345678"),
		},
		{
			name: "usa_passport",
			in:   []byte("usa passport: A12345678"),
		},
		{
			name: "united_states_passport",
			in:   []byte("united states passport: A12345678"),
		},
		{
			name: "american_passport",
			in:   []byte("american passport: A12345678"),
		},
		{
			name: "passport_number",
			in:   []byte("passport number: A12345678"),
		},
		{
			name: "passport_no",
			in:   []byte("passport no: A12345678"),
		},
		{
			name: "passport_num",
			in:   []byte("passport num: A12345678"),
		},
		{
			name: "passport_hash",
			in:   []byte("passport #: A12345678"),
		},
		{
			name: "us_passport_number",
			in:   []byte("us passport number: A12345678"),
		},
		{
			name: "us_passport_no",
			in:   []byte("us passport no: A12345678"),
		},
		{
			name: "us_passport_hash",
			in:   []byte("us passport #: A12345678"),
		},
		{
			name: "us_travel_document",
			in:   []byte("us travel document: A12345678"),
		},
		{
			name: "united_states_travel_document",
			in:   []byte("united states travel document: A12345678"),
		},
		{
			name: "travel_document_number",
			in:   []byte("travel document number: A12345678"),
		},
		{
			name: "passport_book_number",
			in:   []byte("passport book number: A12345678"),
		},
		{
			name: "passport_card_number",
			in:   []byte("passport card number: A12345678"),
		},
		{
			name: "case_insensitive",
			in:   []byte("US PASSPORT: A12345678"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, derr := e.Detect(t.Context(), bytes.NewBuffer(tc.in))
			if derr != nil {
				t.Fatal(derr)
			}
			want := []veles.Secret{
				passportFindingWithLikelihood([]byte("A12345678"), sensitiveinformation.LikelihoodLikely),
			}
			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetect_trueNegatives(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		in   []byte
	}{
		{
			name: "no_match",
			in:   []byte("not a passport number"),
		},
		{
			name: "too_short",
			in:   []byte("A1234567"),
		},
		{
			name: "too_long",
			in:   []byte("A123456789"),
		},
		{
			name: "lowercase_first_character",
			in:   []byte("a12345678"),
		},
		{
			name: "second_character_alpha",
			in:   []byte("AB2345678"),
		},
		{
			name: "contains_dash",
			in:   []byte("A1234-678"),
		},
		{
			name: "contains_space",
			in:   []byte("A1234 678"),
		},
		{
			name: "within_longer_string",
			in:   []byte("asdfA12345678asdf"),
		},
		{
			name: "within_underscores",
			in:   []byte("asdf_A12345678_asdf"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, derr := e.Detect(t.Context(), bytes.NewBuffer(tc.in))
			if derr != nil {
				t.Fatal(derr)
			}
			if diff := cmp.Diff([]veles.Secret(nil), got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetectorMaxSecretLen(t *testing.T) {
	if got, want := NewDetector().MaxSecretLen(), uint32(len("A12345678")+(2*contextWindowSize)); got != want {
		t.Errorf("MaxSecretLen() = %d, want %d", got, want)
	}
}

func passportFinding(raw []byte) sensitiveinformation.SensitiveInformation {
	return passportFindingWithLikelihood(raw, sensitiveinformation.LikelihoodUnlikely)
}

func passportFindingWithLikelihood(raw []byte, likelihood sensitiveinformation.Likelihood) sensitiveinformation.SensitiveInformation {
	return sensitiveinformation.SensitiveInformation{
		InfoType: sensitiveinformation.InfoType{
			Name:        "PASSPORT_NUMBER",
			Sensitivity: sensitiveinformation.SensitivityLevelHigh,
		},
		Likelihood: likelihood,
		Raw:        raw,
	}
}
