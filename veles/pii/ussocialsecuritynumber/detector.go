// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ussocialsecuritynumber

import (
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	maxSSNLen     = 11
	maxKeywordLen = 20
)

var (
	keywordRe = regexp.MustCompile(`(?i)\b[A-Za-z_-]*(?:social|security|number|ssn)[A-Za-z_-]*\b`)
	ssnRe     = regexp.MustCompile(`\b([0-9]{3}-[0-9]{2}-[0-9]{4}|[0-9]{9})\b`)
)

// source: https://www.ssa.gov/kc/SSAFactSheet--IssuingSSNs.pdf
func isValidSSN(pos123, pos45, pos6789 string) bool {
	if pos123[0] == '9' { // first character will never be a `9`
		return false
	} else if pos123 == "666" || pos123 == "000" { // invalid values for positions 1-3
		return false
	} else if pos45 == "00" { // invalid values for position 4-5
		return false
	} else if pos6789 == "0000" { // // invalid values for position 6-9
		return false
	}
	return true
}

// A match is considered successful only if the context keyword is also found near to the value
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxSSNLen,
		MaxDistance:   veles.KiB, // The context keyword should be within 1Kb of data from the detected value
		FindA:         pair.FindAllMatches(ssnRe),
		FindB:         pair.FindAllMatches(keywordRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			match := string(p.A.Value)
			groups := strings.Split(match, "-")
			if len(groups) == 1 {
				pos123 := match[:3]
				pos45 := match[3:5]
				pos6789 := match[5:9]
				return USSocialSecurityNumber{Value: match}, isValidSSN(pos123, pos45, pos6789)
			} else if len(groups) == 3 {
				pos123 := groups[0]
				pos45 := groups[1]
				pos6789 := groups[2]
				return USSocialSecurityNumber{Value: match}, isValidSSN(pos123, pos45, pos6789)
			}

			return USSocialSecurityNumber{Value: match}, false
		},
	}
}
