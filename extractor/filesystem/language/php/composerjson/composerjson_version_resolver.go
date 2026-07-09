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

package composerjson

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ----- type definitions -----

// version is a composer-normalized version: 4 numeric parts.
type version [4]int

var versionRe = regexp.MustCompile(`(?i)^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?$`)

func newVersion(digits []int) version {
	var v version
	copy(v[:], digits)
	return v
}

func (v version) cmp(o version) int {
	for i := range v {
		if v[i] != o[i] {
			if v[i] < o[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// next returns the successor in the discrete 4-part version space.
func (v version) next() version {
	v[3]++
	return v
}

func (v version) String() string {
	parts := []string{strconv.Itoa(v[0]), strconv.Itoa(v[1]), strconv.Itoa(v[2])}
	if v[3] != 0 {
		parts = append(parts, strconv.Itoa(v[3]))
	}
	return strings.Join(parts, ".")
}

// comparator is one primitive comparison; a constraint parses to an OR-list of AND-groups of these.
type comparator struct {
	op string
	v  version
}

// ----- version resolver -----

var (
	matchAllRe = regexp.MustCompile(`(?i)^v?[x*](\.[x*])*$`)
	xRangeRe   = regexp.MustCompile(`(?i)^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.[x*])+$`)
	cmpRe      = regexp.MustCompile(`^(<>|!=|>=|<=|==|=|>|<)\s*(.+)$`)
	hyphenRe   = regexp.MustCompile(`(\S+)\s+-\s+(\S+)`)
	orRe       = regexp.MustCompile(`\s*\|\|?\s*`)
	andRe      = regexp.MustCompile(`[\s,]+`)
)

func parseHyphenComparators(from, to string) ([]comparator, error) {
	fromDigits, err := parseDigits(from)
	if err != nil {
		return nil, err
	}
	toDigits, err := parseDigits(to)
	if err != nil {
		return nil, err
	}
	comparators := []comparator{{">=", newVersion(fromDigits)}}
	if len(toDigits) >= 3 {
		comparators = append(comparators, comparator{"<=", newVersion(toDigits)})
	} else {
		idx := 0
		if len(toDigits) >= 2 {
			idx = 1
		}
		comparators = append(comparators, comparator{"<", newVersion(bump(toDigits, idx))})
	}
	return comparators, nil
}

func parseConstraint(token string) ([]comparator, error) {
	// match-all: (*.*.*)
	if matchAllRe.MatchString(token) {
		return nil, nil
	}

	// tilde range: the last given digit may float
	if strings.HasPrefix(token, "~") {
		digits, err := parseDigits(token[1:])
		if err != nil {
			return nil, err
		}
		idx := len(digits) - 2 // highPosition = max(1, position-1)
		if idx < 0 {
			idx = 0
		}
		return []comparator{
			{">=", newVersion(digits)},
			{"<", newVersion(bump(digits, idx))},
		}, nil
	}

	// caret range: bump the leftmost non-zero digit
	if strings.HasPrefix(token, "^") {
		digits, err := parseDigits(token[1:])
		if err != nil {
			return nil, err
		}
		var idx int
		switch {
		case digits[0] != 0 || len(digits) < 2:
			idx = 0
		case digits[1] != 0 || len(digits) < 3:
			idx = 1
		default:
			idx = 2
		}
		return []comparator{
			{">=", newVersion(digits)},
			{"<", newVersion(bump(digits, idx))},
		}, nil
	}

	// exclusive range: 1.2.* is sugar for >=1.2.0.0 <1.3.0.0
	if m := xRangeRe.FindStringSubmatch(token); m != nil {
		var digits []int
		for _, g := range m[1:4] {
			if g != "" {
				n, _ := strconv.Atoi(g)
				digits = append(digits, n)
			}
		}
		low := newVersion(digits)
		high := newVersion(bump(digits, len(digits)-1))
		if low == (version{}) {
			return []comparator{{"<", high}}, nil
		}
		return []comparator{{">=", low}, {"<", high}}, nil
	}

	// basic comparators
	if m := cmpRe.FindStringSubmatch(token); m != nil {
		op := m[1]
		switch op {
		case "=", "==":
			op = "=="
		case "<>":
			op = "!="
		}
		digits, err := parseDigits(m[2])
		if err != nil {
			return nil, err
		}
		return []comparator{{op, newVersion(digits)}}, nil
	}

	// bare version = exact match, normalized to 4 parts
	digits, err := parseDigits(token)
	if err != nil {
		return nil, err
	}
	return []comparator{{"==", newVersion(digits)}}, nil
}

// parseConstraints processes a given version constraint string
// returns a multi-dimensional array containing the disjunctive normal form (dnf) of the constraint
func parseConstraints(constraint string) ([][]comparator, error) {
	var dnf [][]comparator

	// process OR branches
	for _, orBranch := range orRe.Split(strings.TrimSpace(constraint), -1) {
		var comparators []comparator

		// process hyphenated comparators (e.g. 1.0 - 2.0)
		for _, match := range hyphenRe.FindAllStringSubmatch(orBranch, -1) {
			p, err := parseHyphenComparators(match[1], match[2])
			if err != nil {
				return nil, err
			}
			comparators = append(comparators, p...)
		}

		rest := hyphenRe.ReplaceAllString(orBranch, " ")

		// process AND branches
		for _, andBranch := range andRe.Split(strings.TrimSpace(rest), -1) {
			if andBranch == "" {
				continue
			}

			p, err := parseConstraint(andBranch)
			if err != nil {
				return nil, err
			}
			comparators = append(comparators, p...)
		}

		dnf = append(dnf, comparators)
	}
	return dnf, nil
}

// getMinimumVersionForGroup finds the smallest version satisfying an AND-group of comparators, if any.
func getMinimumVersionForGroup(group []comparator) (version, bool) {
	var lower version
	for _, p := range group {
		switch p.op {
		case ">=", "==":
			if p.v.cmp(lower) > 0 {
				lower = p.v
			}
		case ">":
			if s := p.v.next(); s.cmp(lower) > 0 {
				lower = s
			}
		}
	}
	// A != carving out the bound itself bumps it to the next discrete version;
	// any other failing comparator is an upper bound below the lower: empty branch.
	for retry := true; retry; {
		retry = false
		for _, p := range group {
			if holds(lower, p) {
				continue
			}
			if p.op != "!=" {
				return version{}, false
			}
			lower = lower.next()
			retry = true
			break
		}
	}
	return lower, true
}

// getMinimumVersion finds the smallest satisfiable version across OR branches.
func getMinimumVersion(dnf [][]comparator) (version, bool) {
	var best version
	found := false
	for _, group := range dnf {
		if v, ok := getMinimumVersionForGroup(group); ok && (!found || v.cmp(best) < 0) {
			best, found = v, true
		}
	}
	return best, found
}

func getMinimumVersionForConstraint(constraint string) (string, error) {
	dnf, err := parseConstraints(constraint)
	if err != nil {
		return "", err
	}

	minimum, ok := getMinimumVersion(dnf)
	if !ok {
		return "", fmt.Errorf("unsatisfiable constraint: %s", constraint)
	}

	return minimum.String(), nil
}

// ----- helper functions -----

// parseDigits splits a version string into its given digits.
func parseDigits(s string) ([]int, error) {
	m := versionRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return nil, fmt.Errorf("cannot parse version %q", s)
	}
	var digits []int
	for _, g := range m[1:] {
		if g != "" {
			n, _ := strconv.Atoi(g)
			digits = append(digits, n)
		}
	}
	return digits, nil
}

// bump returns digits truncated after index idx, with that digit incremented.
func bump(digits []int, idx int) []int {
	out := append([]int(nil), digits[:idx+1]...)
	out[idx]++
	return out
}

func holds(v version, p comparator) bool {
	c := v.cmp(p.v)
	switch p.op {
	case "==":
		return c == 0
	case "!=":
		return c != 0
	case ">":
		return c > 0
	case ">=":
		return c >= 0
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	}
	return false
}
