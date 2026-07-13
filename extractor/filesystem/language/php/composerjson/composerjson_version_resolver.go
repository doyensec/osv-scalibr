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

// version is a composer-normalized version with 4 numeric parts.
type version struct {
	parts [4]int
}

var versionRe = regexp.MustCompile(`(?i)^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?$`)

func (v version) cmp(o version) int {
	for i := range v.parts {
		if v.parts[i] != o.parts[i] {
			if v.parts[i] < o.parts[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// bump returns v with the digit at index idx incremented and all later digits zeroed.
func (v version) bump(idx int) version {
	v.parts[idx]++
	for i := idx + 1; i < len(v.parts); i++ {
		v.parts[i] = 0
	}
	return v
}

func (v version) holds(p comparator) bool {
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

// next returns the successor in the discrete 4-part version space.
func (v version) next() version {
	v.parts[3]++
	return v
}

func (v version) String() string {
	parts := []string{strconv.Itoa(v.parts[0]), strconv.Itoa(v.parts[1]), strconv.Itoa(v.parts[2])}
	if v.parts[3] != 0 {
		parts = append(parts, strconv.Itoa(v.parts[3]))
	}
	return strings.Join(parts, ".")
}

// comparator is one primitive comparison; a constraint parses to an OR-list of AND-groups of these.
type comparator struct {
	op string
	v  version
}

// ----- helper functions -----

// parseDigits parses a version string, returning the normalized version
// and how many components were given (1-4).
func parseDigits(s string) (version, int, error) {
	m := versionRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return version{}, 0, fmt.Errorf("cannot parse version %q", s)
	}
	var v version
	n := 0
	for i, g := range m[1:] {
		if g != "" {
			v.parts[i], _ = strconv.Atoi(g)
			n++
		}
	}
	return v, n, nil
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
	fromVersion, _, err := parseDigits(from)
	if err != nil {
		return nil, err
	}
	toVersion, toVersionN, err := parseDigits(to)
	if err != nil {
		return nil, err
	}
	comparators := []comparator{{">=", fromVersion}}
	// upper bound is fully specified. inclusive comparison
	if toVersionN >= 3 {
		comparators = append(comparators, comparator{"<=", toVersion})
	} else {
		// upper bound not fully specified. exclusive comparison
		idx := 0
		if toVersionN >= 2 {
			idx = 1
		}
		comparators = append(comparators, comparator{"<", toVersion.bump(idx)})
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
		v, n, err := parseDigits(token[1:])
		if err != nil {
			return nil, err
		}

		// calculate the index of the last given digit of the version string
		// used to bump the version for the upper bound
		idx := max(0, n-2) // lastPosition = max(1, position-1)
		return []comparator{
			{">=", v},
			{"<", v.bump(idx)},
		}, nil
	}

	// caret range: update to the next compatibility boundary. upper-bound is defined by:
	//   * bumping the leftmost non-zero digit
	//   * if the version is < 1.0, bumping the left-most non-zero digit
	//   * if constraint is unspecified (e.g. ^0 or ^0.0), bumping the right-most zero
	if strings.HasPrefix(token, "^") {
		v, n, err := parseDigits(token[1:])
		if err != nil {
			return nil, err
		}

		// look for the left-most non-zero to bump
		// if none found, bump the last supplied
		idx := n - 1
		for i := 0; i < n; i++ {
			if v.parts[i] != 0 {
				idx = i
				break
			}
		}

		return []comparator{
			{">=", v},
			{"<", v.bump(idx)},
		}, nil
	}

	// exclusive range: 1.2.* is sugar for >=1.2.0.0 <1.3.0.0
	if m := xRangeRe.FindStringSubmatch(token); m != nil {
		var low version
		n := 0
		for i, g := range m[1:4] {
			if g != "" {
				low.parts[i], _ = strconv.Atoi(g)
				n++
			}
		}
		high := low.bump(n - 1)
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
		v, _, err := parseDigits(m[2])
		if err != nil {
			return nil, err
		}
		return []comparator{{op, v}}, nil
	}

	// bare version = exact match, normalized to 4 parts
	v, _, err := parseDigits(token)
	if err != nil {
		return nil, err
	}
	return []comparator{{"==", v}}, nil
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
			if lower.holds(p) {
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
