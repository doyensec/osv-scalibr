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

package basicauth

import (
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

var (
	// Updated to handle standard headers and quoted log formats (e.g., "Authorization"="Basic ...")
	headerRe      = regexp.MustCompile(`(?i)\bAuthorization["'\s=:]*Basic\s+([A-Za-z0-9+/]+={0,2})`)
	requestLineRe = regexp.MustCompile(`(?i)(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+([^\s]+)\s+HTTP/[0-9.]+`)
	hostRe        = regexp.MustCompile(`(?i)Host:\s+([a-zA-Z0-9.-]+)`)
	urlRe         = regexp.MustCompile(`(?i)https?://[a-zA-Z0-9.-]+(?:/[^\s"'<>]*)?`)
)

type Detector struct {
	SearchWindow int
}

var _ veles.Detector = (*Detector)(nil)

func NewDetector() veles.Detector {
	return &Detector{
		SearchWindow: 2000,
	}
}

func (d *Detector) MaxSecretLen() uint32 {
	return uint32(d.SearchWindow)
}

func (d *Detector) Detect(data []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var indices []int

	matches := headerRe.FindAllSubmatchIndex(data, -1)
	for _, m := range matches {
		creds, ok := extractPayload(data[m[2]:m[3]])
		if !ok {
			continue
		}

		creds.Metadata = extractMetadata(data, m[0], m[1], d.SearchWindow)

		secrets = append(secrets, *creds)
		indices = append(indices, m[0])
	}

	return secrets, indices
}

func extractPayload(b64Data []byte) (*Credentials, bool) {
	decoded, err := base64.StdEncoding.DecodeString(string(b64Data))
	if err != nil {
		return nil, false
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, false
	}

	return &Credentials{
		Username: parts[0],
		Password: parts[1],
	}, true
}

func extractMetadata(data []byte, matchStart, matchEnd, windowSize int) *Metadata {
	start := matchStart - windowSize
	if start < 0 {
		start = 0
	}
	end := matchEnd + windowSize
	if end > len(data) {
		end = len(data)
	}

	window := data[start:end]
	anchor := matchStart - start // The position of the secret relative to the window

	// findClosest scans the window and returns the submatches of the match closest to the anchor
	findClosest := func(re *regexp.Regexp) [][]byte {
		matches := re.FindAllSubmatchIndex(window, -1)
		var best []int
		minDist := -1

		for _, m := range matches {
			dist := 0
			if m[1] < anchor {
				dist = anchor - m[1] // context is before the secret
			} else if m[0] > anchor {
				dist = m[0] - anchor // context is after the secret
			}

			if minDist == -1 || dist < minDist {
				minDist = dist
				best = m
			}
		}

		if best == nil {
			return nil
		}

		res := make([][]byte, len(best)/2)
		for i := 0; i < len(best)/2; i++ {
			if best[i*2] != -1 {
				res[i] = window[best[i*2]:best[i*2+1]]
			}
		}
		return res
	}

	res := Metadata{}
	if m := findClosest(requestLineRe); m != nil {
		res.Method = strings.ToUpper(string(m[1]))
		res.Path = string(m[2])
	}

	if m := findClosest(hostRe); m != nil {
		res.TargetURL = string(m[1])
	} else if m := findClosest(urlRe); m != nil {
		res.TargetURL = string(m[0])
	}

	if res.TargetURL == "" {
		return nil
	}

	return &res
}
