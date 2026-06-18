// Package uspassport implements US passport number detection logic.
package uspassport

import (
	"bytes"
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/sensitiveinformation/common/simpleregex"
)

const (
	maxSecretLength   = 9
	contextWindowSize = 32
)

var passportRe = regexp.MustCompile(`\b[A-Z0-9][0-9]{8}\b`)

var passportKeywords = simpleregex.KeywordsRe([]string{
	`u[\s-]*s[\s-]*passport`,
	`u[\s-]*s[\s-]*a[\s-]*passport`,
	`united[\s-]*states[\s-]*passport`,
	`american[\s-]*passport`,

	`passport[\s-]*number`,
	`passport[\s-]*no`,
	`passport[\s-]*num`,
	`passport[\s-]*#`,

	`u[\s-]*s[\s-]*passport[\s-]*number`,
	`u[\s-]*s[\s-]*passport[\s-]*no`,
	`u[\s-]*s[\s-]*passport[\s-]*#`,

	`u[\s-]*s[\s-]*travel[\s-]*document`,
	`united[\s-]*states[\s-]*travel[\s-]*document`,
	`travel[\s-]*document[\s-]*number`,

	`passport[\s-]*book[\s-]*number`,
	`passport[\s-]*card[\s-]*number`,
})

// NewDetector returns a Detector that finds US passport numbers.
func NewDetector() veles.Detector {
	return simpleregex.Detector{
		MaxLen:              maxSecretLength,
		Re:                  passportRe,
		ContextWindowBefore: contextWindowSize,
		ContextWindowAfter:  contextWindowSize,
		KeywordsRe:          passportKeywords,
		FromMatch: func(b []byte, contextMatch bool) (sensitiveinformation.SensitiveInformation, bool) {

			likelihood := sensitiveinformation.LikelihoodUnlikely
			if contextMatch {
				likelihood = sensitiveinformation.LikelihoodLikely
			}

			finding := sensitiveinformation.SensitiveInformation{
				InfoType: sensitiveinformation.InfoType{
					Name:        "PASSPORT_NUMBER",
					Sensitivity: sensitiveinformation.SensitivityLevelHigh,
				},
				Likelihood: likelihood,
				Raw:        bytes.Clone(b),
			}

			return finding, true
		},
	}
}
