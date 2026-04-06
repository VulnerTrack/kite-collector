// Package posture evaluates CWE→CAPEC attack pattern mappings against
// configuration audit findings to produce posture assessments.
package posture

import (
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// Evaluate checks all rules against the given findings and returns posture
// assessments for matched attack patterns.
func Evaluate(findings []model.ConfigFinding, assetID, scanRunID uuid.UUID) []model.PostureAssessment {
	if len(findings) == 0 {
		return nil
	}

	// Build a set of CWE IDs present in findings and map CWE→finding IDs.
	cweSet := make(map[string]bool)
	cweFindingIDs := make(map[string][]uuid.UUID)
	for _, f := range findings {
		cweSet[f.CWEID] = true
		cweFindingIDs[f.CWEID] = append(cweFindingIDs[f.CWEID], f.ID)
	}

	now := time.Now().UTC()
	var assessments []model.PostureAssessment

	for _, rule := range Rules {
		if !allCWEsPresent(rule.RequiredCWEs, cweSet) {
			continue
		}

		// Collect all finding IDs that contributed to this match.
		var matchedIDs []uuid.UUID
		seen := make(map[uuid.UUID]bool)
		for _, cwe := range rule.RequiredCWEs {
			for _, fid := range cweFindingIDs[cwe] {
				if !seen[fid] {
					matchedIDs = append(matchedIDs, fid)
					seen[fid] = true
				}
			}
		}

		assessments = append(assessments, model.PostureAssessment{
			ID:         uuid.Must(uuid.NewV7()),
			AssetID:    assetID,
			ScanRunID:  scanRunID,
			CAPECID:    rule.CAPECID,
			CAPECName:  rule.CAPECName,
			FindingIDs: matchedIDs,
			Likelihood: rule.Likelihood,
			Mitigation: rule.Mitigation,
			Timestamp:  now,
		})
	}

	return assessments
}

// allCWEsPresent returns true if every CWE in required is present in the set.
func allCWEsPresent(required []string, cweSet map[string]bool) bool {
	for _, cwe := range required {
		if !cweSet[cwe] {
			return false
		}
	}
	return true
}
