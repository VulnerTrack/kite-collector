package posture

import (
	"testing"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestEvaluate_NoFindings(t *testing.T) {
	assessments := Evaluate(nil, uuid.New(), uuid.New())
	if len(assessments) != 0 {
		t.Fatalf("expected 0 assessments for nil findings, got %d", len(assessments))
	}
}

func TestEvaluate_SingleCWEMatch(t *testing.T) {
	assetID := uuid.Must(uuid.NewV7())
	scanID := uuid.Must(uuid.NewV7())
	findingID := uuid.Must(uuid.NewV7())

	findings := []model.ConfigFinding{
		{
			ID:      findingID,
			AssetID: assetID,
			CWEID:   "CWE-287",
			Auditor: "ssh",
			CheckID: "ssh-002",
		},
	}

	assessments := Evaluate(findings, assetID, scanID)

	// CWE-287 should match CAPEC-49 (Password Brute Forcing)
	found := false
	for _, a := range assessments {
		if a.CAPECID == "CAPEC-49" {
			found = true
			if a.Likelihood != model.SeverityHigh {
				t.Errorf("expected high likelihood, got %s", a.Likelihood)
			}
			if len(a.FindingIDs) != 1 || a.FindingIDs[0] != findingID {
				t.Errorf("expected finding ID %s, got %v", findingID, a.FindingIDs)
			}
			if a.AssetID != assetID {
				t.Errorf("expected asset ID %s, got %s", assetID, a.AssetID)
			}
			if a.ScanRunID != scanID {
				t.Errorf("expected scan ID %s, got %s", scanID, a.ScanRunID)
			}
		}
	}
	if !found {
		t.Error("expected CAPEC-49 assessment for CWE-287 finding")
	}
}

func TestEvaluate_MultiCWERule(t *testing.T) {
	assetID := uuid.Must(uuid.NewV7())
	scanID := uuid.Must(uuid.NewV7())

	findings := []model.ConfigFinding{
		{ID: uuid.Must(uuid.NewV7()), AssetID: assetID, CWEID: "CWE-284"},
		{ID: uuid.Must(uuid.NewV7()), AssetID: assetID, CWEID: "CWE-770"},
	}

	assessments := Evaluate(findings, assetID, scanID)

	// CWE-284 + CWE-770 should match CAPEC-125 (Flooding)
	found := false
	for _, a := range assessments {
		if a.CAPECID == "CAPEC-125" {
			found = true
			if len(a.FindingIDs) != 2 {
				t.Errorf("expected 2 finding IDs, got %d", len(a.FindingIDs))
			}
		}
	}
	if !found {
		t.Error("expected CAPEC-125 assessment for CWE-284 + CWE-770")
	}
}

func TestEvaluate_MultiCWERulePartialMatch(t *testing.T) {
	assetID := uuid.Must(uuid.NewV7())
	scanID := uuid.Must(uuid.NewV7())

	// Only CWE-284 present, CWE-770 missing - CAPEC-125 should NOT match
	findings := []model.ConfigFinding{
		{ID: uuid.Must(uuid.NewV7()), AssetID: assetID, CWEID: "CWE-284"},
	}

	assessments := Evaluate(findings, assetID, scanID)

	for _, a := range assessments {
		if a.CAPECID == "CAPEC-125" {
			t.Error("CAPEC-125 should not match with only CWE-284 (needs CWE-770 too)")
		}
	}
}

func TestEvaluate_MultipleMatches(t *testing.T) {
	assetID := uuid.Must(uuid.NewV7())
	scanID := uuid.Must(uuid.NewV7())

	// CWE-250 and CWE-732 together should match both CAPEC-115 and CAPEC-233
	findings := []model.ConfigFinding{
		{ID: uuid.Must(uuid.NewV7()), AssetID: assetID, CWEID: "CWE-250"},
		{ID: uuid.Must(uuid.NewV7()), AssetID: assetID, CWEID: "CWE-732"},
	}

	assessments := Evaluate(findings, assetID, scanID)

	capecs := make(map[string]bool)
	for _, a := range assessments {
		capecs[a.CAPECID] = true
	}

	if !capecs["CAPEC-115"] {
		t.Error("expected CAPEC-115 (Authentication Bypass) for CWE-250")
	}
	if !capecs["CAPEC-122"] {
		t.Error("expected CAPEC-122 (Privilege Abuse) for CWE-732")
	}
	if !capecs["CAPEC-233"] {
		t.Error("expected CAPEC-233 (Privilege Escalation) for CWE-250 + CWE-732")
	}
}

func TestEvaluate_NoMatchingCWEs(t *testing.T) {
	assetID := uuid.Must(uuid.NewV7())
	scanID := uuid.Must(uuid.NewV7())

	findings := []model.ConfigFinding{
		{ID: uuid.Must(uuid.NewV7()), AssetID: assetID, CWEID: "CWE-999"},
	}

	assessments := Evaluate(findings, assetID, scanID)
	if len(assessments) != 0 {
		t.Fatalf("expected 0 assessments for unknown CWE, got %d", len(assessments))
	}
}

func TestEvaluate_DuplicateCWEFindings(t *testing.T) {
	assetID := uuid.Must(uuid.NewV7())
	scanID := uuid.Must(uuid.NewV7())

	// Two findings with the same CWE should both appear in FindingIDs
	fid1 := uuid.Must(uuid.NewV7())
	fid2 := uuid.Must(uuid.NewV7())
	findings := []model.ConfigFinding{
		{ID: fid1, AssetID: assetID, CWEID: "CWE-287"},
		{ID: fid2, AssetID: assetID, CWEID: "CWE-287"},
	}

	assessments := Evaluate(findings, assetID, scanID)

	for _, a := range assessments {
		if a.CAPECID == "CAPEC-49" {
			if len(a.FindingIDs) != 2 {
				t.Errorf("expected 2 finding IDs for duplicate CWE, got %d", len(a.FindingIDs))
			}
		}
	}
}

func TestAllCWEsPresent(t *testing.T) {
	cweSet := map[string]bool{"CWE-287": true, "CWE-284": true, "CWE-770": true}

	if !allCWEsPresent([]string{"CWE-287"}, cweSet) {
		t.Error("single present CWE should return true")
	}
	if !allCWEsPresent([]string{"CWE-284", "CWE-770"}, cweSet) {
		t.Error("both present CWEs should return true")
	}
	if allCWEsPresent([]string{"CWE-284", "CWE-999"}, cweSet) {
		t.Error("missing CWE should return false")
	}
	if !allCWEsPresent([]string{}, cweSet) {
		t.Error("empty required should return true")
	}
}
