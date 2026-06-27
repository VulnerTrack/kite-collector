package winargcnvrg1023

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindOfficerDesignation), "cybersec-officer-designation"},
		{string(KindIncidentPlaybook), "cybersec-incident-playbook"},
		{string(KindIncidentRegistry), "cybersec-incident-registry"},
		{string(KindVulnScanReport), "cybersec-vuln-scan-report"},
		{string(KindPentestReport), "cybersec-pentest-report"},
		{string(KindBCPDRPlan), "cybersec-bcp-dr-plan"},
		{string(KindEncryptionPolicy), "cybersec-encryption-policy"},
		{string(KindAccessMatrix), "cybersec-access-matrix"},
		{string(KindDataClassification), "cybersec-data-classification"},
		{string(KindThirdPartyRisk), "cybersec-thirdparty-risk"},
		{string(KindMFADocumentation), "cybersec-mfa-documentation"},
		{string(KindAwarenessTraining), "cybersec-awareness-training"},
		{string(KindAuditReport), "cybersec-audit-report"},
		{string(KindInstaller), "cybersec-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(StatusCompliant), "compliant"},
		{string(StatusNonCompliant), "non-compliant"},
		{string(StatusPendingReview), "pending-review"},
		{string(StatusInProgress), "in-progress"},
		{string(StatusOther), "other"},
		{string(StatusUnknown), "unknown"},
		{string(SeverityCritical), "critical"},
		{string(SeverityHigh), "high"},
		{string(SeverityMedium), "medium"},
		{string(SeverityLow), "low"},
		{string(SeverityInfo), "info"},
		{string(SeverityNotApplicable), "not-applicable"},
		{string(SeverityUnknown), "unknown"},
		{string(SujetoALYC), "alyc"},
		{string(SujetoFCIAdmin), "fci-admin"},
		{string(SujetoFCICustodian), "fci-custodian"},
		{string(SujetoMercado), "mercado"},
		{string(SujetoCamaraCompensadora), "camara-compensadora"},
		{string(SujetoOther), "other"},
		{string(SujetoUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"rg1023_compliance.pdf",
		"cybersec_policy.docx",
		"officer_designation_20260615.pdf",
		"incident_playbook_v2.md",
		"incident_registry_2026.csv",
		"vuln_scan_q2_2026.json",
		"pentest_2026.pdf",
		"bcp_plan_2026.docx",
		"dr_plan.docx",
		"encryption_policy_2026.md",
		"access_matrix.xlsx",
		"data_classification_2026.xlsx",
		"third_party_risk_register.xlsx",
		"mfa_documentation.json",
		"awareness_training_log.csv",
		"audit_report_2026.pdf",
		"ciberseguridad_policy.pdf",
	}
	no := []string{"", "factura.pdf", "random.docx"}
	for _, v := range yes {
		if !IsCandidateName(v) {
			t.Fatalf("expected candidate: %q", v)
		}
	}
	for _, v := range no {
		if IsCandidateName(v) {
			t.Fatalf("expected NOT candidate: %q", v)
		}
	}
}

func TestArtifactKindFromName(t *testing.T) {
	cases := map[string]ArtifactKind{
		"officer_designation_20260615.pdf": KindOfficerDesignation,
		"incident_playbook_v2.md":          KindIncidentPlaybook,
		"incident_registry_2026.csv":       KindIncidentRegistry,
		"vuln_scan_q2_2026.json":           KindVulnScanReport,
		"pentest_2026.pdf":                 KindPentestReport,
		"bcp_plan_2026.docx":               KindBCPDRPlan,
		"dr_plan_2026.docx":                KindBCPDRPlan,
		"encryption_policy_2026.md":        KindEncryptionPolicy,
		"access_matrix.xlsx":               KindAccessMatrix,
		"data_classification_2026.xlsx":    KindDataClassification,
		"third_party_risk_register.xlsx":   KindThirdPartyRisk,
		"mfa_documentation.json":           KindMFADocumentation,
		"awareness_training_log.csv":       KindAwarenessTraining,
		"audit_report_2026.pdf":            KindAuditReport,
		"cybersec_v1_installer.msi":        KindInstaller,
		"":                                 KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSujetoReguladoFromPath(t *testing.T) {
	cases := map[string]SujetoReguladoKind{
		`C:\Compliance\ALYC\rg1023_policy.pdf`:         SujetoALYC,
		`C:\Compliance\FCI_Admin\policy.pdf`:           SujetoFCIAdmin,
		`C:\Compliance\FCI_Custodian\policy.pdf`:       SujetoFCICustodian,
		`C:\Compliance\Mercado\policy.pdf`:             SujetoMercado,
		`C:\Compliance\Camara_Compensadora\policy.pdf`: SujetoCamaraCompensadora,
		`C:\CNV\RG1023\generic.pdf`:                    SujetoOther,
		`C:\Random\path.pdf`:                           SujetoUnknown,
		"":                                             SujetoUnknown,
	}
	for in, want := range cases {
		if got := SujetoReguladoFromPath(in); got != want {
			t.Fatalf("SujetoReguladoFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	cases := []struct {
		a, b Severity
		want Severity
	}{
		{SeverityCritical, SeverityHigh, SeverityCritical},
		{SeverityLow, SeverityHigh, SeverityHigh},
		{SeverityUnknown, SeverityInfo, SeverityInfo},
		{SeverityCritical, SeverityCritical, SeverityCritical},
	}
	for _, c := range cases {
		if got := MaxSeverityOf(c.a, c.b); got != c.want {
			t.Fatalf("MaxSeverityOf(%q,%q)=%q want %q", c.a, c.b, got, c.want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"cliente 27-11111111-4", "27", "1114"},
		{"empresa 30-71234567-8", "30", "5678"},
		{"no cuit", "", ""},
		{"11-12345678-9", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestIsAnnualKind(t *testing.T) {
	yes := []ArtifactKind{
		KindPentestReport, KindAuditReport, KindBCPDRPlan,
		KindEncryptionPolicy, KindDataClassification,
		KindAwarenessTraining,
	}
	no := []ArtifactKind{
		KindOfficerDesignation, KindIncidentPlaybook,
		KindIncidentRegistry, KindVulnScanReport,
		KindAccessMatrix, KindThirdPartyRisk,
		KindMFADocumentation, KindInstaller,
		KindOther, KindUnknown,
	}
	for _, k := range yes {
		if !IsAnnualKind(k) {
			t.Fatalf("expected annual: %q", k)
		}
	}
	for _, k := range no {
		if IsAnnualKind(k) {
			t.Fatalf("expected NOT annual: %q", k)
		}
	}
}

func TestIsReviewOverdue(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		kind ArtifactKind
		date string
		want bool
	}{
		// Quarterly windows.
		{KindVulnScanReport, "2026-06-01", false}, // <90d
		{KindVulnScanReport, "2026-02-01", true},  // >90d
		// Annual windows.
		{KindPentestReport, "2025-12-01", false}, // <365d
		{KindPentestReport, "2024-12-01", true},  // >365d
		// Empty date = no opinion.
		{KindVulnScanReport, "", false},
		// Unparseable date.
		{KindVulnScanReport, "garbage", false},
	}
	for _, c := range cases {
		if got := IsReviewOverdue(c.kind, c.date, now); got != c.want {
			t.Fatalf("IsReviewOverdue(%q,%q)=%v want %v",
				c.kind, c.date, got, c.want)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateCriticalFinding(t *testing.T) {
	r := Row{
		ArtifactKind:  KindVulnScanReport,
		CriticalCount: 3,
		FileMode:      0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasCriticalFinding {
		t.Fatal("critical count > 0 must flag")
	}
}

func TestAnnotateOpenHighFinding(t *testing.T) {
	r := Row{
		ArtifactKind:     KindVulnScanReport,
		HighCount:        2,
		OpenFindingCount: 1,
		FileMode:         0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasOpenHighFinding {
		t.Fatal("high + open must flag")
	}
}

func TestAnnotateUnassessedThirdParty(t *testing.T) {
	r := Row{
		ArtifactKind:              KindThirdPartyRisk,
		ThirdPartyCount:           5,
		ThirdPartyUnassessedCount: 2,
		FileMode:                  0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasUnassessedThirdParty {
		t.Fatal("unassessed > 0 must flag")
	}
}

func TestAnnotateNoMFADocumented(t *testing.T) {
	r := Row{
		ArtifactKind:  KindMFADocumentation,
		MFAEntryCount: 0,
		FileMode:      0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasNoMFADocumented {
		t.Fatal("MFA doc with 0 entries must flag")
	}
}

func TestAnnotateMFADocumentedOK(t *testing.T) {
	r := Row{
		ArtifactKind:  KindMFADocumentation,
		MFAEntryCount: 3,
		FileMode:      0o644,
	}
	AnnotateSecurity(&r)
	if r.HasNoMFADocumented {
		t.Fatal("MFA doc with entries must NOT flag")
	}
}

func TestAnnotateClientePII(t *testing.T) {
	r := Row{
		ArtifactKind:       KindPentestReport,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClientePII {
		t.Fatal("cliente CUIT must flag PII")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + cliente PII = exposure: %+v", r)
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:       KindPentestReport,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseRG1023Artifact ------------------------------------------

func TestParseRG1023ArtifactPentest(t *testing.T) {
	body := []byte(`{
  "report_type": "pentest",
  "last_review_date": "2024-12-01",
  "compliance_status": "non-compliant",
  "findings": [
    {"finding_id": "F1", "severity": "critical", "status": "open"},
    {"finding_id": "F2", "severity": "high", "status": "open"},
    {"finding_id": "F3", "severity": "medium", "status": "remediated"}
  ],
  "cliente_cuit": "27-11111111-4",
  "oficial_ciberseguridad_cuit": "20-12345678-9"
}`)
	f := ParseRG1023Artifact(body)
	if f.ComplianceStatus != string(StatusNonCompliant) {
		t.Fatalf("status=%q", f.ComplianceStatus)
	}
	if f.MaxSeverity != SeverityCritical {
		t.Fatalf("max severity=%q", f.MaxSeverity)
	}
	if f.LastReviewDate != "2024-12-01" {
		t.Fatalf("last review=%q", f.LastReviewDate)
	}
	if f.FindingCount < 3 {
		t.Fatalf("findings=%d", f.FindingCount)
	}
	if f.OpenFindingCount < 2 {
		t.Fatalf("open=%d", f.OpenFindingCount)
	}
	if f.CriticalCount < 1 {
		t.Fatalf("critical=%d", f.CriticalCount)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
	if f.OfficerCuitRaw == "" {
		t.Fatal("officer cuit missing")
	}
}

func TestParseRG1023ArtifactMFA(t *testing.T) {
	body := []byte(`{
  "report_type": "mfa_documentation",
  "users": [
    {"user_id": "u1", "mfa_type": "totp"},
    {"user_id": "u2", "mfa_type": "fido2"},
    {"user_id": "u3", "mfa_type": "hardware"}
  ]
}`)
	f := ParseRG1023Artifact(body)
	if f.MFAEntryCount < 3 {
		t.Fatalf("mfa=%d want >=3", f.MFAEntryCount)
	}
}

func TestParseRG1023ArtifactThirdParty(t *testing.T) {
	body := []byte(`{
  "third_party": "vendor_a",
  "assessment_date": "2026-03-15",
  "third_party": "vendor_b",
  "third_party": "vendor_c"
}`)
	f := ParseRG1023Artifact(body)
	if f.ThirdPartyCount < 3 {
		t.Fatalf("tp count=%d", f.ThirdPartyCount)
	}
	if f.ThirdPartyUnassessedCount < 2 {
		t.Fatalf("unassessed=%d (3 entries, 1 assessment_date)", f.ThirdPartyUnassessedCount)
	}
}

func TestParseRG1023ArtifactIncidentRegistry(t *testing.T) {
	withPlaybook := []byte(`{
  "incident_id": "INC-001",
  "playbook_id": "PB-AUTH-002",
  "severity": "high"
}`)
	withoutPlaybook := []byte(`{
  "incident_id": "INC-002",
  "severity": "medium"
}`)
	f1 := ParseRG1023Artifact(withPlaybook)
	if !f1.HasIncidentMarker || !f1.HasPlaybookReference {
		t.Fatalf("withPlaybook: %+v", f1)
	}
	f2 := ParseRG1023Artifact(withoutPlaybook)
	if !f2.HasIncidentMarker || f2.HasPlaybookReference {
		t.Fatalf("withoutPlaybook: %+v", f2)
	}
}

func TestParseRG1023ArtifactEmpty(t *testing.T) {
	f := ParseRG1023Artifact(nil)
	if f.MaxSeverity != SeverityUnknown {
		t.Fatalf("empty must be unknown: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "Compliance", "CNV")
	must(t, os.MkdirAll(dir, 0o755))

	// Pentest report with critical finding + cliente CUIT, readable.
	pentestPath := filepath.Join(dir, "pentest_2026.json")
	must(t, os.WriteFile(pentestPath, []byte(`{
  "report_type": "pentest",
  "last_review_date": "2024-12-01",
  "compliance_status": "non-compliant",
  "findings": [
    {"finding_id": "F1", "severity": "critical", "status": "open"},
    {"finding_id": "F2", "severity": "high", "status": "open"}
  ],
  "cliente_cuit": "27-11111111-4"
}`), 0o644))

	// Vuln scan overdue (Feb 2026 vs now=Jun 24 2026 → >90d).
	vulnPath := filepath.Join(dir, "vuln_scan_q1_2026.json")
	must(t, os.WriteFile(vulnPath, []byte(`{
  "report_type": "vuln_scan",
  "last_review_date": "2026-02-01",
  "compliance_status": "in-progress",
  "findings": [
    {"finding_id": "V1", "severity": "medium", "status": "open"}
  ]
}`), 0o600))

	// MFA doc with no entries — non-compliance signal.
	mfaPath := filepath.Join(dir, "mfa_documentation_2026.json")
	must(t, os.WriteFile(mfaPath, []byte(`{
  "report_type": "mfa_documentation",
  "users": []
}`), 0o644))

	// Third-party register with unassessed entries.
	tpPath := filepath.Join(dir, "third_party_risk_register_2026.json")
	must(t, os.WriteFile(tpPath, []byte(`{
  "third_party": "vendor_a",
  "assessment_date": "2026-03-15",
  "third_party": "vendor_b",
  "third_party": "vendor_c"
}`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "Compliance", "CNV")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "pentest_skip.json"),
		[]byte(`{}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 (pentest+vuln+mfa+tp), got %d: %+v", len(got), got)
	}

	var pentest, vuln, mfa, tp Row
	for _, r := range got {
		switch r.FilePath {
		case pentestPath:
			pentest = r
		case vulnPath:
			vuln = r
		case mfaPath:
			mfa = r
		case tpPath:
			tp = r
		}
	}

	if pentest.ArtifactKind != KindPentestReport {
		t.Fatalf("pentest kind=%q", pentest.ArtifactKind)
	}
	if !pentest.HasCriticalFinding {
		t.Fatalf("pentest must flag critical: %+v", pentest)
	}
	if !pentest.HasOpenHighFinding {
		t.Fatalf("pentest must flag open high: %+v", pentest)
	}
	if !pentest.HasOverdueReview {
		t.Fatalf("pentest 2024-12-01 must flag overdue (annual): %+v", pentest)
	}
	if pentest.ComplianceStatus != StatusNonCompliant {
		t.Fatalf("pentest status=%q", pentest.ComplianceStatus)
	}
	if !pentest.HasClientePII {
		t.Fatalf("pentest must flag cliente PII: %+v", pentest)
	}
	if !pentest.IsCredentialExposureRisk {
		t.Fatalf("readable + PII + critical = exposure: %+v", pentest)
	}

	if vuln.ArtifactKind != KindVulnScanReport {
		t.Fatalf("vuln kind=%q", vuln.ArtifactKind)
	}
	if !vuln.HasOverdueReview {
		t.Fatalf("vuln 2026-02-01 must flag overdue (quarterly): %+v", vuln)
	}
	if vuln.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", vuln)
	}

	if mfa.ArtifactKind != KindMFADocumentation {
		t.Fatalf("mfa kind=%q", mfa.ArtifactKind)
	}
	if !mfa.HasNoMFADocumented {
		t.Fatalf("mfa 0 entries must flag: %+v", mfa)
	}

	if tp.ArtifactKind != KindThirdPartyRisk {
		t.Fatalf("tp kind=%q", tp.ArtifactKind)
	}
	if !tp.HasUnassessedThirdParty {
		t.Fatalf("tp must flag unassessed: %+v", tp)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-rg1023")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "pentest_2026.json"),
		[]byte(`{"compliance_status":"compliant"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "CNV_RG1023_DIR" {
				return envDir
			}
			return ""
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
		now:      func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || got[0].ArtifactKind != KindPentestReport {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-rg1023"},
		usersBases:   []string{"/nope-users"},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortRowsDeterministic(t *testing.T) {
	in := []Row{
		{FilePath: "z", ArtifactKind: KindPentestReport},
		{FilePath: "a", ArtifactKind: KindVulnScanReport},
		{FilePath: "a", ArtifactKind: KindPentestReport},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindPentestReport {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashContents(t *testing.T) {
	a := HashContents([]byte("rg1023"))
	b := HashContents([]byte("rg1023"))
	c := HashContents([]byte("RG1023"))
	if a != b {
		t.Fatal("hash drift")
	}
	if a == c {
		t.Fatal("hash collision case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
