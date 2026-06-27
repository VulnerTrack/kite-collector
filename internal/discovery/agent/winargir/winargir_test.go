package winargir

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindHechoRelevanteDraft), "ir-hecho-relevante-draft"},
		{string(KindInsiderList), "ir-insider-list"},
		{string(KindEarningsCallScript), "ir-earnings-call-script"},
		{string(KindEarningsCallQA), "ir-earnings-call-qa"},
		{string(KindPressRelease), "ir-press-release"},
		{string(KindSustainabilityReport), "ir-sustainability-report"},
		{string(KindESGDisclosure), "ir-esg-disclosure"},
		{string(KindMemoriaAnual), "ir-memoria-anual"},
		{string(IssuerPanelLider), "panel-lider"},
		{string(IssuerCEDEARIssuer), "cedear-issuer"},
		{string(IssuerCrossListedUSIssuer), "cross-listed-us-issuer"},
		{string(RoleIRDirector), "ir-director"},
		{string(RoleCFO), "cfo"},
		{string(RoleBoardSecretary), "board-secretary"},
		{string(PhaseQ4), "q4"},
		{string(PhaseEventDriven), "event-driven"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"hecho_relevante_20260615.pdf",
		"insider_list_q2_2026.csv",
		"earnings_call_q2_2026.pdf",
		"earnings_call_qa_q2_2026.pdf",
		"press_release_q2.pdf",
		"analyst_report_jpmorgan.pdf",
		"analyst_coverage_2026.csv",
		"roadshow_nyc.pdf",
		"conference_call_q2_2026.mp3",
		"sustainability_report_2025.pdf",
		"esg_disclosure_2025.pdf",
		"memoria_anual_2025.pdf",
		"estados_contables_q2_2026.pdf",
		"conflict_disclosure_director.pdf",
		"ir_config.ini",
	}
	no := []string{"", "factura.xml", "random.bin", "report.pdf", "notes.txt"}
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
		"hecho_relevante_20260615.pdf":     KindHechoRelevanteDraft,
		"insider_list_q2_2026.csv":         KindInsiderList,
		"earnings_call_q2_2026.pdf":        KindEarningsCallScript,
		"earnings_call_qa_q2_2026.pdf":     KindEarningsCallQA,
		"press_release_q2.pdf":             KindPressRelease,
		"analyst_report_jpmorgan.pdf":      KindAnalystReport,
		"analyst_coverage_2026.csv":        KindAnalystCoverageList,
		"roadshow_nyc.pdf":                 KindRoadshow,
		"conference_call_q2_2026.mp3":      KindConferenceCallRecording,
		"sustainability_report_2025.pdf":   KindSustainabilityReport,
		"esg_disclosure_2025.pdf":          KindESGDisclosure,
		"memoria_anual_2025.pdf":           KindMemoriaAnual,
		"estados_contables_q2_2026.pdf":    KindEstadosContablesPublic,
		"conflict_disclosure_director.pdf": KindConflictDisclosure,
		"ir_config.ini":                    KindConfig,
		"credentials.json":                 KindCredentials,
		"ir_setup.msi":                     KindInstaller,
		"":                                 KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitEntityOnlyFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"emisor 30-71234567-8", "30", "5678"},
		{"individual 27-11111111-4", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuitEntityOnlyFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitEntityOnlyFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestCuilFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"insider 27-11111111-4", "27", "1114"},
		{"emisor 30-71234567-8", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuilFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuilFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestPanelLider(t *testing.T) {
	yes := []string{"GGAL", "YPFD", "PAMP"}
	no := []string{"", "AAPL", "AL30"}
	for _, v := range yes {
		if !IsPanelLiderStem(v) {
			t.Fatalf("expected panel líder: %q", v)
		}
	}
	for _, v := range no {
		if IsPanelLiderStem(v) {
			t.Fatalf("expected NOT panel líder: %q", v)
		}
	}
}

func TestCrossListedUSIssuer(t *testing.T) {
	yes := []string{"YPF", "GGAL", "MELI"}
	no := []string{"", "ALUA", "COME"}
	for _, v := range yes {
		if !IsCrossListedUSIssuerStem(v) {
			t.Fatalf("expected ADR: %q", v)
		}
	}
	for _, v := range no {
		if IsCrossListedUSIssuerStem(v) {
			t.Fatalf("expected NOT ADR: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindHechoRelevanteDraft, KindInsiderList,
		KindEarningsCallScript, KindEarningsCallQA,
		KindPressRelease, KindAnalystReport,
		KindAnalystCoverageList, KindRoadshow,
		KindConferenceCallRecording,
		KindSustainabilityReport, KindESGDisclosure,
		KindMemoriaAnual, KindEstadosContablesPublic,
		KindConflictDisclosure,
		KindConfig, KindCredentials,
	}
	for _, k := range yes {
		if !IsCredentialKind(k) {
			t.Fatalf("expected cred kind: %q", k)
		}
	}
	for _, k := range []ArtifactKind{KindInstaller, KindOther, KindUnknown} {
		if IsCredentialKind(k) {
			t.Fatalf("expected NOT cred kind: %q", k)
		}
	}
}

func TestIsPrePublicationKind(t *testing.T) {
	yes := []ArtifactKind{
		KindHechoRelevanteDraft, KindEarningsCallScript,
		KindEarningsCallQA, KindPressRelease,
		KindRoadshow, KindSustainabilityReport,
		KindESGDisclosure, KindMemoriaAnual,
	}
	for _, k := range yes {
		if !IsPrePublicationKind(k) {
			t.Fatalf("expected pre-pub kind: %q", k)
		}
	}
	no := []ArtifactKind{
		KindInsiderList, KindAnalystReport,
		KindAnalystCoverageList, KindConferenceCallRecording,
		KindEstadosContablesPublic, KindConflictDisclosure,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range no {
		if IsPrePublicationKind(k) {
			t.Fatalf("expected NOT pre-pub kind: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:             KindHechoRelevanteDraft,
		HasPasswordInConfig:      true,
		ClienteEmisorCuitPrefix:  "30",
		ClienteEmisorCuitSuffix4: "5678",
		FileMode:                 0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteEmisorCuit {
		t.Fatal("emisor cuit must flag")
	}
	if !r.HasHechoRelevanteDraft {
		t.Fatal("HR kind must auto-flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + emisor = exposure")
	}
}

func TestAnnotateHechoRelevanteAlwaysPrePub(t *testing.T) {
	r := Row{
		ArtifactKind: KindHechoRelevanteDraft,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsPrePublicationFindingRisk {
		t.Fatal("readable + HR = pre-pub (always)")
	}
}

func TestAnnotateInsiderListPII(t *testing.T) {
	r := Row{
		ArtifactKind:       KindInsiderList,
		InsiderCuilPrefix:  "27",
		InsiderCuilSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasInsiderList {
		t.Fatal("insider kind must flag")
	}
	if !r.HasInsiderCuil {
		t.Fatal("insider CUIL must flag")
	}
	if !r.IsInsiderListPIIRisk {
		t.Fatal("readable + insider list + CUIL = PII risk")
	}
}

func TestAnnotateInsiderListLarge(t *testing.T) {
	r := Row{
		ArtifactKind: KindInsiderList,
		InsiderCount: LargeInsiderListThreshold + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasInsiderListLarge {
		t.Fatal("> 50 insiders must flag large")
	}
}

func TestAnnotateDraftEarningsScriptPrePub(t *testing.T) {
	r := Row{
		ArtifactKind:           KindEarningsCallScript,
		HasPrePublicationDraft: true,
		FileMode:               0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsPrePublicationFindingRisk {
		t.Fatal("readable + draft + earnings script = pre-pub")
	}
}

func TestParseHechoRelevanteDraft(t *testing.T) {
	body := []byte(`HECHO RELEVANTE - DRAFT
EMBARGOED - MNPI
cnv_filing_id: HR-2026-0123
issuer_name: YPF S.A.
panel: panel lider
NYSE
cliente_emisor_cuit: 30-71234567-8
insider_cuil: 27-11111111-4
`)
	f := ParseHechoRelevanteDraft(body)
	if f.CNVFilingID != "HR-2026-0123" {
		t.Fatalf("filing=%q", f.CNVFilingID)
	}
	if f.IssuerName != "YPF S.A." {
		t.Fatalf("issuer=%q", f.IssuerName)
	}
	if f.IssuerClass != IssuerPanelLider {
		t.Fatalf("class=%q want panel-lider", f.IssuerClass)
	}
	if !f.HasPrePublicationDraft {
		t.Fatal("DRAFT/EMBARGOED must flag pre-pub")
	}
	if !f.HasCrossListedUSIssuer {
		t.Fatal("NYSE must flag cross-listed")
	}
	if f.ClienteEmisorCuitRaw == "" {
		t.Fatal("emisor cuit must extract")
	}
	if f.InsiderCuilRaw == "" {
		t.Fatal("insider cuil must extract")
	}
}

func TestParseInsiderList(t *testing.T) {
	body := []byte(`Insider List Q2 2026
insider_count: 65
INS-001,27-11111111-4,Director General
INS-002,20-22222222-3,CFO
INS-003,23-33333333-4,Board Secretary
`)
	f := ParseInsiderList(body)
	if f.InsiderCount != 65 {
		t.Fatalf("count=%d want 65", f.InsiderCount)
	}
}

func TestParseEarningsCallScriptDraft(t *testing.T) {
	body := []byte(`Earnings Call Script Q2 2026
DRAFT - For Internal Use Only
issuer_name: Grupo Galicia
panel: panel lider
disclosure_phase: Q2
`)
	f := ParseEarningsCallScript(body)
	if !f.HasPrePublicationDraft {
		t.Fatal("DRAFT must flag")
	}
	if f.DisclosurePhase != PhaseQ2 {
		t.Fatalf("phase=%q want q2", f.DisclosurePhase)
	}
}

func TestDetectIssuerClass(t *testing.T) {
	cases := map[string]IssuerClass{
		"panel lider":           IssuerPanelLider,
		"panel general":         IssuerPanelGeneral,
		"CEDEAR":                IssuerCEDEARIssuer,
		"sub-sovereign":         IssuerSubSovereign,
		"provincia":             IssuerSubSovereign,
		"sovereign":             IssuerSovereign,
		"financial institution": IssuerFinancialInstitution,
		"banco":                 IssuerFinancialInstitution,
		"insurance":             IssuerInsuranceCompany,
		"fideicomiso":           IssuerFideicomisoFinanciero,
		"PYME":                  IssuerPYME,
		"cross-listed ADR":      IssuerCrossListedUSIssuer,
		"random":                IssuerUnknown,
	}
	for in, want := range cases {
		got := detectIssuerClass(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectDisclosurePhase(t *testing.T) {
	cases := map[string]DisclosurePhase{
		"Q1":               PhaseQ1,
		"first quarter":    PhaseQ1,
		"primer trimestre": PhaseQ1,
		"Q2":               PhaseQ2,
		"Q3":               PhaseQ3,
		"Q4":               PhaseQ4,
		"annual":           PhaseAnnual,
		"event-driven":     PhaseEventDriven,
		"roadshow":         PhaseRoadshow,
		"random":           PhaseUnknown,
	}
	for in, want := range cases {
		got := detectDisclosurePhase(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyIRRole(t *testing.T) {
	if got := classifyIRRole(Row{HasHechoRelevanteDraft: true, HasInsiderList: true}); got != RoleComplianceOfficer {
		t.Fatalf("hr+insider -> compliance, got %q", got)
	}
	if got := classifyIRRole(Row{HasEstadosContablesPublic: true, HasMemoriaAnual: true}); got != RoleCFO {
		t.Fatalf("ec+ma -> cfo, got %q", got)
	}
	if got := classifyIRRole(Row{HasMemoriaAnual: true}); got != RoleCEO {
		t.Fatalf("ma -> ceo, got %q", got)
	}
	if got := classifyIRRole(Row{HasConflictDisclosure: true, HasInsiderList: true}); got != RoleBoardSecretary {
		t.Fatalf("coi+insider -> board-secretary, got %q", got)
	}
	if got := classifyIRRole(Row{HasHechoRelevanteDraft: true, HasRoadshowMaterial: true}); got != RoleIRDirector {
		t.Fatalf("hr+roadshow -> ir-director, got %q", got)
	}
	if got := classifyIRRole(Row{HasEarningsCallScript: true}); got != RoleIRManager {
		t.Fatalf("earnings script -> ir-manager, got %q", got)
	}
	if got := classifyIRRole(Row{HasAnalystReport: true}); got != RoleIRAnalyst {
		t.Fatalf("analyst -> ir-analyst, got %q", got)
	}
	if got := classifyIRRole(Row{HasPressReleaseDraft: true}); got != RoleCommunicationsLead {
		t.Fatalf("press -> communications-lead, got %q", got)
	}
	if got := classifyIRRole(Row{HasHechoRelevanteDraft: true}); got != RoleIRDirector {
		t.Fatalf("hr alone -> ir-director, got %q", got)
	}
	if got := classifyIRRole(Row{HasInsiderList: true}); got != RoleComplianceOfficer {
		t.Fatalf("insider alone -> compliance, got %q", got)
	}
	if got := classifyIRRole(Row{HasConflictDisclosure: true}); got != RoleGeneralCounsel {
		t.Fatalf("coi alone -> general-counsel, got %q", got)
	}
	if got := classifyIRRole(Row{HasRoadshowMaterial: true}); got != RoleIRDirector {
		t.Fatalf("roadshow -> ir-director, got %q", got)
	}
	if got := classifyIRRole(Row{ArtifactKind: KindConfig}); got != RoleAPI {
		t.Fatalf("config -> api, got %q", got)
	}
	if got := classifyIRRole(Row{}); got != RoleUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	irDir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "IR")
	must(t, os.MkdirAll(irDir, 0o755))

	hrPath := filepath.Join(irDir, "hecho_relevante_20260615.pdf")
	must(t, os.WriteFile(hrPath, []byte(`HECHO RELEVANTE - DRAFT
EMBARGOED
cnv_filing_id: HR-2026-0123
issuer_name: YPF S.A.
NYSE
cliente_emisor_cuit: 30-71234567-8
`), 0o644))

	ilPath := filepath.Join(irDir, "insider_list_q2_2026.csv")
	must(t, os.WriteFile(ilPath, []byte(`Insider List Q2 2026
insider_count: 65
INS-001,27-11111111-4,Director General
INS-002,20-22222222-3,CFO
`), 0o644))

	ecPath := filepath.Join(irDir, "earnings_call_q2_2026.pdf")
	must(t, os.WriteFile(ecPath, []byte(`Earnings Call Script Q2 2026
DRAFT - For Internal Use Only
issuer_name: YPF S.A.
disclosure_phase: Q2
`), 0o644))

	must(t, os.WriteFile(filepath.Join(irDir, "random.txt"),
		[]byte(`nope`), 0o644))

	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "IR")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "hecho_relevante.pdf"),
		[]byte(`# public`), 0o644))

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
	if len(got) != 3 {
		t.Fatalf("want 3 (hr+il+ec), got %d: %+v", len(got), got)
	}

	var hr, il, ec Row
	for _, r := range got {
		switch r.FilePath {
		case hrPath:
			hr = r
		case ilPath:
			il = r
		case ecPath:
			ec = r
		}
	}

	if hr.ArtifactKind != KindHechoRelevanteDraft {
		t.Fatalf("hr kind=%q", hr.ArtifactKind)
	}
	if !hr.HasHechoRelevanteDraft {
		t.Fatalf("hr must flag: %+v", hr)
	}
	if !hr.HasPrePublicationDraft {
		t.Fatalf("hr must flag draft: %+v", hr)
	}
	if !hr.HasCrossListedUSIssuer {
		t.Fatalf("hr must flag NYSE: %+v", hr)
	}
	if !hr.HasClienteEmisorCuit {
		t.Fatalf("hr must flag emisor cuit: %+v", hr)
	}
	if !hr.IsPrePublicationFindingRisk {
		t.Fatalf("hr must flag pre-pub: %+v", hr)
	}

	if il.ArtifactKind != KindInsiderList {
		t.Fatalf("il kind=%q", il.ArtifactKind)
	}
	if !il.HasInsiderList {
		t.Fatalf("il must flag: %+v", il)
	}
	if il.InsiderCount != 65 {
		t.Fatalf("il count=%d", il.InsiderCount)
	}
	if !il.HasInsiderListLarge {
		t.Fatalf("il > 50 must flag large: %+v", il)
	}
	if il.IRRole != RoleComplianceOfficer {
		t.Fatalf("il should classify as compliance, got %q", il.IRRole)
	}

	if ec.ArtifactKind != KindEarningsCallScript {
		t.Fatalf("ec kind=%q", ec.ArtifactKind)
	}
	if !ec.HasEarningsCallScript {
		t.Fatalf("ec must flag: %+v", ec)
	}
	if !ec.HasPrePublicationDraft {
		t.Fatalf("ec must flag draft: %+v", ec)
	}
	if ec.DisclosurePhase != PhaseQ2 {
		t.Fatalf("ec phase=%q", ec.DisclosurePhase)
	}
	if !ec.IsPrePublicationFindingRisk {
		t.Fatalf("ec must flag pre-pub: %+v", ec)
	}
	if ec.IRRole != RoleIRManager {
		t.Fatalf("ec should classify as ir-manager, got %q", ec.IRRole)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-ir")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "ir_config.ini"),
		[]byte(`[IR]
ir_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "IR_DIR" {
				return custom
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
	if len(got) != 1 {
		t.Fatalf("want 1 from env-override, got %d", len(got))
	}
	if !got[0].HasPasswordInConfig {
		t.Fatalf("env-override row must flag password")
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-ir"},
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
	rs := []Row{
		{FilePath: "/b", ArtifactKind: KindHechoRelevanteDraft},
		{FilePath: "/a", ArtifactKind: KindInsiderList},
		{FilePath: "/a", ArtifactKind: KindHechoRelevanteDraft},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindHechoRelevanteDraft {
		t.Fatalf("sort drift: %+v", rs)
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("abc")
	b := HashSecret("ABC")
	if a != b {
		t.Fatal("hash must be case-insensitive")
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
