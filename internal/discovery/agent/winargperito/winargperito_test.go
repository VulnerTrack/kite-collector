package winargperito

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindWorkpaper), "per-workpaper"},
		{string(KindEngagementLetter), "per-engagement-letter"},
		{string(KindConfirmationBank), "per-confirmation-bank"},
		{string(KindLetterRepresentations), "per-letter-representations"},
		{string(KindInternalControlDeficiency), "per-internal-control-deficiency"},
		{string(KindGoingConcernOpinion), "per-going-concern-opinion"},
		{string(FirmPwCArgentina), "pwc-argentina"},
		{string(FirmDeloitteArgentina), "deloitte-argentina"},
		{string(FirmEYArgentina), "ey-argentina"},
		{string(FirmKPMGArgentina), "kpmg-argentina"},
		{string(FirmBDOArgentina), "bdo-argentina"},
		{string(RolePartner), "partner"},
		{string(RoleSeniorManager), "senior-manager"},
		{string(RoleQualityReviewer), "quality-reviewer"},
		{string(ClientCNVListedCompany), "cnv-listed-company"},
		{string(ClientCrossListedUSIssuer), "cross-listed-us-issuer"},
		{string(PhaseYearEnd), "year-end"},
		{string(PhaseQualityReview), "quality-review"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"papeles_de_trabajo_GGAL_2026.pdf",
		"workpaper_audit_AAPL.xlsx",
		"engagement_letter_2026.pdf",
		"internal_control_assessment.pdf",
		"confirmation_bank_galicia.pdf",
		"confirmation_brokerage_cohen.pdf",
		"confirmation_legal_perez.pdf",
		"letter_representations_GGAL.pdf",
		"internal_control_deficiency.pdf",
		"audit_fee_2026.csv",
		"audit_committee_minutes_15.pdf",
		"management_letter_2026.pdf",
		"audit_plan_GGAL_2026.pdf",
		"going_concern_opinion.pdf",
		"soc1_aws_2026.pdf",
		"subsequent_events_2026.pdf",
		"pwc_config.ini",
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
		"papeles_de_trabajo_GGAL_2026.pdf": KindWorkpaper,
		"workpaper_audit_AAPL.xlsx":        KindWorkpaper,
		"engagement_letter_2026.pdf":       KindEngagementLetter,
		"internal_control_assessment.pdf":  KindInternalControlAssessment,
		"confirmation_bank_galicia.pdf":    KindConfirmationBank,
		"confirmation_brokerage_cohen.pdf": KindConfirmationBrokerage,
		"confirmation_legal_perez.pdf":     KindConfirmationLegal,
		"letter_representations_GGAL.pdf":  KindLetterRepresentations,
		"internal_control_deficiency.pdf":  KindInternalControlDeficiency,
		"audit_fee_2026.csv":               KindAuditFeeSchedule,
		"audit_committee_minutes_15.pdf":   KindAuditCommitteeMinutes,
		"management_letter_2026.pdf":       KindManagementLetter,
		"audit_plan_GGAL_2026.pdf":         KindAuditPlan,
		"going_concern_opinion.pdf":        KindGoingConcernOpinion,
		"soc1_aws_2026.pdf":                KindSOCRelianceReport,
		"subsequent_events_2026.pdf":       KindSubsequentEventsReview,
		"auditor_config.ini":               KindConfig,
		"credentials.json":                 KindCredentials,
		"auditor_setup.msi":                KindInstaller,
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
		{"individuo 27-11111111-4", "", ""},
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
		{"auditor 27-11111111-4", "27", "1114"},
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

func TestCrossListedUSIssuer(t *testing.T) {
	yes := []string{"YPF", "GGAL", "BMA", "MELI", "BBAR"}
	no := []string{"", "ALUA", "PAMP"}
	// PAMP is local panel-líder but ADR is "PAM". The test
	// here distinguishes the ADR ticker from local.
	for _, v := range yes {
		if !IsCrossListedUSIssuerStem(v) {
			t.Fatalf("expected ADR: %q", v)
		}
	}
	_ = no // PAMP is listed (panel-líder mirror); ALUA isn't.
	if !IsCrossListedUSIssuerStem("PAMP") {
		t.Fatal("PAMP must be in mirror list")
	}
	if IsCrossListedUSIssuerStem("ALUA") {
		t.Fatal("ALUA must NOT be on ADR list")
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindWorkpaper, KindEngagementLetter,
		KindInternalControlAssessment,
		KindConfirmationBank, KindConfirmationBrokerage,
		KindConfirmationLegal, KindLetterRepresentations,
		KindInternalControlDeficiency,
		KindAuditFeeSchedule, KindAuditCommitteeMinutes,
		KindManagementLetter, KindAuditPlan,
		KindGoingConcernOpinion, KindSOCRelianceReport,
		KindSubsequentEventsReview,
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
		KindWorkpaper, KindInternalControlDeficiency,
		KindGoingConcernOpinion, KindAuditCommitteeMinutes,
		KindManagementLetter, KindSubsequentEventsReview,
	}
	for _, k := range yes {
		if !IsPrePublicationKind(k) {
			t.Fatalf("expected pre-pub kind: %q", k)
		}
	}
}

func TestIsCounterpartyConfirmationKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfirmationBank, KindConfirmationBrokerage,
		KindConfirmationLegal,
	}
	for _, k := range yes {
		if !IsCounterpartyConfirmationKind(k) {
			t.Fatalf("expected counterparty kind: %q", k)
		}
	}
	no := []ArtifactKind{
		KindWorkpaper, KindEngagementLetter,
		KindInternalControlAssessment,
		KindLetterRepresentations, KindInternalControlDeficiency,
		KindConfig, KindCredentials,
	}
	for _, k := range no {
		if IsCounterpartyConfirmationKind(k) {
			t.Fatalf("expected NOT counterparty kind: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:             KindWorkpaper,
		HasPasswordInConfig:      true,
		ClienteEmisorCuitPrefix:  "30",
		ClienteEmisorCuitSuffix4: "5678",
		FileMode:                 0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteEmisorCuit {
		t.Fatal("emisor cuit must flag")
	}
	if !r.HasWorkpaper {
		t.Fatal("workpaper kind must auto-flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + emisor = exposure")
	}
}

func TestAnnotatePrePublicationFinding(t *testing.T) {
	r := Row{
		ArtifactKind:   KindWorkpaper,
		HasDraftMarker: true,
		FileMode:       0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsPrePublicationFindingRisk {
		t.Fatal("readable + draft + workpaper = pre-pub finding risk")
	}
}

func TestAnnotateGoingConcernAlwaysPrePub(t *testing.T) {
	r := Row{
		ArtifactKind: KindGoingConcernOpinion,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsPrePublicationFindingRisk {
		t.Fatal("readable + going concern = pre-pub (always)")
	}
}

func TestAnnotateICDRAlwaysPrePub(t *testing.T) {
	r := Row{
		ArtifactKind: KindInternalControlDeficiency,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsPrePublicationFindingRisk {
		t.Fatal("readable + ICDR = pre-pub (always)")
	}
}

func TestAnnotateCounterpartyDisclosure(t *testing.T) {
	r := Row{
		ArtifactKind: KindConfirmationBank,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsCounterpartyDisclosureRisk {
		t.Fatal("readable + bank confirm = counterparty disclosure")
	}
}

func TestAnnotateIndependenceBreach(t *testing.T) {
	r := Row{
		ArtifactKind:           KindAuditFeeSchedule,
		AuditFeeARSMillions:    100,
		NonAuditFeeARSMillions: 80,
		FileMode:               0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasIndependenceBreach {
		t.Fatal("non-audit > 50% must flag independence breach")
	}
}

func TestAnnotateNoIndependenceBreach(t *testing.T) {
	r := Row{
		ArtifactKind:           KindAuditFeeSchedule,
		AuditFeeARSMillions:    100,
		NonAuditFeeARSMillions: 20,
		FileMode:               0o644,
	}
	AnnotateSecurity(&r)
	if r.HasIndependenceBreach {
		t.Fatal("non-audit < 50% must NOT flag breach")
	}
}

func TestParseEngagementLetter(t *testing.T) {
	body := []byte(`Engagement Letter
engagement_id: ENG-2026-0123
client_name: Grupo Galicia
audit_firm: PwC Argentina
client_class: CNV-listed company
audit_phase: planning
audit_fee: 80000000
non_audit_fee: 15000000
cliente_emisor_cuit: 30-71234567-8
auditor_cuil: 27-11111111-4
NYSE
`)
	f := ParseEngagementLetter(body)
	if f.EngagementID != "ENG-2026-0123" {
		t.Fatalf("engagement=%q", f.EngagementID)
	}
	if f.ClientName != "Grupo Galicia" {
		t.Fatalf("client=%q", f.ClientName)
	}
	if f.AuditFirm != FirmPwCArgentina {
		t.Fatalf("firm=%q want pwc", f.AuditFirm)
	}
	if f.ClientClass != ClientCNVListedCompany {
		t.Fatalf("class=%q want cnv-listed-company", f.ClientClass)
	}
	if f.AuditPhase != PhasePlanning {
		t.Fatalf("phase=%q", f.AuditPhase)
	}
	if f.AuditFeeARSMillions != 80 {
		t.Fatalf("fee=%d want 80", f.AuditFeeARSMillions)
	}
	if f.NonAuditFeeARSMillions != 15 {
		t.Fatalf("non-audit fee=%d want 15", f.NonAuditFeeARSMillions)
	}
	if f.ClienteEmisorCuitRaw == "" {
		t.Fatal("emisor cuit must extract")
	}
	if f.AuditorCuilRaw == "" {
		t.Fatal("auditor cuil must extract")
	}
	if !f.HasCrossListedUSIssuer {
		t.Fatal("NYSE marker must flag cross-listed")
	}
}

func TestParseWorkpaperWithDraft(t *testing.T) {
	body := []byte(`Working Paper - GGAL
DRAFT - PRELIMINARY
engagement_id: ENG-2026-0123
workpaper_count: 45
`)
	f := ParseWorkpaper(body)
	if !f.HasDraftMarker {
		t.Fatal("DRAFT must flag")
	}
	if f.WorkpaperCount != 45 {
		t.Fatalf("workpapers=%d", f.WorkpaperCount)
	}
}

func TestParseConfirmationBank(t *testing.T) {
	body := []byte(`Bank Confirmation Responses
confirmation_count: 12
CONF-001,Banco Galicia,USD 500000
CONF-002,Banco Macro,ARS 5000000
CONF-003,BBVA,USD 250000
`)
	f := ParseConfirmationBank(body)
	if f.ConfirmationCount != 12 {
		t.Fatalf("count=%d want 12", f.ConfirmationCount)
	}
}

func TestParseInternalControlDeficiency(t *testing.T) {
	body := []byte(`ICDR Report
deficiency_count: 5
DEF-001,Segregation of duties failure,High
DEF-002,Access control deficiency,High
DEF-003,Backup not tested,Medium
RESERVADO
`)
	f := ParseInternalControlDeficiency(body)
	if f.DeficiencyCount != 5 {
		t.Fatalf("count=%d want 5", f.DeficiencyCount)
	}
	if !f.HasDraftMarker {
		t.Fatal("RESERVADO must flag draft")
	}
}

func TestParseAuditFeeSchedule(t *testing.T) {
	body := []byte(`Audit Fee Schedule
audit_fee: 100000000
non_audit_fee: 80000000
`)
	f := ParseAuditFeeSchedule(body)
	if f.AuditFeeARSMillions != 100 {
		t.Fatalf("audit fee=%d want 100", f.AuditFeeARSMillions)
	}
	if f.NonAuditFeeARSMillions != 80 {
		t.Fatalf("non-audit fee=%d want 80", f.NonAuditFeeARSMillions)
	}
}

func TestDetectAuditFirm(t *testing.T) {
	cases := map[string]AuditFirm{
		"PwC Argentina":          FirmPwCArgentina,
		"PricewaterhouseCoopers": FirmPwCArgentina,
		"Deloitte Argentina":     FirmDeloitteArgentina,
		"EY Argentina":           FirmEYArgentina,
		"Ernst & Young":          FirmEYArgentina,
		"KPMG Argentina":         FirmKPMGArgentina,
		"BDO Argentina":          FirmBDOArgentina,
		"Grant Thornton":         FirmGrantThorntonArgentina,
		"Crowe Argentina":        FirmCroweArgentina,
		"Baker Tilly":            FirmBakerTillyArgentina,
		"Estudio López y Asoc.":  FirmLocalMidTier,
		"unknown":                FirmUnknown,
	}
	for in, want := range cases {
		got := detectAuditFirm(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectClientClass(t *testing.T) {
	cases := map[string]ClientClass{
		"CNV listed company":     ClientCNVListedCompany,
		"fideicomiso financiero": ClientFideicomisoFinanciero,
		"ALYC broker dealer":     ClientALYCBrokerDealer,
		"insurance company":      ClientInsuranceCompany,
		"banco":                  ClientBank,
		"FCI mutual fund":        ClientFCIMutualFund,
		"PYME":                   ClientPYME,
		"cross-listed ADR":       ClientCrossListedUSIssuer,
		"random":                 ClientUnknown,
	}
	for in, want := range cases {
		got := detectClientClass(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectAuditPhase(t *testing.T) {
	cases := map[string]AuditPhase{
		"planning":          PhasePlanning,
		"interim":           PhaseInterim,
		"year-end":          PhaseYearEnd,
		"cierre":            PhaseYearEnd,
		"reporting":         PhaseReporting,
		"subsequent events": PhaseSubsequentEvents,
		"quality review":    PhaseQualityReview,
		"random":            PhaseUnknown,
	}
	for in, want := range cases {
		got := detectAuditPhase(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyEngagementRole(t *testing.T) {
	if got := classifyEngagementRole(Row{HasSOCRelianceReport: true}); got != RoleComplianceOfficer {
		t.Fatalf("soc -> compliance, got %q", got)
	}
	if got := classifyEngagementRole(Row{HasIndependenceBreach: true}); got != RoleComplianceOfficer {
		t.Fatalf("breach -> compliance, got %q", got)
	}
	if got := classifyEngagementRole(Row{HasAuditCommitteeMinutes: true, HasGoingConcernOpinion: true}); got != RoleQualityReviewer {
		t.Fatalf("ac+gc -> quality-reviewer, got %q", got)
	}
	if got := classifyEngagementRole(Row{HasEngagementLetter: true, HasAuditPlan: true}); got != RoleEngagementTeamLeader {
		t.Fatalf("eng+plan -> team-leader, got %q", got)
	}
	if got := classifyEngagementRole(Row{HasGoingConcernOpinion: true}); got != RolePartner {
		t.Fatalf("gc -> partner, got %q", got)
	}
	if got := classifyEngagementRole(Row{HasManagementLetter: true}); got != RolePartner {
		t.Fatalf("ml -> partner, got %q", got)
	}
	if got := classifyEngagementRole(Row{HasInternalControlAssessment: true}); got != RoleSeniorManager {
		t.Fatalf("ica -> senior-manager, got %q", got)
	}
	if got := classifyEngagementRole(Row{HasInternalControlDeficiency: true}); got != RoleSeniorManager {
		t.Fatalf("icdr -> senior-manager, got %q", got)
	}
	if got := classifyEngagementRole(Row{HasWorkpaper: true}); got != RoleSeniorAuditor {
		t.Fatalf("workpaper -> senior-auditor, got %q", got)
	}
	if got := classifyEngagementRole(Row{HasConfirmationBank: true}); got != RoleSeniorAuditor {
		t.Fatalf("confirm -> senior-auditor, got %q", got)
	}
	if got := classifyEngagementRole(Row{HasSubsequentEventsReview: true}); got != RoleStaffAuditor {
		t.Fatalf("se -> staff-auditor, got %q", got)
	}
	if got := classifyEngagementRole(Row{HasAuditCommitteeMinutes: true}); got != RoleQualityReviewer {
		t.Fatalf("ac alone -> quality-reviewer, got %q", got)
	}
	if got := classifyEngagementRole(Row{HasEngagementLetter: true}); got != RoleEngagementTeamLeader {
		t.Fatalf("engagement -> team-leader, got %q", got)
	}
	if got := classifyEngagementRole(Row{HasLetterRepresentations: true}); got != RoleManager {
		t.Fatalf("lor -> manager, got %q", got)
	}
	if got := classifyEngagementRole(Row{ArtifactKind: KindConfig}); got != RoleAPI {
		t.Fatalf("config -> api, got %q", got)
	}
	if got := classifyEngagementRole(Row{}); got != RoleUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	auditDir := filepath.Join(usersBase, "alice", "AppData", "Roaming",
		"PwC")
	must(t, os.MkdirAll(auditDir, 0o755))

	wpPath := filepath.Join(auditDir, "papeles_de_trabajo_GGAL_2026.pdf")
	must(t, os.WriteFile(wpPath, []byte(`Working Paper GGAL
DRAFT - PRELIMINARY
engagement_id: ENG-2026-0123
client_name: Grupo Galicia
audit_firm: PwC Argentina
client_class: CNV listed company
cliente_emisor_cuit: 30-71234567-8
auditor_cuil: 27-11111111-4
NYSE
`), 0o644))

	cbPath := filepath.Join(auditDir, "confirmation_bank_galicia.pdf")
	must(t, os.WriteFile(cbPath, []byte(`Bank Confirmation Responses
engagement_id: ENG-2026-0123
confirmation_count: 12
CONF-001,Banco Galicia,USD 500000
`), 0o644))

	gcPath := filepath.Join(auditDir, "going_concern_opinion.pdf")
	must(t, os.WriteFile(gcPath, []byte(`Going Concern Opinion
DRAFT
engagement_id: ENG-2026-0123
`), 0o644))

	feePath := filepath.Join(auditDir, "audit_fee_2026.csv")
	must(t, os.WriteFile(feePath, []byte(`Audit Fee Schedule
audit_fee: 100000000
non_audit_fee: 80000000
`), 0o644))

	must(t, os.WriteFile(filepath.Join(auditDir, "random.txt"),
		[]byte(`nope`), 0o644))

	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "PwC")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "workpaper_public.pdf"),
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
	if len(got) != 4 {
		t.Fatalf("want 4 (wp+cb+gc+fee), got %d: %+v", len(got), got)
	}

	var wp, cb, gc, fee Row
	for _, r := range got {
		switch r.FilePath {
		case wpPath:
			wp = r
		case cbPath:
			cb = r
		case gcPath:
			gc = r
		case feePath:
			fee = r
		}
	}

	if wp.ArtifactKind != KindWorkpaper {
		t.Fatalf("wp kind=%q", wp.ArtifactKind)
	}
	if !wp.HasWorkpaper {
		t.Fatalf("wp must flag: %+v", wp)
	}
	if !wp.HasDraftMarker {
		t.Fatalf("wp must flag draft: %+v", wp)
	}
	if !wp.HasCrossListedUSIssuer {
		t.Fatalf("wp must flag NYSE: %+v", wp)
	}
	if !wp.HasClienteEmisorCuit {
		t.Fatalf("wp must flag emisor cuit: %+v", wp)
	}
	if wp.AuditFirm != FirmPwCArgentina {
		t.Fatalf("wp firm=%q", wp.AuditFirm)
	}
	if !wp.IsPrePublicationFindingRisk {
		t.Fatalf("wp must flag pre-pub (draft + workpaper): %+v", wp)
	}

	if cb.ArtifactKind != KindConfirmationBank {
		t.Fatalf("cb kind=%q", cb.ArtifactKind)
	}
	if !cb.HasConfirmationBank {
		t.Fatalf("cb must flag: %+v", cb)
	}
	if cb.ConfirmationCount != 12 {
		t.Fatalf("cb count=%d", cb.ConfirmationCount)
	}
	if !cb.IsCounterpartyDisclosureRisk {
		t.Fatalf("cb must flag counterparty disclosure: %+v", cb)
	}
	if cb.EngagementRole != RoleSeniorAuditor {
		t.Fatalf("cb should classify as senior-auditor, got %q", cb.EngagementRole)
	}

	if gc.ArtifactKind != KindGoingConcernOpinion {
		t.Fatalf("gc kind=%q", gc.ArtifactKind)
	}
	if !gc.IsPrePublicationFindingRisk {
		t.Fatalf("gc must flag pre-pub (always): %+v", gc)
	}
	if gc.EngagementRole != RolePartner {
		t.Fatalf("gc should classify as partner, got %q", gc.EngagementRole)
	}

	if fee.ArtifactKind != KindAuditFeeSchedule {
		t.Fatalf("fee kind=%q", fee.ArtifactKind)
	}
	if !fee.HasIndependenceBreach {
		t.Fatalf("fee must flag breach (80%% non-audit): %+v", fee)
	}
	if fee.EngagementRole != RoleComplianceOfficer {
		t.Fatalf("fee should classify as compliance (breach), got %q", fee.EngagementRole)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-auditor")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "auditor_config.ini"),
		[]byte(`[Auditor]
auditor_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "AUDITOR_DIR" {
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
		installRoots: []string{"/nope-perito"},
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
		{FilePath: "/b", ArtifactKind: KindWorkpaper},
		{FilePath: "/a", ArtifactKind: KindConfirmationBank},
		{FilePath: "/a", ArtifactKind: KindWorkpaper},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindConfirmationBank {
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
