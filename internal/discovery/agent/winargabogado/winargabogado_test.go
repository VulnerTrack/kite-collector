package winargabogado

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindLegalOpinion), "abg-legal-opinion"},
		{string(KindTrueSaleOpinion), "abg-true-sale-opinion"},
		{string(Kind10b5Letter), "abg-10b5-letter"},
		{string(KindEngagementLetter), "abg-engagement-letter"},
		{string(KindBillableHours), "abg-billable-hours"},
		{string(KindRestructuringPlan), "abg-restructuring-plan"},
		{string(KindPrivilegedCommunication), "abg-privileged-communication"},
		{string(FirmMarvalOFarrellMairal), "marval-ofarrell-mairal"},
		{string(FirmBruchouFunesDeRioja), "bruchou-funes-de-rioja"},
		{string(FirmPAGBAM), "pagbam"},
		{string(FirmAllendeBrea), "allende-brea"},
		{string(FirmBeccarVarela), "beccar-varela"},
		{string(RolePartner), "partner"},
		{string(RoleSeniorAssociate), "senior-associate"},
		{string(RoleOfCounsel), "of-counsel"},
		{string(MatterSecuritizationFF), "securitization-ff"},
		{string(MatterRestructuring), "restructuring"},
		{string(MatterClassAction), "class-action"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"legal_opinion_GGAL.pdf",
		"true_sale_opinion_ff_naranja.pdf",
		"10b5_letter_YPF_2026.pdf",
		"no_action_letter.pdf",
		"engagement_letter_2026.pdf",
		"billable_hours_202606.csv",
		"prospecto_legal_review_GGAL.pdf",
		"covenant_compliance_memo.pdf",
		"bondholder_consent.pdf",
		"restructuring_plan_apr.pdf",
		"concurso_preventivo_filing.pdf",
		"enforcement_defense_cnv.pdf",
		"privileged_memo_strategy.eml",
		"class_action_defense_2026.pdf",
		"marval_config.ini",
		"bruchou_billable_2026.csv",
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
		"legal_opinion_GGAL.pdf":           KindLegalOpinion,
		"true_sale_opinion_ff_naranja.pdf": KindTrueSaleOpinion,
		"10b5_letter_YPF_2026.pdf":         Kind10b5Letter,
		"no_action_letter.pdf":             KindNoActionLetter,
		"engagement_letter_2026.pdf":       KindEngagementLetter,
		"billable_hours_202606.csv":        KindBillableHours,
		"prospecto_legal_review_GGAL.pdf":  KindProspectoLegalReview,
		"covenant_compliance_memo.pdf":     KindCovenantComplianceMemo,
		"bondholder_consent.pdf":           KindBondholderConsent,
		"restructuring_plan_apr.pdf":       KindRestructuringPlan,
		"concurso_preventivo_filing.pdf":   KindRestructuringPlan,
		"enforcement_defense_cnv.pdf":      KindEnforcementDefense,
		"privileged_memo_strategy.eml":     KindPrivilegedCommunication,
		"strategy.msg":                     KindPrivilegedCommunication,
		"class_action_defense_2026.pdf":    KindClassActionDefense,
		"legal_config.ini":                 KindConfig,
		"credentials.json":                 KindCredentials,
		"legal_setup.msi":                  KindInstaller,
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
		{"abogado 27-11111111-4", "27", "1114"},
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

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindLegalOpinion, KindTrueSaleOpinion,
		Kind10b5Letter, KindNoActionLetter,
		KindEngagementLetter, KindBillableHours,
		KindProspectoLegalReview,
		KindCovenantComplianceMemo, KindBondholderConsent,
		KindRestructuringPlan, KindEnforcementDefense,
		KindPrivilegedCommunication, KindClassActionDefense,
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

func TestIsInsiderInformationKind(t *testing.T) {
	yes := []ArtifactKind{
		KindTrueSaleOpinion, Kind10b5Letter,
		KindBondholderConsent, KindRestructuringPlan,
		KindEnforcementDefense, KindCovenantComplianceMemo,
		KindProspectoLegalReview,
	}
	for _, k := range yes {
		if !IsInsiderInformationKind(k) {
			t.Fatalf("expected insider kind: %q", k)
		}
	}
	no := []ArtifactKind{
		KindLegalOpinion, KindNoActionLetter,
		KindEngagementLetter, KindBillableHours,
		KindPrivilegedCommunication, KindClassActionDefense,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range no {
		if IsInsiderInformationKind(k) {
			t.Fatalf("expected NOT insider kind: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:             KindLegalOpinion,
		HasPasswordInConfig:      true,
		ClienteEmisorCuitPrefix:  "30",
		ClienteEmisorCuitSuffix4: "5678",
		FileMode:                 0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteEmisorCuit {
		t.Fatal("emisor cuit must flag")
	}
	if !r.HasLegalOpinion {
		t.Fatal("legal opinion kind must auto-flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + emisor = exposure")
	}
}

func TestAnnotatePrivilegedMarker(t *testing.T) {
	r := Row{
		ArtifactKind:        KindLegalOpinion,
		HasPrivilegedMarker: true,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsPrivilegedInformationRisk {
		t.Fatal("readable + privileged marker = privileged info risk")
	}
}

func TestAnnotatePrivilegedCommunication(t *testing.T) {
	r := Row{
		ArtifactKind: KindPrivilegedCommunication,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasPrivilegedCommunication {
		t.Fatal("priv comm kind must flag")
	}
	if !r.IsPrivilegedInformationRisk {
		t.Fatal("readable + priv comm = privileged info risk")
	}
}

func TestAnnotateCovenantBreachInsider(t *testing.T) {
	r := Row{
		ArtifactKind:      KindCovenantComplianceMemo,
		HasCovenantBreach: true,
		FileMode:          0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasCovenantBreach {
		t.Fatal("breach must flag")
	}
	if !r.IsInsiderInformationRisk {
		t.Fatal("readable + breach = insider info")
	}
}

func TestAnnotateRestructuringAlwaysInsider(t *testing.T) {
	r := Row{
		ArtifactKind: KindRestructuringPlan,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsInsiderInformationRisk {
		t.Fatal("readable + restructuring = insider info (always)")
	}
}

func TestAnnotateBondholderConsentInsider(t *testing.T) {
	r := Row{
		ArtifactKind: KindBondholderConsent,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsInsiderInformationRisk {
		t.Fatal("readable + bondholder consent = insider info")
	}
}

func TestAnnotateEnforcementDefenseInsider(t *testing.T) {
	r := Row{
		ArtifactKind: KindEnforcementDefense,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsInsiderInformationRisk {
		t.Fatal("readable + enforcement = insider info")
	}
}

func TestAnnotateDraft10b5Insider(t *testing.T) {
	r := Row{
		ArtifactKind:           Kind10b5Letter,
		HasPrePublicationDraft: true,
		FileMode:               0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsInsiderInformationRisk {
		t.Fatal("readable + draft + 10b5 = insider info")
	}
}

func TestParseLegalOpinion(t *testing.T) {
	body := []byte(`Legal Opinion - GGAL Securities Issuance
ATTORNEY-CLIENT PRIVILEGED AND CONFIDENTIAL
matter_id: MAT-2026-0123
matter_name: GGAL Bond Issuance 2026
law_firm: Marval O'Farrell Mairal
matter_class: capital markets issuance
bar_number: T 123 F 456
cliente_emisor_cuit: 30-71234567-8
lawyer_cuil: 27-11111111-4
PCAOB
`)
	f := ParseLegalOpinion(body)
	if f.MatterID != "MAT-2026-0123" {
		t.Fatalf("matter=%q", f.MatterID)
	}
	if f.LawFirm != FirmMarvalOFarrellMairal {
		t.Fatalf("firm=%q want marval", f.LawFirm)
	}
	if f.MatterClass != MatterCapitalMarketsIssuance {
		t.Fatalf("class=%q want capital-markets-issuance", f.MatterClass)
	}
	if f.BarNumber == "" {
		t.Fatal("bar number must extract")
	}
	if !f.HasPrivilegedMarker {
		t.Fatal("ATTORNEY-CLIENT must flag privileged")
	}
	if !f.HasCrossBorderMatter {
		t.Fatal("PCAOB must flag cross-border")
	}
	if f.ClienteEmisorCuitRaw == "" {
		t.Fatal("emisor cuit must extract")
	}
	if f.LawyerCuilRaw == "" {
		t.Fatal("lawyer cuil must extract")
	}
}

func TestParseEngagementLetter(t *testing.T) {
	body := []byte(`Engagement Letter - 2026
matter_id: MAT-2026-0123
law_firm: Bruchou & Funes de Rioja
matter_class: M&A transactional
hourly_rate: 750000
retainer: 50000000
`)
	f := ParseEngagementLetter(body)
	if f.LawFirm != FirmBruchouFunesDeRioja {
		t.Fatalf("firm=%q", f.LawFirm)
	}
	if f.MatterClass != MatterMATransactional {
		t.Fatalf("class=%q", f.MatterClass)
	}
	if f.HourlyRateARS != 750000 {
		t.Fatalf("rate=%d", f.HourlyRateARS)
	}
	if f.RetainerARSMillions != 50 {
		t.Fatalf("retainer=%d want 50 M", f.RetainerARSMillions)
	}
}

func TestParseBillableHours(t *testing.T) {
	body := []byte(`Billable Hours - 202606
billable_hours: 245
15/06/2026,JD Partner,2.5,Drafting opinion
16/06/2026,JD Partner,3.0,Client call
17/06/2026,XY Associate,4.0,Document review
`)
	f := ParseBillableHours(body)
	if f.BillableHoursCount != 245 {
		t.Fatalf("hours=%d", f.BillableHoursCount)
	}
}

func TestParseCovenantWithBreach(t *testing.T) {
	body := []byte(`Covenant Compliance Memo - GGAL
matter_id: MAT-2026-0123
EVENT OF DEFAULT detected
The 4x leverage covenant has been breached.
CROSS-DEFAULT trigger likely.
`)
	f := ParseCovenantComplianceMemo(body)
	if !f.HasCovenantBreach {
		t.Fatal("EVENT OF DEFAULT must flag breach")
	}
}

func TestParseRestructuringPlan(t *testing.T) {
	body := []byte(`Restructuring Plan - APR
matter_id: MAT-2026-0124
matter_class: restructuring
law_firm: PAGBAM
PRIVILEGED AND CONFIDENTIAL
DRAFT
`)
	f := ParseRestructuringPlan(body)
	if f.LawFirm != FirmPAGBAM {
		t.Fatalf("firm=%q", f.LawFirm)
	}
	if f.MatterClass != MatterRestructuring {
		t.Fatalf("class=%q", f.MatterClass)
	}
	if !f.HasPrivilegedMarker {
		t.Fatal("PRIVILEGED must flag")
	}
	if !f.HasPrePublicationDraft {
		t.Fatal("DRAFT must flag")
	}
}

func TestParse10b5LetterAlwaysCrossBorder(t *testing.T) {
	body := []byte(`SEC Rule 10b-5 Letter
matter_id: MAT-2026-0125
`)
	f := Parse10b5Letter(body)
	if !f.HasCrossBorderMatter {
		t.Fatal("10b-5 must always flag cross-border")
	}
}

func TestDetectLawFirm(t *testing.T) {
	cases := map[string]LawFirm{
		"Marval O'Farrell Mairal":     FirmMarvalOFarrellMairal,
		"Bruchou & Funes de Rioja":    FirmBruchouFunesDeRioja,
		"PAGBAM":                      FirmPAGBAM,
		"Pérez Alati Grondona":        FirmPAGBAM,
		"Allende & Brea":              FirmAllendeBrea,
		"Beccar Varela":               FirmBeccarVarela,
		"Tanoira Cassagne":            FirmTanoiraCassagne,
		"Mitrani Caballero":           FirmMitraniCaballeroRuizMoreno,
		"Cabanellas Etchebarne Kelly": FirmCabanellasEtchebarneKelly,
		"Estudio Pereyra Sentenac":    FirmEstudioPereyraSentenac,
		"Solo Practice":               FirmSoloPractitioner,
		"Estudio Local":               FirmLocalMidTier,
		"unknown":                     FirmUnknown,
	}
	for in, want := range cases {
		got := detectLawFirm(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectMatterClass(t *testing.T) {
	cases := map[string]MatterClass{
		"M&A":                 MatterMATransactional,
		"capital markets":     MatterCapitalMarketsIssuance,
		"securitization":      MatterSecuritizationFF,
		"true sale":           MatterSecuritizationFF,
		"restructuring":       MatterRestructuring,
		"concurso preventivo": MatterRestructuring,
		"enforcement":         MatterEnforcementDefense,
		"sanción":             MatterEnforcementDefense,
		"class action":        MatterClassAction,
		"tax advisory":        MatterTaxAdvisory,
		"cross border":        MatterCrossBorder,
		"corporate":           MatterGeneralCorporate,
		"random":              MatterUnknown,
	}
	for in, want := range cases {
		got := detectMatterClass(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyLegalRole(t *testing.T) {
	if got := classifyLegalRole(Row{HasEnforcementDefense: true, HasCrossBorderMatter: true}); got != RoleComplianceOfficer {
		t.Fatalf("enf+cb -> compliance, got %q", got)
	}
	if got := classifyLegalRole(Row{HasLegalOpinion: true, HasEngagementLetter: true}); got != RolePartner {
		t.Fatalf("op+eng -> partner, got %q", got)
	}
	if got := classifyLegalRole(Row{HasTrueSaleOpinion: true}); got != RoleSeniorAssociate {
		t.Fatalf("true sale -> senior-assoc, got %q", got)
	}
	if got := classifyLegalRole(Row{Has10b5Letter: true}); got != RoleSeniorAssociate {
		t.Fatalf("10b5 -> senior-assoc, got %q", got)
	}
	if got := classifyLegalRole(Row{HasCovenantComplianceMemo: true}); got != RoleAssociate {
		t.Fatalf("covenant -> assoc, got %q", got)
	}
	if got := classifyLegalRole(Row{HasRestructuringPlan: true}); got != RoleOfCounsel {
		t.Fatalf("restructuring -> of-counsel, got %q", got)
	}
	if got := classifyLegalRole(Row{HasNoActionLetter: true}); got != RoleKnowledgeManagement {
		t.Fatalf("no-action -> km, got %q", got)
	}
	if got := classifyLegalRole(Row{HasBillableHours: true}); got != RoleBillingClerk {
		t.Fatalf("billable -> billing, got %q", got)
	}
	if got := classifyLegalRole(Row{HasProspectoLegalReview: true}); got != RoleParalegal {
		t.Fatalf("prospecto -> paralegal, got %q", got)
	}
	if got := classifyLegalRole(Row{HasClassActionDefense: true}); got != RoleParalegal {
		t.Fatalf("class action -> paralegal, got %q", got)
	}
	if got := classifyLegalRole(Row{HasLegalOpinion: true}); got != RolePartner {
		t.Fatalf("opinion -> partner, got %q", got)
	}
	if got := classifyLegalRole(Row{HasEngagementLetter: true}); got != RolePartner {
		t.Fatalf("engagement -> partner, got %q", got)
	}
	if got := classifyLegalRole(Row{HasPrivilegedCommunication: true}); got != RoleAssociate {
		t.Fatalf("priv comm -> assoc, got %q", got)
	}
	if got := classifyLegalRole(Row{HasEnforcementDefense: true}); got != RoleComplianceOfficer {
		t.Fatalf("enf alone -> compliance, got %q", got)
	}
	if got := classifyLegalRole(Row{ArtifactKind: KindConfig}); got != RoleAPI {
		t.Fatalf("config -> api, got %q", got)
	}
	if got := classifyLegalRole(Row{}); got != RoleUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	legalDir := filepath.Join(usersBase, "alice", "AppData", "Roaming",
		"LegalSuite")
	must(t, os.MkdirAll(legalDir, 0o755))

	opPath := filepath.Join(legalDir, "legal_opinion_GGAL.pdf")
	must(t, os.WriteFile(opPath, []byte(`Legal Opinion - GGAL
ATTORNEY-CLIENT PRIVILEGED AND CONFIDENTIAL
matter_id: MAT-2026-0123
law_firm: Marval O'Farrell Mairal
matter_class: capital markets
cliente_emisor_cuit: 30-71234567-8
`), 0o644))

	bhPath := filepath.Join(legalDir, "billable_hours_202606.csv")
	must(t, os.WriteFile(bhPath, []byte(`Billable Hours
billable_hours: 245
15/06/2026,Partner,2.5,Drafting
`), 0o644))

	cmPath := filepath.Join(legalDir, "covenant_compliance_memo.pdf")
	must(t, os.WriteFile(cmPath, []byte(`Covenant Memo - GGAL
matter_id: MAT-2026-0123
EVENT OF DEFAULT
`), 0o644))

	rpPath := filepath.Join(legalDir, "restructuring_plan_apr.pdf")
	must(t, os.WriteFile(rpPath, []byte(`Restructuring Plan APR
matter_id: MAT-2026-0124
DRAFT
PRIVILEGED
`), 0o644))

	must(t, os.WriteFile(filepath.Join(legalDir, "random.txt"),
		[]byte(`nope`), 0o644))

	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming",
		"LegalSuite")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "legal_opinion.pdf"),
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
		t.Fatalf("want 4 (op+bh+cm+rp), got %d: %+v", len(got), got)
	}

	var op, bh, cm, rp Row
	for _, r := range got {
		switch r.FilePath {
		case opPath:
			op = r
		case bhPath:
			bh = r
		case cmPath:
			cm = r
		case rpPath:
			rp = r
		}
	}

	if op.ArtifactKind != KindLegalOpinion {
		t.Fatalf("op kind=%q", op.ArtifactKind)
	}
	if !op.HasLegalOpinion {
		t.Fatalf("op must flag: %+v", op)
	}
	if !op.HasPrivilegedMarker {
		t.Fatalf("op must flag ATTORNEY-CLIENT: %+v", op)
	}
	if !op.HasClienteEmisorCuit {
		t.Fatalf("op must flag emisor cuit: %+v", op)
	}
	if op.LawFirm != FirmMarvalOFarrellMairal {
		t.Fatalf("op firm=%q", op.LawFirm)
	}
	if !op.IsPrivilegedInformationRisk {
		t.Fatalf("op must flag privileged info risk: %+v", op)
	}

	if bh.ArtifactKind != KindBillableHours {
		t.Fatalf("bh kind=%q", bh.ArtifactKind)
	}
	if !bh.HasBillableHours {
		t.Fatalf("bh must flag: %+v", bh)
	}
	if bh.BillableHoursCount != 245 {
		t.Fatalf("bh count=%d", bh.BillableHoursCount)
	}
	if bh.LegalRole != RoleBillingClerk {
		t.Fatalf("bh should classify as billing-clerk, got %q", bh.LegalRole)
	}

	if cm.ArtifactKind != KindCovenantComplianceMemo {
		t.Fatalf("cm kind=%q", cm.ArtifactKind)
	}
	if !cm.HasCovenantBreach {
		t.Fatalf("cm must flag breach: %+v", cm)
	}
	if !cm.IsInsiderInformationRisk {
		t.Fatalf("cm must flag insider info (breach): %+v", cm)
	}
	if cm.LegalRole != RoleAssociate {
		t.Fatalf("cm should classify as associate, got %q", cm.LegalRole)
	}

	if rp.ArtifactKind != KindRestructuringPlan {
		t.Fatalf("rp kind=%q", rp.ArtifactKind)
	}
	if !rp.HasRestructuringPlan {
		t.Fatalf("rp must flag: %+v", rp)
	}
	if !rp.HasPrivilegedMarker {
		t.Fatalf("rp must flag privileged: %+v", rp)
	}
	if !rp.HasPrePublicationDraft {
		t.Fatalf("rp must flag draft: %+v", rp)
	}
	if !rp.IsInsiderInformationRisk {
		t.Fatalf("rp must flag insider info (restructuring): %+v", rp)
	}
	if rp.LegalRole != RoleOfCounsel {
		t.Fatalf("rp should classify as of-counsel, got %q", rp.LegalRole)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-legal")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "legal_config.ini"),
		[]byte(`[Legal]
legal_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "ABOGADO_DIR" {
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
		installRoots: []string{"/nope-legal"},
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
		{FilePath: "/b", ArtifactKind: KindLegalOpinion},
		{FilePath: "/a", ArtifactKind: KindRestructuringPlan},
		{FilePath: "/a", ArtifactKind: KindLegalOpinion},
	}
	SortRows(rs)
	// "abg-legal-opinion" < "abg-restructuring-plan".
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindLegalOpinion {
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
