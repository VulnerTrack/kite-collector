package winargma

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindPitchDeck), "ma-pitch-deck"},
		{string(KindNDA), "ma-nda"},
		{string(KindInformationMemorandum), "ma-information-memorandum"},
		{string(KindDataroomManifest), "ma-dataroom-manifest"},
		{string(KindBidderRoster), "ma-bidder-roster"},
		{string(KindDCFModel), "ma-dcf-model"},
		{string(KindLBOModel), "ma-lbo-model"},
		{string(KindHechoRelevanteDraft), "ma-hecho-relevante-draft"},
		{string(FirmBancoGaliciaECM), "banco-galicia-ecm"},
		{string(FirmJPMorganArgentina), "jpmorgan-argentina"},
		{string(FirmMorganStanleyArgentina), "morgan-stanley-argentina"},
		{string(RoleAnalyst), "analyst"},
		{string(RoleManagingDirector), "managing-director"},
		{string(RoleDataRoomAdmin), "data-room-admin"},
		{string(MandateSellSide), "sell-side"},
		{string(MandateFairnessOpinion), "fairness-opinion"},
		{string(StagePitch), "pitch"},
		{string(StageExclusivity), "exclusivity"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"pitch_deck_project_tango.pptx",
		"nda_strategic_bidder_1.pdf",
		"information_memorandum_round1.pdf",
		"info_memo_v2.pdf",
		"dataroom_manifest.csv",
		"bidder_roster.xlsx",
		"process_letter_round2.pdf",
		"bid_evaluation_round2.xlsx",
		"dcf_model.xlsx",
		"lbo_model.xlsx",
		"merger_model.xlsx",
		"qofe_report.pdf",
		"spa_draft_v3.docx",
		"disclosure_schedules.xlsx",
		"closing_memo.pdf",
		"fairness_opinion_board.pdf",
		"synergy_analysis.xlsx",
		"antitrust_memo_cndc.pdf",
		"hecho_relevante_draft.pdf",
		"investment_banking_pipeline.xlsx",
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
		"pitch_deck_project_tango.pptx":     KindPitchDeck,
		"nda_strategic_bidder_1.pdf":        KindNDA,
		"information_memorandum_round1.pdf": KindInformationMemorandum,
		"info_memo_v2.pdf":                  KindInformationMemorandum,
		"dataroom_manifest.csv":             KindDataroomManifest,
		"bidder_roster.xlsx":                KindBidderRoster,
		"process_letter_round2.pdf":         KindProcessLetter,
		"bid_evaluation_round2.xlsx":        KindBidEvaluation,
		"dcf_model.xlsx":                    KindDCFModel,
		"lbo_model.xlsx":                    KindLBOModel,
		"merger_model.xlsx":                 KindMergerModel,
		"qofe_report.pdf":                   KindQofEReport,
		"spa_draft_v3.docx":                 KindSPADraft,
		"disclosure_schedules.xlsx":         KindDisclosureSchedules,
		"closing_memo.pdf":                  KindClosingMemo,
		"fairness_opinion_board.pdf":        KindFairnessOpinion,
		"synergy_analysis.xlsx":             KindSynergyAnalysis,
		"antitrust_memo_cndc.pdf":           KindAntitrustMemo,
		"hecho_relevante_draft.pdf":         KindHechoRelevanteDraft,
		"ma_deal_config.ini":                KindConfig,
		"credentials.json":                  KindCredentials,
		"ib_setup.msi":                      KindInstaller,
		"":                                  KindUnknown,
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
		{"target 30-71234567-8", "30", "5678"},
		// Individual prefix rejected.
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

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindPitchDeck, KindNDA, KindInformationMemorandum,
		KindDataroomManifest, KindBidderRoster,
		KindProcessLetter, KindBidEvaluation,
		KindDCFModel, KindLBOModel, KindMergerModel,
		KindQofEReport, KindSPADraft,
		KindDisclosureSchedules, KindClosingMemo,
		KindFairnessOpinion, KindSynergyAnalysis,
		KindAntitrustMemo, KindHechoRelevanteDraft,
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
		KindPitchDeck, KindInformationMemorandum,
		KindDataroomManifest, KindBidderRoster,
		KindBidEvaluation, KindSPADraft,
		KindDisclosureSchedules, KindClosingMemo,
		KindFairnessOpinion, KindHechoRelevanteDraft,
		KindAntitrustMemo,
	}
	for _, k := range yes {
		if !IsInsiderInformationKind(k) {
			t.Fatalf("expected insider kind: %q", k)
		}
	}
	no := []ArtifactKind{
		KindNDA, KindProcessLetter,
		KindDCFModel, KindLBOModel, KindMergerModel,
		KindQofEReport, KindSynergyAnalysis,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range no {
		if IsInsiderInformationKind(k) {
			t.Fatalf("expected NOT insider kind: %q", k)
		}
	}
}

func TestIsValuationIPKind(t *testing.T) {
	yes := []ArtifactKind{
		KindDCFModel, KindLBOModel,
		KindMergerModel, KindSynergyAnalysis,
	}
	for _, k := range yes {
		if !IsValuationIPKind(k) {
			t.Fatalf("expected IP kind: %q", k)
		}
	}
	no := []ArtifactKind{
		KindPitchDeck, KindNDA,
		KindInformationMemorandum, KindDataroomManifest,
		KindBidderRoster, KindProcessLetter,
		KindBidEvaluation, KindQofEReport,
		KindSPADraft, KindDisclosureSchedules,
		KindClosingMemo, KindFairnessOpinion,
		KindAntitrustMemo, KindHechoRelevanteDraft,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range no {
		if IsValuationIPKind(k) {
			t.Fatalf("expected NOT IP kind: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindPitchDeck,
		HasPasswordInConfig: true,
		TargetCuitPrefix:    "30",
		TargetCuitSuffix4:   "5678",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasTargetCuit {
		t.Fatal("target cuit must flag")
	}
	if !r.HasPitchDeck {
		t.Fatal("pitch deck kind must auto-flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + target = exposure")
	}
}

func TestAnnotateInsiderInformation(t *testing.T) {
	r := Row{
		ArtifactKind: KindPitchDeck,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsInsiderInformationRisk {
		t.Fatal("readable + pitch = insider info")
	}
}

func TestAnnotateHechoRelevanteDraft(t *testing.T) {
	r := Row{
		ArtifactKind: KindHechoRelevanteDraft,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasHechoRelevanteDraft {
		t.Fatal("HR draft kind must flag")
	}
	if !r.IsInsiderInformationRisk {
		t.Fatal("readable + HR draft = insider info")
	}
}

func TestAnnotatePreAnnouncementDraft(t *testing.T) {
	r := Row{
		ArtifactKind:            KindFairnessOpinion,
		HasPreAnnouncementDraft: true,
		FileMode:                0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsInsiderInformationRisk {
		t.Fatal("readable + draft = insider")
	}
}

func TestAnnotateValuationIP(t *testing.T) {
	r := Row{
		ArtifactKind: KindDCFModel,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsValuationIPRisk {
		t.Fatal("readable + DCF = valuation IP")
	}
	r2 := Row{
		ArtifactKind: KindMergerModel,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r2)
	if !r2.IsValuationIPRisk {
		t.Fatal("readable + merger model = valuation IP")
	}
}

func TestParsePitchDeck(t *testing.T) {
	body := []byte(`Pitch Deck - Project Tango
DRAFT - PRIVILEGED AND CONFIDENTIAL
deal_id: DEAL-2026-0123
project_name: Project Tango
advisor_firm: Cohen IB
mandate_type: sell-side
stage: pitch
target_cuit: 30-71234567-8
bidder_cuit: 30-99999999-1
NYSE
`)
	f := ParsePitchDeck(body)
	if f.DealID != "DEAL-2026-0123" {
		t.Fatalf("deal=%q", f.DealID)
	}
	if f.ProjectName != "Project Tango" {
		t.Fatalf("project=%q", f.ProjectName)
	}
	if f.AdvisorFirm != FirmCohenIB {
		t.Fatalf("firm=%q want cohen-ib", f.AdvisorFirm)
	}
	if f.MandateType != MandateSellSide {
		t.Fatalf("mandate=%q want sell-side", f.MandateType)
	}
	if f.DealStage != StagePitch {
		t.Fatalf("stage=%q want pitch", f.DealStage)
	}
	if !f.HasPreAnnouncementDraft {
		t.Fatal("DRAFT must flag pre-announcement")
	}
	if !f.HasPublicTarget {
		t.Fatal("NYSE must flag public target")
	}
	if f.TargetCuitRaw == "" {
		t.Fatal("target cuit must extract")
	}
	if f.BidderCuitRaw == "" {
		t.Fatal("bidder cuit must extract")
	}
}

func TestParseDataroomManifest(t *testing.T) {
	body := []byte(`Dataroom Manifest - Project Tango
deal_id: DEAL-2026-0123
dataroom_file_count: 245
DOC-001,Financial Statements 2025,5MB
DOC-002,Legal Agreements,12MB
DOC-003,Operational Reports,8MB
`)
	f := ParseDataroomManifest(body)
	if f.DataroomFileCount != 245 {
		t.Fatalf("file count=%d want 245", f.DataroomFileCount)
	}
}

func TestParseBidderRoster(t *testing.T) {
	body := []byte(`Bidder Roster - Project Tango
bidder_count: 15
BIDDER-001,30-71234567-8,Strategic Buyer Inc
BIDDER-002,30-99999999-1,Financial Sponsor LP
BIDDER-003,30-88888888-2,Industry Buyer
`)
	f := ParseBidderRoster(body)
	if f.BidderCount != 15 {
		t.Fatalf("bidder count=%d want 15", f.BidderCount)
	}
}

func TestParseDCFModel(t *testing.T) {
	body := []byte(`DCF Model - Project Tango
deal_id: DEAL-2026-0123
enterprise_value: 50000000000
`)
	f := ParseDCFModel(body)
	if f.EnterpriseValueARSMillions != 50_000 {
		t.Fatalf("EV=%d want 50k M ARS (50B)", f.EnterpriseValueARSMillions)
	}
}

func TestParseClosingMemo(t *testing.T) {
	body := []byte(`Closing Memo - Project Tango
deal_id: DEAL-2026-0123
enterprise_value: 50000000000
advisory_fee: 750000000
success_fee_bps: 125
`)
	f := ParseClosingMemo(body)
	if f.EnterpriseValueARSMillions != 50_000 {
		t.Fatalf("EV=%d", f.EnterpriseValueARSMillions)
	}
	if f.AdvisoryFeeARSMillions != 750 {
		t.Fatalf("fee=%d want 750", f.AdvisoryFeeARSMillions)
	}
	if f.SuccessFeeBPS != 125 {
		t.Fatalf("bps=%d", f.SuccessFeeBPS)
	}
}

func TestDetectAdvisorFirm(t *testing.T) {
	cases := map[string]AdvisorFirm{
		"Cohen IB":          FirmCohenIB,
		"Banco Galicia ECM": FirmBancoGaliciaECM,
		"BTG Pactual":       FirmBTGPactualArgentina,
		"Adcap Securities":  FirmAdcapSecuritiesIB,
		"Allaria Ledesma":   FirmAllariaLedesmaIB,
		"JPMorgan":          FirmJPMorganArgentina,
		"Morgan Stanley":    FirmMorganStanleyArgentina,
		"Citi":              FirmCitiArgentina,
		"Itaú BBA":          FirmItauBBAArgentina,
		"BBVA Argentina":    FirmBBVAArgentinaIB,
		"Santander Río":     FirmSantanderRioIB,
		"Boutique Advisory": FirmLocalBoutique,
		"unknown":           FirmUnknown,
	}
	for in, want := range cases {
		got := detectAdvisorFirm(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectMandateType(t *testing.T) {
	cases := map[string]MandateType{
		"sell-side":        MandateSellSide,
		"buy-side":         MandateBuySide,
		"fairness opinion": MandateFairnessOpinion,
		"defense":          MandateDefense,
		"divestiture":      MandateDivestiture,
		"spin-off":         MandateSpinOff,
		"capital raise":    MandateCapitalRaise,
		"restructuring":    MandateRestructuring,
		"random":           MandateUnknown,
	}
	for in, want := range cases {
		got := detectMandateType(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectDealStage(t *testing.T) {
	cases := map[string]DealStage{
		"origination":  StageOrigination,
		"pitch":        StagePitch,
		"exclusivity":  StageExclusivity,
		"execution":    StageExecution,
		"closing":      StageClosing,
		"post-closing": StagePostClosing,
		"random":       StageUnknown,
	}
	for in, want := range cases {
		got := detectDealStage(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyDealRole(t *testing.T) {
	if got := classifyDealRole(Row{HasHechoRelevanteDraft: true}); got != RoleComplianceOfficer {
		t.Fatalf("hr -> compliance, got %q", got)
	}
	if got := classifyDealRole(Row{HasAntitrustMemo: true}); got != RoleAntitrustCounsel {
		t.Fatalf("antitrust -> antitrust-counsel, got %q", got)
	}
	if got := classifyDealRole(Row{HasPitchDeck: true, HasInformationMemorandum: true}); got != RoleEngagementTeamLeader {
		t.Fatalf("pitch+im -> team-leader, got %q", got)
	}
	if got := classifyDealRole(Row{HasFairnessOpinion: true}); got != RoleManagingDirector {
		t.Fatalf("fairness -> md, got %q", got)
	}
	if got := classifyDealRole(Row{HasClosingMemo: true}); got != RoleManagingDirector {
		t.Fatalf("closing -> md, got %q", got)
	}
	if got := classifyDealRole(Row{HasSPADraft: true}); got != RoleDirector {
		t.Fatalf("spa -> director, got %q", got)
	}
	if got := classifyDealRole(Row{HasDCFModel: true}); got != RoleVP {
		t.Fatalf("dcf -> vp, got %q", got)
	}
	if got := classifyDealRole(Row{HasLBOModel: true}); got != RoleVP {
		t.Fatalf("lbo -> vp, got %q", got)
	}
	if got := classifyDealRole(Row{HasSynergyAnalysis: true}); got != RoleVP {
		t.Fatalf("synergy -> vp, got %q", got)
	}
	if got := classifyDealRole(Row{HasInformationMemorandum: true}); got != RoleAssociate {
		t.Fatalf("im -> associate, got %q", got)
	}
	if got := classifyDealRole(Row{HasBidderRoster: true}); got != RoleAssociate {
		t.Fatalf("bidder -> associate, got %q", got)
	}
	if got := classifyDealRole(Row{HasQofEReport: true}); got != RoleAnalyst {
		t.Fatalf("qofe -> analyst, got %q", got)
	}
	if got := classifyDealRole(Row{HasDataroomManifest: true}); got != RoleDataRoomAdmin {
		t.Fatalf("dr -> dr-admin, got %q", got)
	}
	if got := classifyDealRole(Row{HasPitchDeck: true}); got != RoleEngagementTeamLeader {
		t.Fatalf("pitch -> team-leader, got %q", got)
	}
	if got := classifyDealRole(Row{HasNDA: true}); got != RoleOperations {
		t.Fatalf("nda -> operations, got %q", got)
	}
	if got := classifyDealRole(Row{ArtifactKind: KindConfig}); got != RoleAPI {
		t.Fatalf("config -> api, got %q", got)
	}
	if got := classifyDealRole(Row{}); got != RoleUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	maDir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "IB",
		"Project Tango")
	must(t, os.MkdirAll(maDir, 0o755))

	pdPath := filepath.Join(maDir, "pitch_deck_tango.pptx")
	must(t, os.WriteFile(pdPath, []byte(`Pitch Deck - Project Tango
DRAFT - PRIVILEGED AND CONFIDENTIAL
deal_id: DEAL-2026-0123
project_name: Project Tango
advisor_firm: Cohen IB
mandate_type: sell-side
stage: pitch
target_cuit: 30-71234567-8
NYSE
`), 0o644))

	drPath := filepath.Join(maDir, "dataroom_manifest.csv")
	must(t, os.WriteFile(drPath, []byte(`Dataroom Manifest
deal_id: DEAL-2026-0123
dataroom_file_count: 245
DOC-001,Financial Statements 2025,5MB
`), 0o644))

	dcfPath := filepath.Join(maDir, "dcf_model.xlsx")
	must(t, os.WriteFile(dcfPath, []byte(`DCF Model
deal_id: DEAL-2026-0123
enterprise_value: 50000000000
`), 0o644))

	hrPath := filepath.Join(maDir, "hecho_relevante_draft.pdf")
	must(t, os.WriteFile(hrPath, []byte(`Hecho Relevante - DRAFT
deal_id: DEAL-2026-0123
`), 0o644))

	must(t, os.WriteFile(filepath.Join(maDir, "random.txt"),
		[]byte(`nope`), 0o644))

	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "IB")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "pitch_deck.pptx"),
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
		t.Fatalf("want 4 (pd+dr+dcf+hr), got %d: %+v", len(got), got)
	}

	var pd, dr, dcf, hr Row
	for _, r := range got {
		switch r.FilePath {
		case pdPath:
			pd = r
		case drPath:
			dr = r
		case dcfPath:
			dcf = r
		case hrPath:
			hr = r
		}
	}

	if pd.ArtifactKind != KindPitchDeck {
		t.Fatalf("pd kind=%q", pd.ArtifactKind)
	}
	if !pd.HasPitchDeck {
		t.Fatalf("pd must flag: %+v", pd)
	}
	if !pd.HasPreAnnouncementDraft {
		t.Fatalf("pd must flag draft: %+v", pd)
	}
	if !pd.HasPublicTarget {
		t.Fatalf("pd must flag NYSE: %+v", pd)
	}
	if !pd.HasTargetCuit {
		t.Fatalf("pd must flag target cuit: %+v", pd)
	}
	if pd.AdvisorFirm != FirmCohenIB {
		t.Fatalf("pd firm=%q", pd.AdvisorFirm)
	}
	if !pd.IsInsiderInformationRisk {
		t.Fatalf("pd must flag insider (readable + pitch + draft): %+v", pd)
	}

	if dr.ArtifactKind != KindDataroomManifest {
		t.Fatalf("dr kind=%q", dr.ArtifactKind)
	}
	if !dr.HasDataroomManifest {
		t.Fatalf("dr must flag: %+v", dr)
	}
	if dr.DataroomFileCount != 245 {
		t.Fatalf("dr file count=%d", dr.DataroomFileCount)
	}
	if dr.DealRole != RoleDataRoomAdmin {
		t.Fatalf("dr should classify as dr-admin, got %q", dr.DealRole)
	}

	if dcf.ArtifactKind != KindDCFModel {
		t.Fatalf("dcf kind=%q", dcf.ArtifactKind)
	}
	if !dcf.HasDCFModel {
		t.Fatalf("dcf must flag: %+v", dcf)
	}
	if dcf.EnterpriseValueARSMillions != 50_000 {
		t.Fatalf("dcf EV=%d", dcf.EnterpriseValueARSMillions)
	}
	if !dcf.IsValuationIPRisk {
		t.Fatalf("dcf must flag valuation IP: %+v", dcf)
	}
	if dcf.DealRole != RoleVP {
		t.Fatalf("dcf should classify as VP, got %q", dcf.DealRole)
	}

	if hr.ArtifactKind != KindHechoRelevanteDraft {
		t.Fatalf("hr kind=%q", hr.ArtifactKind)
	}
	if !hr.HasHechoRelevanteDraft {
		t.Fatalf("hr must flag: %+v", hr)
	}
	if !hr.IsInsiderInformationRisk {
		t.Fatalf("hr must flag insider: %+v", hr)
	}
	if hr.DealRole != RoleComplianceOfficer {
		t.Fatalf("hr should classify as compliance, got %q", hr.DealRole)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-ma")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "ma_deal_config.ini"),
		[]byte(`[MA]
ib_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "MA_DIR" {
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
		installRoots: []string{"/nope-ma"},
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
		{FilePath: "/b", ArtifactKind: KindPitchDeck},
		{FilePath: "/a", ArtifactKind: KindDataroomManifest},
		{FilePath: "/a", ArtifactKind: KindPitchDeck},
	}
	SortRows(rs)
	// Sort by file path first, then by artifact kind alphabetically:
	// "ma-dataroom-manifest" < "ma-pitch-deck".
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindDataroomManifest {
		t.Fatalf("sort drift: %+v", rs)
	}
	if rs[1].FilePath != "/a" || rs[1].ArtifactKind != KindPitchDeck {
		t.Fatalf("sort drift: %+v", rs)
	}
	if rs[2].FilePath != "/b" {
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
