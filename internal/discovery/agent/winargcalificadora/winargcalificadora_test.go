package winargcalificadora

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindRatingLetter), "cal-rating-letter"},
		{string(KindMethodologyDoc), "cal-methodology-doc"},
		{string(KindCommitteeMinutes), "cal-committee-minutes"},
		{string(KindWatchlist), "cal-watchlist"},
		{string(KindInternalCreditModel), "cal-internal-credit-model"},
		{string(KindDissentingOpinion), "cal-dissenting-opinion"},
		{string(KindIssuerRoster), "cal-issuer-roster"},
		{string(CalFIXSCRArgentina), "fix-scr-argentina"},
		{string(CalMoodysLocalArgentina), "moodys-local-argentina"},
		{string(CalEvaluadoraLatinoamericana), "evaluadora-latinoamericana"},
		{string(RoleLeadAnalyst), "lead-analyst"},
		{string(RoleCommitteeChair), "committee-chair"},
		{string(RoleMethodologyOfficer), "methodology-officer"},
		{string(WatchPositive), "positive"},
		{string(WatchDeveloping), "developing"},
		{string(IssuerSovereign), "sovereign"},
		{string(IssuerFideicomisoFinanciero), "fideicomiso-financiero"},
		{string(RatingAAA), "aaa"},
		{string(RatingWithdrawn), "withdrawn"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"calificacion_GGAL_2026.pdf",
		"rating_AL30_202606.pdf",
		"metodologia_corporate_bond_v2.pdf",
		"comite_calificacion_15.pdf",
		"monitoreo_GGAL_202606.pdf",
		"watchlist_202606.json",
		"conflicto_interes_GGAL.pdf",
		"honorarios_2026.csv",
		"modelo_pd_corporate.xlsx",
		"modelo_lgd_fideicomiso.xlsx",
		"opinion_disidente_GGAL_2026.pdf",
		"cliente_emisor_roster.json",
		"issuer_roster_2026.csv",
		"cnv_filing_202606.xml",
		"soc1_2026.pdf",
		"fix_scr_config.ini",
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
		"calificacion_GGAL_2026.pdf":        KindRatingLetter,
		"rating_AL30_202606.pdf":            KindRatingLetter,
		"metodologia_corporate_bond_v2.pdf": KindMethodologyDoc,
		"comite_calificacion_15.pdf":        KindCommitteeMinutes,
		"committee_minutes_15.pdf":          KindCommitteeMinutes,
		"monitoreo_GGAL_202606.pdf":         KindMonitoringReport,
		"watchlist_202606.json":             KindWatchlist,
		"conflicto_interes_GGAL.pdf":        KindConflictOfInterestDoc,
		"honorarios_2026.csv":               KindFeeSchedule,
		"modelo_pd_corporate.xlsx":          KindInternalCreditModel,
		"opinion_disidente_GGAL_2026.pdf":   KindDissentingOpinion,
		"cliente_emisor_roster.json":        KindIssuerRoster,
		"issuer_roster_2026.csv":            KindIssuerRoster,
		"cnv_filing_202606.xml":             KindCNVFiling,
		"soc1_2026.pdf":                     KindSOCReport,
		"calificadora_config.ini":           KindConfig,
		"credentials.json":                  KindCredentials,
		"calificadora_setup.msi":            KindInstaller,
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
		{"emisor 30-71234567-8", "30", "5678"},
		// Individual prefix 27 rejected.
		{"persona 27-11111111-4", "", ""},
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
		{"analista 27-11111111-4", "27", "1114"},
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
		KindRatingLetter, KindMethodologyDoc,
		KindCommitteeMinutes, KindMonitoringReport,
		KindWatchlist, KindConflictOfInterestDoc,
		KindFeeSchedule, KindInternalCreditModel,
		KindDissentingOpinion, KindIssuerRoster,
		KindCNVFiling, KindSOCReport,
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

func TestIsMarketMovingKind(t *testing.T) {
	yes := []ArtifactKind{
		KindRatingLetter, KindCommitteeMinutes,
		KindWatchlist, KindDissentingOpinion,
	}
	for _, k := range yes {
		if !IsMarketMovingKind(k) {
			t.Fatalf("expected market-moving kind: %q", k)
		}
	}
	no := []ArtifactKind{
		KindMethodologyDoc, KindMonitoringReport,
		KindConflictOfInterestDoc, KindFeeSchedule,
		KindInternalCreditModel, KindIssuerRoster,
		KindCNVFiling, KindSOCReport,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range no {
		if IsMarketMovingKind(k) {
			t.Fatalf("expected NOT market-moving kind: %q", k)
		}
	}
}

func TestIsIntellectualPropertyKind(t *testing.T) {
	yes := []ArtifactKind{KindMethodologyDoc, KindInternalCreditModel}
	for _, k := range yes {
		if !IsIntellectualPropertyKind(k) {
			t.Fatalf("expected IP kind: %q", k)
		}
	}
	no := []ArtifactKind{
		KindRatingLetter, KindCommitteeMinutes,
		KindMonitoringReport, KindWatchlist,
		KindConflictOfInterestDoc, KindFeeSchedule,
		KindDissentingOpinion, KindIssuerRoster,
		KindCNVFiling, KindSOCReport,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range no {
		if IsIntellectualPropertyKind(k) {
			t.Fatalf("expected NOT IP kind: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:             KindRatingLetter,
		HasPasswordInConfig:      true,
		ClienteEmisorCuitPrefix:  "30",
		ClienteEmisorCuitSuffix4: "5678",
		FileMode:                 0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteEmisorCuit {
		t.Fatal("emisor cuit must flag")
	}
	if !r.HasRatingLetter {
		t.Fatal("rating letter kind must auto-flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + emisor = exposure")
	}
}

func TestAnnotateMarketMovingInfo(t *testing.T) {
	r := Row{
		ArtifactKind: KindRatingLetter,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsMarketMovingInfoRisk {
		t.Fatal("readable + rating letter = market-moving")
	}
}

func TestAnnotatePendingWatchAction(t *testing.T) {
	r := Row{
		ArtifactKind: KindWatchlist,
		WatchStatus:  WatchNegative,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasPendingWatchAction {
		t.Fatal("watch status != stable must flag pending")
	}
	if !r.IsMarketMovingInfoRisk {
		t.Fatal("readable + pending watch = market-moving")
	}
}

func TestAnnotateStableWatchNoPending(t *testing.T) {
	r := Row{
		ArtifactKind: KindWatchlist,
		WatchStatus:  WatchStable,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if r.HasPendingWatchAction {
		t.Fatal("watch stable must NOT flag pending")
	}
}

func TestAnnotateCommitteeSplit(t *testing.T) {
	r := Row{
		ArtifactKind:           KindCommitteeMinutes,
		DissentingOpinionCount: 2,
		FileMode:               0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasCommitteeSplit {
		t.Fatal("dissent count > 0 must flag split")
	}
	if !r.IsMarketMovingInfoRisk {
		t.Fatal("readable + committee split = market-moving")
	}
}

func TestAnnotateIntellectualProperty(t *testing.T) {
	r := Row{
		ArtifactKind: KindMethodologyDoc,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsIntellectualPropertyRisk {
		t.Fatal("readable + methodology = IP risk")
	}
	r2 := Row{
		ArtifactKind: KindInternalCreditModel,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r2)
	if !r2.IsIntellectualPropertyRisk {
		t.Fatal("readable + internal model = IP risk")
	}
}

func TestParseRatingLetter(t *testing.T) {
	body := []byte(`Rating Letter
rating_id: CAL-2026-0123
calificadora: FIX SCR Argentina
rating: AAA
outlook: stable
series_id: SERIE-XXIV
issuer_class: corporate bond
cliente_emisor_cuit: 30-71234567-8
analyst_cuil: 27-11111111-4
`)
	f := ParseRatingLetter(body)
	if f.RatingID != "CAL-2026-0123" {
		t.Fatalf("rating id=%q", f.RatingID)
	}
	if f.CalificadoraID != CalFIXSCRArgentina {
		t.Fatalf("cal=%q want fix-scr-argentina", f.CalificadoraID)
	}
	if f.RatingClass != RatingAAA {
		t.Fatalf("rating=%q want aaa", f.RatingClass)
	}
	if f.WatchStatus != WatchStable {
		t.Fatalf("watch=%q want stable", f.WatchStatus)
	}
	if f.SeriesID != "SERIE-XXIV" {
		t.Fatalf("series=%q", f.SeriesID)
	}
	if f.IssuerClass != IssuerCorporateBond {
		t.Fatalf("issuer=%q want corporate-bond", f.IssuerClass)
	}
	if f.ClienteEmisorCuitRaw == "" {
		t.Fatal("emisor cuit must extract")
	}
	if f.ClienteAnalystCuilRaw == "" {
		t.Fatal("analyst cuil must extract")
	}
}

func TestParseMethodologyDoc(t *testing.T) {
	body := []byte(`Corporate Bond Rating Methodology
methodology_version: v2.3.1
REVISED METHODOLOGY
peer analysis included
`)
	f := ParseMethodologyDoc(body)
	if f.MethodologyVersion != "v2.3.1" {
		t.Fatalf("version=%q", f.MethodologyVersion)
	}
	if !f.HasMethodologyChange {
		t.Fatal("REVISED marker must flag change")
	}
	if !f.HasCrossIssuerComparable {
		t.Fatal("peer analysis must flag cross-issuer comparable")
	}
}

func TestParseCommitteeMinutes(t *testing.T) {
	body := []byte(`Rating Committee Minutes
rating_id: CAL-2026-0123
rating: AA+
dissenting_opinion_count: 2
`)
	f := ParseCommitteeMinutes(body)
	if f.DissentingOpinionCount != 2 {
		t.Fatalf("dissent=%d", f.DissentingOpinionCount)
	}
	if f.RatingClass != RatingAA {
		t.Fatalf("rating=%q", f.RatingClass)
	}
}

func TestParseWatchlist(t *testing.T) {
	body := []byte(`Watchlist Report
watch_issuer_count: 8
watch_status: negative
`)
	f := ParseWatchlist(body)
	if f.WatchIssuerCount != 8 {
		t.Fatalf("watch issuer count=%d", f.WatchIssuerCount)
	}
	if f.WatchStatus != WatchNegative {
		t.Fatalf("watch status=%q", f.WatchStatus)
	}
}

func TestParseInternalCreditModel(t *testing.T) {
	body := []byte(`model_input_count: 25
methodology_version: v2.3.1
`)
	f := ParseInternalCreditModel(body)
	if f.ModelInputParamCount != 25 {
		t.Fatalf("inputs=%d", f.ModelInputParamCount)
	}
}

func TestParseFeeSchedule(t *testing.T) {
	body := []byte(`Issuer Fee Schedule
fee_total: 50000000
honorarios_total: 75000000
`)
	f := ParseFeeSchedule(body)
	if f.FeeTotalARSMillions != 125 {
		t.Fatalf("fee=%d want 125 M", f.FeeTotalARSMillions)
	}
}

func TestParseIssuerRoster(t *testing.T) {
	body := []byte(`issuer_count: 75
ISSUER-001,30-71234567-8,Banco Galicia
ISSUER-002,30-99999999-1,Cohen S.A.
`)
	f := ParseIssuerRoster(body)
	if f.IssuerCount != 75 {
		t.Fatalf("issuer count=%d", f.IssuerCount)
	}
}

func TestDetectWatchStatus(t *testing.T) {
	cases := map[string]WatchStatus{
		"positive":      WatchPositive,
		"positiva":      WatchPositive,
		"negative":      WatchNegative,
		"negativa":      WatchNegative,
		"developing":    WatchDeveloping,
		"en desarrollo": WatchDeveloping,
		"stable":        WatchStable,
		"estable":       WatchStable,
		"under review":  WatchUnderReview,
		"random":        WatchUnknown,
	}
	for in, want := range cases {
		got := detectWatchStatus(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectIssuerClass(t *testing.T) {
	cases := map[string]IssuerClass{
		"sovereign":              IssuerSovereign,
		"sub-sovereign":          IssuerSubSovereign,
		"provincia":              IssuerSubSovereign,
		"corporate bond":         IssuerCorporateBond,
		"fideicomiso financiero": IssuerFideicomisoFinanciero,
		"financial institution":  IssuerFinancialInstitution,
		"banco":                  IssuerFinancialInstitution,
		"insurance":              IssuerInsurance,
		"pyme":                   IssuerPYMEOn,
		"project finance":        IssuerProjectFinance,
		"unknown stuff":          IssuerUnknown,
	}
	for in, want := range cases {
		got := detectIssuerClass(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectCalificadora(t *testing.T) {
	cases := map[string]CalificadoraID{
		"FIX SCR Argentina":          CalFIXSCRArgentina,
		"Moody's Local Argentina":    CalMoodysLocalArgentina,
		"Evaluadora Latinoamericana": CalEvaluadoraLatinoamericana,
		"Untref":                     CalUntref,
		"ACR":                        CalACR,
		"Standard and Poors":         CalStandardAndPoorsArgentina,
		"unknown":                    CalUnknown,
	}
	for in, want := range cases {
		got := detectCalificadora(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectRating(t *testing.T) {
	cases := map[string]RatingClass{
		"AAA":       RatingAAA,
		"AA+":       RatingAA,
		"BBB-":      RatingBBB,
		"D":         RatingD,
		"NR":        RatingNoRating,
		"withdrawn": RatingWithdrawn,
		"XX":        RatingUnknown,
	}
	for in, want := range cases {
		got := detectRating(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyAnalystRole(t *testing.T) {
	if got := classifyAnalystRole(Row{HasCNVFiling: true}); got != RoleComplianceOfficer {
		t.Fatalf("cnv -> compliance, got %q", got)
	}
	if got := classifyAnalystRole(Row{HasSOCReport: true}); got != RoleComplianceOfficer {
		t.Fatalf("soc -> compliance, got %q", got)
	}
	if got := classifyAnalystRole(Row{HasMethodologyDoc: true}); got != RoleMethodologyOfficer {
		t.Fatalf("methodology -> methodology-officer, got %q", got)
	}
	if got := classifyAnalystRole(Row{HasInternalCreditModel: true}); got != RoleMethodologyOfficer {
		t.Fatalf("model -> methodology-officer, got %q", got)
	}
	if got := classifyAnalystRole(Row{HasCommitteeMinutes: true, HasCommitteeSplit: true}); got != RoleCommitteeChair {
		t.Fatalf("committee+split -> chair, got %q", got)
	}
	if got := classifyAnalystRole(Row{HasCommitteeMinutes: true}); got != RoleCommitteeMember {
		t.Fatalf("committee -> member, got %q", got)
	}
	if got := classifyAnalystRole(Row{HasDissentingOpinion: true}); got != RoleCommitteeMember {
		t.Fatalf("dissent -> member, got %q", got)
	}
	if got := classifyAnalystRole(Row{HasRatingLetter: true}); got != RoleLeadAnalyst {
		t.Fatalf("rating -> lead-analyst, got %q", got)
	}
	if got := classifyAnalystRole(Row{HasWatchlist: true}); got != RoleLeadAnalyst {
		t.Fatalf("watchlist -> lead-analyst, got %q", got)
	}
	if got := classifyAnalystRole(Row{HasConflictOfInterestDoc: true}); got != RoleQualityControl {
		t.Fatalf("coi -> quality-control, got %q", got)
	}
	if got := classifyAnalystRole(Row{HasIssuerRoster: true}); got != RoleCRM {
		t.Fatalf("roster -> crm, got %q", got)
	}
	if got := classifyAnalystRole(Row{ArtifactKind: KindConfig}); got != RoleAPI {
		t.Fatalf("config -> api, got %q", got)
	}
	if got := classifyAnalystRole(Row{}); got != RoleUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	calDir := filepath.Join(usersBase, "alice", "AppData", "Roaming",
		"FIX SCR")
	must(t, os.MkdirAll(calDir, 0o755))

	ratPath := filepath.Join(calDir, "calificacion_GGAL_2026.pdf")
	must(t, os.WriteFile(ratPath, []byte(`Rating Letter
rating_id: CAL-2026-0123
calificadora: FIX SCR Argentina
rating: AAA
outlook: negative
cliente_emisor_cuit: 30-71234567-8
`), 0o644))

	wlPath := filepath.Join(calDir, "watchlist_202606.json")
	must(t, os.WriteFile(wlPath, []byte(`{
"watch_issuer_count": 8,
"watch_status": "negative"
}`), 0o644))

	cmPath := filepath.Join(calDir, "comite_calificacion_15.pdf")
	must(t, os.WriteFile(cmPath, []byte(`Rating Committee Minutes
rating_id: CAL-2026-0123
rating: AA+
dissenting_opinion_count: 2
`), 0o644))

	mdPath := filepath.Join(calDir, "metodologia_corporate_bond_v2.pdf")
	must(t, os.WriteFile(mdPath, []byte(`Corporate Bond Methodology
methodology_version: v2.3.1
REVISED METHODOLOGY
`), 0o644))

	must(t, os.WriteFile(filepath.Join(calDir, "random.txt"),
		[]byte(`nope`), 0o644))

	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "FIX SCR")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "calificacion.pdf"),
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
		t.Fatalf("want 4 (rat+wl+cm+md), got %d: %+v", len(got), got)
	}

	var rat, wl, cm, md Row
	for _, r := range got {
		switch r.FilePath {
		case ratPath:
			rat = r
		case wlPath:
			wl = r
		case cmPath:
			cm = r
		case mdPath:
			md = r
		}
	}

	if rat.ArtifactKind != KindRatingLetter {
		t.Fatalf("rat kind=%q", rat.ArtifactKind)
	}
	if !rat.HasRatingLetter {
		t.Fatalf("rat must flag: %+v", rat)
	}
	if rat.WatchStatus != WatchNegative {
		t.Fatalf("rat watch=%q", rat.WatchStatus)
	}
	if !rat.HasPendingWatchAction {
		t.Fatalf("rat negative watch must flag pending: %+v", rat)
	}
	if !rat.IsMarketMovingInfoRisk {
		t.Fatalf("rat must flag market-moving: %+v", rat)
	}
	if rat.AnalystRole != RoleLeadAnalyst {
		t.Fatalf("rat should classify as lead-analyst, got %q", rat.AnalystRole)
	}

	if wl.ArtifactKind != KindWatchlist {
		t.Fatalf("wl kind=%q", wl.ArtifactKind)
	}
	if !wl.HasWatchlist {
		t.Fatalf("wl must flag: %+v", wl)
	}
	if wl.WatchIssuerCount != 8 {
		t.Fatalf("wl count=%d", wl.WatchIssuerCount)
	}

	if cm.ArtifactKind != KindCommitteeMinutes {
		t.Fatalf("cm kind=%q", cm.ArtifactKind)
	}
	if !cm.HasCommitteeMinutes {
		t.Fatalf("cm must flag: %+v", cm)
	}
	if !cm.HasCommitteeSplit {
		t.Fatalf("cm must flag split (dissent>0): %+v", cm)
	}
	if cm.AnalystRole != RoleCommitteeChair {
		t.Fatalf("cm should classify as committee-chair, got %q", cm.AnalystRole)
	}

	if md.ArtifactKind != KindMethodologyDoc {
		t.Fatalf("md kind=%q", md.ArtifactKind)
	}
	if !md.HasMethodologyChange {
		t.Fatalf("md must flag methodology change: %+v", md)
	}
	if !md.IsIntellectualPropertyRisk {
		t.Fatalf("md must flag IP risk: %+v", md)
	}
	if md.AnalystRole != RoleMethodologyOfficer {
		t.Fatalf("md should classify as methodology-officer, got %q", md.AnalystRole)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-cal")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "calificadora_config.ini"),
		[]byte(`[CAL]
calificadora_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "CALIFICADORA_DIR" {
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
		installRoots: []string{"/nope-cal"},
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
		{FilePath: "/b", ArtifactKind: KindRatingLetter},
		{FilePath: "/a", ArtifactKind: KindWatchlist},
		{FilePath: "/a", ArtifactKind: KindRatingLetter},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindRatingLetter {
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
