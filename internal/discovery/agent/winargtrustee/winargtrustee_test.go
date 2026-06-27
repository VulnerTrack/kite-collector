package winargtrustee

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindIndenture), "trustee-indenture"},
		{string(KindCovenantTest), "trustee-covenant-test"},
		{string(KindDefaultNotice), "trustee-default-notice"},
		{string(KindBondholderMeeting), "trustee-bondholder-meeting"},
		{string(KindCashFlowDistribution), "trustee-cash-flow-distribution"},
		{string(KindBondholderRoster), "trustee-bondholder-roster"},
		{string(KindWorkoutNegotiation), "trustee-workout-negotiation"},
		{string(KindRatingCoordination), "trustee-rating-coordination"},
		{string(KindCNVFiling), "trustee-cnv-filing"},
		{string(KindCrossAcceleration), "trustee-cross-acceleration"},
		{string(KindCollateralMonitoring), "trustee-collateral-monitoring"},
		{string(KindTrusteeFee), "trustee-fee"},
		{string(FirmTMFTrust), "tmf-trust"},
		{string(FirmBNYMellon), "bny-mellon"},
		{string(FirmFirstTrust), "first-trust"},
		{string(FirmEquityTrust), "equity-trust"},
		{string(FirmBICE), "bice"},
		{string(FirmRosarioAdministradora), "rosario-administradora"},
		{string(FirmCohenTrustee), "cohen-trustee"},
		{string(RoleTrusteeOfficer), "trustee-officer"},
		{string(RoleBondholderRep), "bondholder-rep"},
		{string(RoleBondholderCounsel), "bondholder-counsel"},
		{string(ONSimple), "on-simple"},
		{string(ONConvertible), "on-convertible"},
		{string(ONSecured), "on-secured"},
		{string(ONGreenBond), "on-green-bond"},
		{string(ONSustainabilityLinked), "on-sustainability-linked"},
		{string(StatusPerforming), "performing"},
		{string(StatusCovenantBreach), "covenant-breach"},
		{string(StatusPaymentDefault), "payment-default"},
		{string(StatusCrossDefault), "cross-default"},
		{string(StatusCollateralExecution), "collateral-execution"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"indenture_YPF_Serie-12.pdf",
		"covenant_test_YPF-S12_202606.xlsx",
		"default_notice_YPF-S12_20260624.pdf",
		"bondholder_meeting_YPF-S12_20260624.pdf",
		"asamblea_YPF-S12.pdf",
		"cash_flow_dist_YPF-S12_20260624.csv",
		"bondholder_roster_YPF-S12_202606.csv",
		"lista_obligacionistas_YPF-S12.csv",
		"workout_negotiation_YPF-S12.pdf",
		"rating_coordination_YPF-S12.pdf",
		"cnv_filing_YPF-S12_2026q2.xml",
		"cross_acceleration_YPF-S12.pdf",
		"collateral_monitoring_YPF-S12.xlsx",
		"trustee_fee_YPF-S12_2026q2.pdf",
		"trustee_config.ini",
		"tmf_trust_export.csv",
		"bny_mellon_report.csv",
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
		"indenture_YPF_Serie-12.pdf":           KindIndenture,
		"contrato_emision_YPF_Serie-12.pdf":    KindIndenture,
		"covenant_test_YPF-S12_202606.xlsx":    KindCovenantTest,
		"default_notice_YPF-S12_20260624.pdf":  KindDefaultNotice,
		"bondholder_meeting_YPF-S12.pdf":       KindBondholderMeeting,
		"asamblea_YPF-S12.pdf":                 KindBondholderMeeting,
		"cash_flow_dist_YPF-S12_20260624.csv":  KindCashFlowDistribution,
		"distribucion_pago_YPF-S12.csv":        KindCashFlowDistribution,
		"bondholder_roster_YPF-S12_202606.csv": KindBondholderRoster,
		"lista_obligacionistas_YPF-S12.csv":    KindBondholderRoster,
		"workout_negotiation_YPF-S12.pdf":      KindWorkoutNegotiation,
		"rating_coordination_YPF-S12.pdf":      KindRatingCoordination,
		"cnv_filing_YPF-S12_2026q2.xml":        KindCNVFiling,
		"informe_cnv_YPF-S12.xml":              KindCNVFiling,
		"cross_acceleration_YPF-S12.pdf":       KindCrossAcceleration,
		"collateral_monitoring_YPF-S12.xlsx":   KindCollateralMonitoring,
		"trustee_fee_YPF-S12_2026q2.pdf":       KindTrusteeFee,
		"trustee_invoice_YPF-S12.pdf":          KindTrusteeFee,
		"trustee_config.ini":                   KindConfig,
		"credentials.json":                     KindCredentials,
		"trustee_installer_setup.msi":          KindInstaller,
		"":                                     KindUnknown,
		"random_unrelated.txt":                 KindOther,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestTrusteeFirmFromName(t *testing.T) {
	cases := map[string]TrusteeFirm{
		"tmf_argentina_export.csv":        FirmTMFArgentina,
		"tmf_trust_export.csv":            FirmTMFTrust,
		"bny_mellon_report.csv":           FirmBNYMellon,
		"first_trust_export.csv":          FirmFirstTrust,
		"equity_trust_export.csv":         FirmEquityTrust,
		"bice_fideicomiso_export.csv":     FirmBICE,
		"bice_data.csv":                   FirmBICE,
		"rosario_administradora_data.csv": FirmRosarioAdministradora,
		"cohen_trustee_export.csv":        FirmCohenTrustee,
		"hsbc_trust_export.csv":           FirmHSBCTrust,
		"santander_trust_export.csv":      FirmSantanderTrust,
		"aval_federal_trust_export.csv":   FirmAvalFederalTrust,
		"random.txt":                      FirmUnknown,
	}
	for in, want := range cases {
		if got := TrusteeFirmFromName(in); got != want {
			t.Fatalf("TrusteeFirmFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectTrusteeFirm(t *testing.T) {
	cases := map[string]TrusteeFirm{
		"TMF Argentina":     FirmTMFArgentina,
		"TMF Trust":         FirmTMFTrust,
		"BNY Mellon":        FirmBNYMellon,
		"First Trust":       FirmFirstTrust,
		"BICE Fideicomisos": FirmBICE,
		"Cohen Trustee":     FirmCohenTrustee,
		"random":            FirmUnknown,
	}
	for in, want := range cases {
		if got := detectTrusteeFirm(in); got != want {
			t.Fatalf("detectTrusteeFirm(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectONClass(t *testing.T) {
	cases := map[string]ONClass{
		"simple":                ONSimple,
		"convertible":           ONConvertible,
		"subordinated":          ONSubordinated,
		"secured":               ONSecured,
		"vrd-mixed":             ONVRDMixed,
		"pyme":                  ONPyme,
		"green-bond":            ONGreenBond,
		"social-bond":           ONSocialBond,
		"sustainability-linked": ONSustainabilityLinked,
		"slb":                   ONSustainabilityLinked,
		"random":                ONUnknown,
	}
	for in, want := range cases {
		if got := detectONClass(in); got != want {
			t.Fatalf("detectONClass(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectDefaultStatus(t *testing.T) {
	cases := map[string]DefaultStatus{
		"performing":           StatusPerforming,
		"cumpliendo":           StatusPerforming,
		"covenant_breach":      StatusCovenantBreach,
		"payment_default":      StatusPaymentDefault,
		"cross_default":        StatusCrossDefault,
		"acceleration":         StatusAcceleration,
		"aceleracion":          StatusAcceleration,
		"restructured":         StatusRestructured,
		"collateral_execution": StatusCollateralExecution,
		"random":               StatusUnknown,
	}
	for in, want := range cases {
		if got := detectDefaultStatus(in); got != want {
			t.Fatalf("detectDefaultStatus(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindIndenture, KindCovenantTest,
		KindDefaultNotice, KindBondholderMeeting,
		KindCashFlowDistribution, KindBondholderRoster,
		KindWorkoutNegotiation, KindRatingCoordination,
		KindCNVFiling, KindCrossAcceleration,
		KindCollateralMonitoring, KindTrusteeFee,
		KindConfig, KindCredentials,
	}
	for _, k := range yes {
		if !IsCredentialKind(k) {
			t.Fatalf("expected cred: %q", k)
		}
	}
	for _, k := range []ArtifactKind{KindInstaller, KindOther, KindUnknown} {
		if IsCredentialKind(k) {
			t.Fatalf("expected NOT cred: %q", k)
		}
	}
}

func TestIsDefaultDisclosureKind(t *testing.T) {
	yes := []ArtifactKind{
		KindDefaultNotice, KindCovenantTest,
		KindCrossAcceleration, KindCollateralMonitoring,
	}
	for _, k := range yes {
		if !IsDefaultDisclosureKind(k) {
			t.Fatalf("expected default disclosure: %q", k)
		}
	}
}

func TestIsWorkoutStrategyKind(t *testing.T) {
	yes := []ArtifactKind{KindWorkoutNegotiation, KindRatingCoordination}
	for _, k := range yes {
		if !IsWorkoutStrategyKind(k) {
			t.Fatalf("expected workout: %q", k)
		}
	}
}

func TestIsBondholderPIIKind(t *testing.T) {
	yes := []ArtifactKind{KindBondholderRoster, KindCashFlowDistribution, KindBondholderMeeting}
	for _, k := range yes {
		if !IsBondholderPIIKind(k) {
			t.Fatalf("expected bondholder PII: %q", k)
		}
	}
}

func TestAnnotateDefaultDisclosure(t *testing.T) {
	r := Row{
		ArtifactKind: KindDefaultNotice,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasDefaultNotice {
		t.Fatal("default notice kind must flag")
	}
	if !r.IsDefaultDisclosureRisk {
		t.Fatal("readable + default notice = disclosure risk")
	}
}

func TestAnnotateDefaultDisclosureViaPastDue(t *testing.T) {
	r := Row{
		ArtifactKind: KindCashFlowDistribution,
		FileMode:     0o644,
		DaysPastDue:  PaymentPastDueDaysGracePeriod + 1,
	}
	AnnotateSecurity(&r)
	if !r.IsDefaultDisclosureRisk {
		t.Fatal("readable + past grace period = disclosure risk")
	}
}

func TestAnnotateWorkoutStrategyLeak(t *testing.T) {
	r := Row{
		ArtifactKind: KindWorkoutNegotiation,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasWorkoutNegotiation {
		t.Fatal("workout kind must flag")
	}
	if !r.IsWorkoutStrategyLeak {
		t.Fatal("readable + workout = workout strategy leak")
	}
}

func TestAnnotateBondholderPII(t *testing.T) {
	r := Row{
		ArtifactKind: KindBondholderRoster,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasBondholderRoster {
		t.Fatal("roster kind must flag")
	}
	if !r.IsBondholderPIIRisk {
		t.Fatal("readable + roster = bondholder PII risk")
	}
}

func TestAnnotateCovenantBreach(t *testing.T) {
	r := Row{
		ArtifactKind:        KindCovenantTest,
		FileMode:            0o644,
		CovenantBreachCount: 3,
	}
	AnnotateSecurity(&r)
	if !r.HasCovenantBreach {
		t.Fatal("> 0 breaches must flag covenant breach")
	}
	if !r.IsDefaultDisclosureRisk {
		t.Fatal("readable + breach = default disclosure risk")
	}
}

func TestAnnotateCredentialExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindConfig,
		FileMode:            0o644,
		HasPasswordInConfig: true,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + config + password = credential exposure")
	}
}

func TestParseTrustee(t *testing.T) {
	body := []byte(`Indenture
trustee_firm: TMF Trust
on_class: on-simple
default_status: covenant_breach
issuer_cuit: 30-50000446-7
trustee_cuit: 30-71234567-8
on_series_id: YPF-S12
bondholder_count: 850
outstanding_principal_ars: 50000000000
accrued_interest_ars: 3500000000
covenant_breach_count: 2
days_past_due: 45
`)
	f := ParseTrustee(body)
	if f.TrusteeFirm != FirmTMFTrust {
		t.Fatalf("firm=%q", f.TrusteeFirm)
	}
	if f.ONClass != ONSimple {
		t.Fatalf("on_class=%q", f.ONClass)
	}
	if f.DefaultStatus != StatusCovenantBreach {
		t.Fatalf("default=%q", f.DefaultStatus)
	}
	if f.IssuerCuitRaw == "" {
		t.Fatal("issuer_cuit must extract")
	}
	if f.TrusteeCuitRaw == "" {
		t.Fatal("trustee_cuit must extract")
	}
	if f.ONSeriesID != "YPF-S12" {
		t.Fatalf("series=%q", f.ONSeriesID)
	}
	if f.BondholderCount != 850 {
		t.Fatalf("holders=%d", f.BondholderCount)
	}
	if f.OutstandingPrincipalARS != 50_000_000_000 {
		t.Fatalf("principal=%d", f.OutstandingPrincipalARS)
	}
	if f.AccruedInterestARS != 3_500_000_000 {
		t.Fatalf("interest=%d", f.AccruedInterestARS)
	}
	if f.CovenantBreachCount != 2 {
		t.Fatalf("breaches=%d", f.CovenantBreachCount)
	}
	if f.DaysPastDue != 45 {
		t.Fatalf("dpd=%d", f.DaysPastDue)
	}
}

func TestParseTrusteeJSONForm(t *testing.T) {
	body := []byte(`{
  "trustee_firm": "BNY Mellon",
  "on_class": "convertible",
  "default_status": "performing",
  "api_key": "secret"
}`)
	f := ParseTrustee(body)
	if !f.HasPassword {
		t.Fatal("api_key must trigger password")
	}
	if f.TrusteeFirm != FirmBNYMellon {
		t.Fatalf("firm=%q", f.TrusteeFirm)
	}
	if f.ONClass != ONConvertible {
		t.Fatalf("class=%q", f.ONClass)
	}
	if f.DefaultStatus != StatusPerforming {
		t.Fatalf("status=%q", f.DefaultStatus)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	trDir := filepath.Join(usersBase, "alice", "trustee")
	must(t, os.MkdirAll(trDir, 0o755))

	covPath := filepath.Join(trDir, "covenant_test_YPF-S12_202606.xlsx")
	must(t, os.WriteFile(covPath, []byte(`covenant,test,result
DSCR,1.2,fail
trustee_firm: TMF Trust
issuer_cuit: 30-50000446-7
trustee_cuit: 30-71234567-8
on_series_id: YPF-S12
covenant_breach_count: 2
`), 0o644))

	defaultPath := filepath.Join(trDir, "default_notice_YPF-S12_20260624.pdf")
	must(t, os.WriteFile(defaultPath, []byte(`Default Notice
default_status: payment_default
days_past_due: 45
on_series_id: YPF-S12
`), 0o644))

	workoutPath := filepath.Join(trDir, "workout_negotiation_YPF-S12.pdf")
	must(t, os.WriteFile(workoutPath, []byte(`Workout Negotiation Term Sheet
on_series_id: YPF-S12
`), 0o644))

	rosterPath := filepath.Join(trDir, "bondholder_roster_YPF-S12_202606.csv")
	must(t, os.WriteFile(rosterPath, []byte(`holder,vn
JOHN-DOE-NOMINEE,1000000
bondholder_count: 850
`), 0o644))

	must(t, os.WriteFile(filepath.Join(trDir, "random.txt"),
		[]byte(`nope`), 0o644))

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
		t.Fatalf("want 4 (cov+default+workout+roster), got %d: %+v", len(got), got)
	}

	var cov, def, work, ros Row
	for _, r := range got {
		switch r.FilePath {
		case covPath:
			cov = r
		case defaultPath:
			def = r
		case workoutPath:
			work = r
		case rosterPath:
			ros = r
		}
	}

	if cov.ArtifactKind != KindCovenantTest {
		t.Fatalf("cov kind=%q", cov.ArtifactKind)
	}
	if !cov.HasCovenantBreach {
		t.Fatalf("cov must flag breach: %+v", cov)
	}
	if !cov.IsDefaultDisclosureRisk {
		t.Fatalf("cov must flag default disclosure: %+v", cov)
	}
	if !cov.HasIssuerCuit || !cov.HasTrusteeCuit {
		t.Fatalf("cov must flag issuer+trustee cuit: %+v", cov)
	}

	if def.ArtifactKind != KindDefaultNotice {
		t.Fatalf("def kind=%q", def.ArtifactKind)
	}
	if def.DefaultStatus != StatusPaymentDefault {
		t.Fatalf("def status=%q", def.DefaultStatus)
	}
	if !def.IsDefaultDisclosureRisk {
		t.Fatalf("def must flag default risk: %+v", def)
	}

	if work.ArtifactKind != KindWorkoutNegotiation {
		t.Fatalf("work kind=%q", work.ArtifactKind)
	}
	if !work.IsWorkoutStrategyLeak {
		t.Fatalf("work must flag workout leak: %+v", work)
	}

	if ros.ArtifactKind != KindBondholderRoster {
		t.Fatalf("ros kind=%q", ros.ArtifactKind)
	}
	if !ros.IsBondholderPIIRisk {
		t.Fatalf("ros must flag bondholder PII: %+v", ros)
	}
	if ros.BondholderCount != 850 {
		t.Fatalf("ros count=%d", ros.BondholderCount)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-trustee")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "trustee_config.ini"),
		[]byte(`[Trustee]
trustee_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "TRUSTEE_DIR" {
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
		installRoots: []string{"/nope-trustee"},
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
		{FilePath: "/b", ArtifactKind: KindIndenture},
		{FilePath: "/a", ArtifactKind: KindCovenantTest},
		{FilePath: "/a", ArtifactKind: KindIndenture},
	}
	SortRows(rs)
	// "trustee-covenant-test" < "trustee-indenture" alphabetically.
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindCovenantTest {
		t.Fatalf("sort drift: %+v", rs)
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("TMF-TRUST")
	b := HashSecret("tmf-trust")
	if a != b {
		t.Fatal("hash must be case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func TestCuitEntityOnlyFingerprint(t *testing.T) {
	prefix, suffix4 := CuitEntityOnlyFingerprint("issuer_cuit: 30-50000446-7")
	if prefix != "30" {
		t.Fatalf("prefix=%q", prefix)
	}
	if suffix4 != "4467" {
		t.Fatalf("suffix4=%q", suffix4)
	}
	prefix, _ = CuitEntityOnlyFingerprint("20-12345678-9")
	if prefix != "" {
		t.Fatalf("individual prefix must be rejected: %q", prefix)
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if got := PeriodFromFilename("covenant_test_YPF-S12_202606.xlsx"); got != "202606" {
		t.Fatalf("got=%q", got)
	}
	if got := PeriodFromFilename("trustee_fee_2026q2.pdf"); got != "2026" {
		t.Fatalf("got=%q", got)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
