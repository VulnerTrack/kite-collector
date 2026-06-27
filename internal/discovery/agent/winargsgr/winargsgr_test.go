package winargsgr

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindGuaranteeGrant), "sgr-guarantee-grant"},
		{string(KindPymeRoster), "sgr-pyme-roster"},
		{string(KindRiskFundStatement), "sgr-risk-fund-statement"},
		{string(KindCPDGuarantee), "sgr-cpd-guarantee"},
		{string(KindONPymeGuarantee), "sgr-onpyme-guarantee"},
		{string(KindSEPyMeFiling), "sgr-sepyme-filing"},
		{string(KindLeverageRatio), "sgr-leverage-ratio"},
		{string(KindRecoveryProceeding), "sgr-recovery-proceeding"},
		{string(KindCounterGuarantee), "sgr-counter-guarantee"},
		{string(KindSolvencyReport), "sgr-solvency-report"},
		{string(ShopGarantizar), "garantizar"},
		{string(ShopAcindarPymes), "acindar-pymes"},
		{string(ShopGarantizarSustentable), "garantizar-sustentable"},
		{string(ShopFondoGarantiaBuenosAires), "fondo-garantia-buenos-aires"},
		{string(RoleSocioProtector), "socio-protector"},
		{string(RoleCreditOfficer), "credit-officer"},
		{string(RoleRecoveryOfficer), "recovery-officer"},
		{string(CGPledge), "pledge"},
		{string(CGThirdPartyFianza), "third-party-fianza"},
		{string(StatusVigente), "vigente"},
		{string(StatusEjecutada), "ejecutada"},
		{string(InstCPD), "cpd"},
		{string(InstONPyme), "onpyme"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"guarantee_grant_PYME-001_20260624.pdf",
		"pyme_roster_202606.csv",
		"risk_fund_statement_202606.xlsx",
		"cpd_guarantee_30712345678_20260624.pdf",
		"onpyme_guarantee_30712345678_2026.pdf",
		"sepyme_filing_2026q2.xml",
		"leverage_ratio_202606.csv",
		"recovery_proceeding_PYME-001.pdf",
		"counter_guarantee_PYME-001.pdf",
		"solvency_report_2026.pdf",
		"financial_statement_2026.xlsx",
		"shareholder_list_2026.csv",
		"board_resolution_20260624.pdf",
		"sgr_config.ini",
		"garantizar_export.csv",
		"acindar_pymes_avales.csv",
		"aval_federal_pyme.csv",
		"vinculos_sgr_data.csv",
		"don_mario_avales.csv",
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
		"guarantee_grant_PYME-001.pdf":     KindGuaranteeGrant,
		"aval_otorgado_PYME-001.pdf":       KindGuaranteeGrant,
		"pyme_roster_202606.csv":           KindPymeRoster,
		"lista_pymes_202606.csv":           KindPymeRoster,
		"risk_fund_statement_202606.xlsx":  KindRiskFundStatement,
		"fondo_riesgo_202606.xlsx":         KindRiskFundStatement,
		"cpd_guarantee_30712345678.pdf":    KindCPDGuarantee,
		"onpyme_guarantee_30712345678.pdf": KindONPymeGuarantee,
		"sepyme_filing_2026q2.xml":         KindSEPyMeFiling,
		"leverage_ratio_202606.csv":        KindLeverageRatio,
		"apalancamiento_202606.csv":        KindLeverageRatio,
		"recovery_proceeding_PYME-001.pdf": KindRecoveryProceeding,
		"recobro_PYME-001.pdf":             KindRecoveryProceeding,
		"counter_guarantee_PYME-001.pdf":   KindCounterGuarantee,
		"contragarantia_PYME-001.pdf":      KindCounterGuarantee,
		"solvency_report_2026.pdf":         KindSolvencyReport,
		"solvencia_2026.pdf":               KindSolvencyReport,
		"financial_statement_2026.xlsx":    KindFinancialStatement,
		"shareholder_list_2026.csv":        KindShareholderList,
		"socios_2026.csv":                  KindShareholderList,
		"board_resolution_20260624.pdf":    KindBoardResolution,
		"acta_directorio_20260624.pdf":     KindBoardResolution,
		"sgr_config.ini":                   KindConfig,
		"credentials.json":                 KindCredentials,
		"sgr_installer_setup.msi":          KindInstaller,
		"":                                 KindUnknown,
		"garantizar_export.csv":            KindOther,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSGRShopFromName(t *testing.T) {
	cases := map[string]SGRShop{
		"garantizar_sustentable_data.csv": ShopGarantizarSustentable,
		"garantizar_export.csv":           ShopGarantizar,
		"acindar_pymes_avales.csv":        ShopAcindarPymes,
		"aval_federal_pyme.csv":           ShopAvalFederal,
		"vinculos_sgr_data.csv":           ShopVinculos,
		"affidavit_sgr_data.csv":          ShopAffidavit,
		"don_mario_avales.csv":            ShopDonMario,
		"confiable_sgr_data.csv":          ShopConfiable,
		"avaluar_sgr_data.csv":            ShopAvaluar,
		"crecer_sgr_data.csv":             ShopCrecer,
		"fogaba_avales.csv":               ShopFondoGarantiaBuenosAires,
		"random.txt":                      ShopUnknown,
	}
	for in, want := range cases {
		if got := SGRShopFromName(in); got != want {
			t.Fatalf("SGRShopFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectSGRShop(t *testing.T) {
	cases := map[string]SGRShop{
		"Garantizar Sustentable": ShopGarantizarSustentable,
		"Garantizar":             ShopGarantizar,
		"Acindar Pymes":          ShopAcindarPymes,
		"Aval Federal":           ShopAvalFederal,
		"FOGABA":                 ShopFondoGarantiaBuenosAires,
		"random":                 ShopUnknown,
	}
	for in, want := range cases {
		if got := detectSGRShop(in); got != want {
			t.Fatalf("detectSGRShop(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectCounterGuarantee(t *testing.T) {
	cases := map[string]CounterGuaranteeType{
		"pledge":     CGPledge,
		"prenda":     CGPledge,
		"mortgage":   CGMortgage,
		"hipoteca":   CGMortgage,
		"fianza":     CGThirdPartyFianza,
		"term":       CGTermDeposit,
		"plazo":      CGTermDeposit,
		"securities": CGSecurities,
		"titulos":    CGSecurities,
		"random":     CGUnknown,
	}
	for in, want := range cases {
		if got := detectCounterGuarantee(in); got != want {
			t.Fatalf("detectCounterGuarantee(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectGuaranteeStatus(t *testing.T) {
	cases := map[string]GuaranteeStatus{
		"vigente":    StatusVigente,
		"active":     StatusVigente,
		"ejecutada":  StatusEjecutada,
		"executed":   StatusEjecutada,
		"recuperada": StatusRecuperada,
		"prescripta": StatusPrescripta,
		"anulada":    StatusAnulada,
		"random":     StatusUnknown,
	}
	for in, want := range cases {
		if got := detectGuaranteeStatus(in); got != want {
			t.Fatalf("detectGuaranteeStatus(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectInstrumentType(t *testing.T) {
	cases := map[string]InstrumentType{
		"cpd":         InstCPD,
		"cheque":      InstCPD,
		"onpyme":      InstONPyme,
		"on pyme":     InstONPyme,
		"pagare":      InstPagareBursatil,
		"fideicomiso": InstFideicomisoPyme,
		"prestamo":    InstPrestamoBanc,
		"bancario":    InstPrestamoBanc,
		"random":      InstUnknown,
	}
	for in, want := range cases {
		if got := detectInstrumentType(in); got != want {
			t.Fatalf("detectInstrumentType(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindGuaranteeGrant, KindPymeRoster,
		KindRiskFundStatement, KindCPDGuarantee,
		KindONPymeGuarantee, KindSEPyMeFiling,
		KindLeverageRatio, KindRecoveryProceeding,
		KindCounterGuarantee, KindSolvencyReport,
		KindFinancialStatement, KindShareholderList,
		KindBoardResolution,
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

func TestIsSMEPIIKind(t *testing.T) {
	yes := []ArtifactKind{
		KindGuaranteeGrant, KindPymeRoster,
		KindCPDGuarantee, KindONPymeGuarantee,
		KindCounterGuarantee, KindRecoveryProceeding,
	}
	for _, k := range yes {
		if !IsSMEPIIKind(k) {
			t.Fatalf("expected SME PII: %q", k)
		}
	}
	for _, k := range []ArtifactKind{
		KindRiskFundStatement, KindSEPyMeFiling,
		KindLeverageRatio, KindSolvencyReport,
		KindFinancialStatement, KindShareholderList,
		KindBoardResolution,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown,
	} {
		if IsSMEPIIKind(k) {
			t.Fatalf("expected NOT SME PII: %q", k)
		}
	}
}

func TestIsRecoveryLeakKind(t *testing.T) {
	yes := []ArtifactKind{KindRecoveryProceeding, KindCounterGuarantee}
	for _, k := range yes {
		if !IsRecoveryLeakKind(k) {
			t.Fatalf("expected recovery leak: %q", k)
		}
	}
}

func TestAnnotateSMEPII(t *testing.T) {
	r := Row{
		ArtifactKind: KindGuaranteeGrant,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasGuaranteeGrant {
		t.Fatal("guarantee-grant kind must flag")
	}
	if !r.IsSMEPIIRisk {
		t.Fatal("readable + guarantee-grant = SME PII risk")
	}
}

func TestAnnotateRecoveryLeak(t *testing.T) {
	r := Row{
		ArtifactKind: KindRecoveryProceeding,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasRecoveryProceeding {
		t.Fatal("recovery kind must flag")
	}
	if !r.IsRecoveryProceedingLeak {
		t.Fatal("readable + recovery = recovery leak risk")
	}
}

func TestAnnotateApalancamientoBreach(t *testing.T) {
	r := Row{
		ArtifactKind:           KindLeverageRatio,
		ApalancamientoRatioPct: ApalancamientoCapPct + 1,
		FileMode:               0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasApalancamientoBreach {
		t.Fatal("> 1000% must flag breach")
	}
	if !r.IsApalancamientoBreachRisk {
		t.Fatal("readable + breach = breach risk")
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

func TestParseSGR(t *testing.T) {
	body := []byte(`Guarantee Grant
sgr_shop: Garantizar
counter_guarantee_type: pledge
guarantee_status: vigente
instrument_type: cpd
sgr_cuit: 30-71234567-8
sme_cuit: 30-72345678-9
pyme_count: 250
active_guarantee_count: 4200
risk_fund_size_ars: 50000000000
guarantees_outstanding_ars: 350000000000
apalancamiento_ratio_pct: 700
`)
	f := ParseSGR(body)
	if f.SGRShop != ShopGarantizar {
		t.Fatalf("shop=%q", f.SGRShop)
	}
	if f.CounterGuaranteeType != CGPledge {
		t.Fatalf("cg=%q", f.CounterGuaranteeType)
	}
	if f.GuaranteeStatus != StatusVigente {
		t.Fatalf("status=%q", f.GuaranteeStatus)
	}
	if f.InstrumentType != InstCPD {
		t.Fatalf("inst=%q", f.InstrumentType)
	}
	if f.SGRCuitRaw == "" {
		t.Fatal("sgr_cuit must extract")
	}
	if f.SMECuitRaw == "" {
		t.Fatal("sme_cuit must extract")
	}
	if f.PymeCount != 250 {
		t.Fatalf("pyme=%d", f.PymeCount)
	}
	if f.ActiveGuaranteeCount != 4200 {
		t.Fatalf("ag=%d", f.ActiveGuaranteeCount)
	}
	if f.RiskFundSizeARS != 50_000_000_000 {
		t.Fatalf("rf=%d", f.RiskFundSizeARS)
	}
	if f.GuaranteesOutstandingARS != 350_000_000_000 {
		t.Fatalf("out=%d", f.GuaranteesOutstandingARS)
	}
	if f.ApalancamientoRatioPct != 700 {
		t.Fatalf("apal=%d", f.ApalancamientoRatioPct)
	}
}

func TestParseSGRJSONForm(t *testing.T) {
	body := []byte(`{
  "sgr_shop": "Acindar Pymes",
  "guarantee_status": "ejecutada",
  "instrument_type": "onpyme",
  "api_key": "secret_value"
}`)
	f := ParseSGR(body)
	if !f.HasPassword {
		t.Fatal("api_key must trigger password")
	}
	if f.SGRShop != ShopAcindarPymes {
		t.Fatalf("shop=%q", f.SGRShop)
	}
	if f.GuaranteeStatus != StatusEjecutada {
		t.Fatalf("status=%q", f.GuaranteeStatus)
	}
	if f.InstrumentType != InstONPyme {
		t.Fatalf("inst=%q", f.InstrumentType)
	}
}

func TestCuitEntityOnlyFingerprint(t *testing.T) {
	prefix, suffix4 := CuitEntityOnlyFingerprint("sgr_cuit: 30-71234567-8")
	if prefix != "30" {
		t.Fatalf("prefix=%q", prefix)
	}
	if suffix4 != "5678" {
		t.Fatalf("suffix4=%q", suffix4)
	}
	// Reject individual prefix.
	prefix, _ = CuitEntityOnlyFingerprint("20-12345678-9")
	if prefix != "" {
		t.Fatalf("individual prefix must be rejected: %q", prefix)
	}
}

func TestCuitAnyFingerprint(t *testing.T) {
	// SME beneficiary can be an individual (unincorporated).
	prefix, suffix4 := CuitAnyFingerprint("sme_cuit: 20-12345678-9")
	if prefix != "20" {
		t.Fatalf("prefix=%q", prefix)
	}
	if suffix4 != "6789" {
		t.Fatalf("suffix4=%q", suffix4)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	sgrDir := filepath.Join(usersBase, "alice", "sgr")
	must(t, os.MkdirAll(sgrDir, 0o755))

	grantPath := filepath.Join(sgrDir, "guarantee_grant_PYME-001_20260624.pdf")
	must(t, os.WriteFile(grantPath, []byte(`Guarantee Grant
sgr_shop: Garantizar
sgr_cuit: 30-71234567-8
sme_cuit: 30-72345678-9
guarantee_status: vigente
instrument_type: cpd
`), 0o644))

	leveragePath := filepath.Join(sgrDir, "leverage_ratio_202606.csv")
	must(t, os.WriteFile(leveragePath, []byte(`period,ratio
202606,1500
apalancamiento_ratio_pct: 1500
`), 0o644))

	recoveryPath := filepath.Join(sgrDir, "recovery_proceeding_PYME-001.pdf")
	must(t, os.WriteFile(recoveryPath, []byte(`Recovery Proceeding
sme_cuit: 30-72345678-9
guarantee_status: ejecutada
`), 0o644))

	pymePath := filepath.Join(sgrDir, "pyme_roster_202606.csv")
	must(t, os.WriteFile(pymePath, []byte(`pyme_count: 250
`), 0o644))

	must(t, os.WriteFile(filepath.Join(sgrDir, "random.txt"),
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
		t.Fatalf("want 4 (grant+leverage+recovery+pyme), got %d: %+v", len(got), got)
	}

	var grant, lev, rec, pyme Row
	for _, r := range got {
		switch r.FilePath {
		case grantPath:
			grant = r
		case leveragePath:
			lev = r
		case recoveryPath:
			rec = r
		case pymePath:
			pyme = r
		}
	}

	if grant.ArtifactKind != KindGuaranteeGrant {
		t.Fatalf("grant kind=%q", grant.ArtifactKind)
	}
	if !grant.IsSMEPIIRisk {
		t.Fatalf("grant must flag SME PII risk: %+v", grant)
	}
	if !grant.HasSGRCuit {
		t.Fatalf("grant must flag SGR cuit: %+v", grant)
	}
	if !grant.HasSMECuit {
		t.Fatalf("grant must flag SME cuit: %+v", grant)
	}
	if grant.SGRShop != ShopGarantizar {
		t.Fatalf("grant shop=%q", grant.SGRShop)
	}

	if lev.ArtifactKind != KindLeverageRatio {
		t.Fatalf("lev kind=%q", lev.ArtifactKind)
	}
	if !lev.HasApalancamientoBreach {
		t.Fatalf("lev must flag breach: %+v", lev)
	}
	if !lev.IsApalancamientoBreachRisk {
		t.Fatalf("lev must flag breach risk: %+v", lev)
	}

	if rec.ArtifactKind != KindRecoveryProceeding {
		t.Fatalf("rec kind=%q", rec.ArtifactKind)
	}
	if !rec.IsRecoveryProceedingLeak {
		t.Fatalf("rec must flag recovery leak: %+v", rec)
	}

	if pyme.ArtifactKind != KindPymeRoster {
		t.Fatalf("pyme kind=%q", pyme.ArtifactKind)
	}
	if pyme.PymeCount != 250 {
		t.Fatalf("pyme count=%d", pyme.PymeCount)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-sgr")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "sgr_config.ini"),
		[]byte(`[SGR]
sgr_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "SGR_DIR" {
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
		installRoots: []string{"/nope-sgr"},
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
		{FilePath: "/b", ArtifactKind: KindGuaranteeGrant},
		{FilePath: "/a", ArtifactKind: KindCPDGuarantee},
		{FilePath: "/a", ArtifactKind: KindGuaranteeGrant},
	}
	SortRows(rs)
	// "sgr-cpd-guarantee" < "sgr-guarantee-grant" alphabetically.
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindCPDGuarantee {
		t.Fatalf("sort drift: %+v", rs)
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("GARANTIZAR")
	b := HashSecret("garantizar")
	if a != b {
		t.Fatal("hash must be case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if got := PeriodFromFilename("pyme_roster_202606.csv"); got != "202606" {
		t.Fatalf("got=%q", got)
	}
	if got := PeriodFromFilename("solvency_report_2026.pdf"); got != "2026" {
		t.Fatalf("got=%q", got)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
