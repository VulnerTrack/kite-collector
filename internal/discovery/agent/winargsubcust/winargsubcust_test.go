package winargsubcust

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindForeignBORoster), "subcust-foreign-bo-roster"},
		{string(KindFXClearance), "subcust-fx-clearance"},
		{string(KindWithholdingCert), "subcust-withholding-cert"},
		{string(KindIIGGNonResidentFiling), "subcust-iigg-nonresident-filing"},
		{string(KindAFIPRG5527Filing), "subcust-afip-rg5527-filing"},
		{string(KindCVSAReconciliation), "subcust-cvsa-reconciliation"},
		{string(KindOmnibusAccount), "subcust-omnibus-account"},
		{string(KindADRChain), "subcust-adr-chain"},
		{string(KindSWIFTInstruction), "subcust-swift-instruction"},
		{string(KindProxyService), "subcust-proxy-service"},
		{string(KindCorporateAction), "subcust-corporate-action"},
		{string(KindSovereignImmunity), "subcust-sovereign-immunity"},
		{string(BankBNYGalicia), "bny-galicia"},
		{string(BankCitibankAR), "citibank-ar"},
		{string(BankHSBCAR), "hsbc-ar"},
		{string(BankStandardBank), "standard-bank"},
		{string(GCBNYMellon), "bny-mellon"},
		{string(GCStateStreet), "state-street"},
		{string(GCBrownBrothersHarriman), "brown-brothers-harriman"},
		{string(GCCajaDeValores), "caja-de-valores"},
		{string(RoleRelationshipManager), "relationship-manager"},
		{string(RoleFXOfficer), "fx-officer"},
		{string(RoleProxyOfficer), "proxy-officer"},
		{string(DGTUSA), "usa"},
		{string(DGTSpain), "spain"},
		{string(DGTSwitzerland), "switzerland"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"foreign_bo_roster_bny_202606.csv",
		"fx_clearance_20260624.csv",
		"withholding_cert_spain_2026.pdf",
		"dgt_cert_spain_2026.pdf",
		"iigg_nonresident_2026q2.xml",
		"afip_rg5527_2026q2.xml",
		"cvsa_reconciliation_202606.csv",
		"omnibus_account_state_street_202606.csv",
		"adr_chain_YPF_202606.csv",
		"swift_instruction_20260624.txt",
		"swift_mt540_20260624.txt",
		"proxy_service_YPF_2026.pdf",
		"corporate_action_YPF_20260624.pdf",
		"sovereign_immunity_FED_2026.pdf",
		"subcust_config.ini",
		"bny_galicia_export.csv",
		"citibank_ar_report.csv",
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
		"foreign_bo_roster_bny_202606.csv":        KindForeignBORoster,
		"fx_clearance_20260624.csv":               KindFXClearance,
		"mulc_clearance_20260624.csv":             KindFXClearance,
		"withholding_cert_spain_2026.pdf":         KindWithholdingCert,
		"dgt_cert_spain_2026.pdf":                 KindWithholdingCert,
		"iigg_nonresident_2026q2.xml":             KindIIGGNonResidentFiling,
		"afip_rg5527_2026q2.xml":                  KindAFIPRG5527Filing,
		"rg5527_2026q2.xml":                       KindAFIPRG5527Filing,
		"cvsa_reconciliation_202606.csv":          KindCVSAReconciliation,
		"omnibus_account_state_street_202606.csv": KindOmnibusAccount,
		"omnibus_202606.csv":                      KindOmnibusAccount,
		"adr_chain_YPF_202606.csv":                KindADRChain,
		"dtc_chain_YPF_202606.csv":                KindADRChain,
		"swift_instruction_20260624.txt":          KindSWIFTInstruction,
		"swift_mt540_20260624.txt":                KindSWIFTInstruction,
		"proxy_service_YPF_2026.pdf":              KindProxyService,
		"proxy_voting_YPF_2026.pdf":               KindProxyService,
		"corporate_action_YPF_20260624.pdf":       KindCorporateAction,
		"ca_notice_YPF_20260624.pdf":              KindCorporateAction,
		"sovereign_immunity_FED_2026.pdf":         KindSovereignImmunity,
		"subcust_config.ini":                      KindConfig,
		"credentials.json":                        KindCredentials,
		"subcust_installer_setup.msi":             KindInstaller,
		"":                                        KindUnknown,
		"bny_galicia_export.csv":                  KindOther,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSubCustBankFromName(t *testing.T) {
	cases := map[string]SubCustBank{
		"bny_galicia_export.csv":        BankBNYGalicia,
		"citibank_ar_report.csv":        BankCitibankAR,
		"hsbc_ar_report.csv":            BankHSBCAR,
		"standard_bank_report.csv":      BankStandardBank,
		"icbc_ar_report.csv":            BankStandardBank,
		"santander_ar_report.csv":       BankSantanderAR,
		"bbva_ar_report.csv":            BankBBVAAR,
		"itau_ar_report.csv":            BankItauAR,
		"credit_agricole_ar_report.csv": BankCreditAgricoleAR,
		"jpmorgan_ar_report.csv":        BankJPMorganAR,
		"random.txt":                    BankUnknown,
	}
	for in, want := range cases {
		if got := SubCustBankFromName(in); got != want {
			t.Fatalf("SubCustBankFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectSubCustBank(t *testing.T) {
	cases := map[string]SubCustBank{
		"BNY Galicia":        BankBNYGalicia,
		"Citibank AR":        BankCitibankAR,
		"HSBC AR":            BankHSBCAR,
		"Standard Bank":      BankStandardBank,
		"ICBC AR":            BankStandardBank,
		"Santander AR":       BankSantanderAR,
		"BBVA AR":            BankBBVAAR,
		"Itau AR":            BankItauAR,
		"Credit Agricole AR": BankCreditAgricoleAR,
		"JPMorgan AR":        BankJPMorganAR,
		"random":             BankUnknown,
	}
	for in, want := range cases {
		if got := detectSubCustBank(in); got != want {
			t.Fatalf("detectSubCustBank(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectGlobalCustodian(t *testing.T) {
	cases := map[string]GlobalCustodian{
		"BNY Mellon":              GCBNYMellon,
		"Citi GCA":                GCCitiGCA,
		"HSBC SS":                 GCHSBCSS,
		"JPMorgan SS":             GCJPMorganSS,
		"State Street":            GCStateStreet,
		"Northern Trust":          GCNorthernTrust,
		"Brown Brothers Harriman": GCBrownBrothersHarriman,
		"BBH":                     GCBrownBrothersHarriman,
		"SSGA":                    GCSSGA,
		"Caja de Valores":         GCCajaDeValores,
		"CVSA":                    GCCajaDeValores,
		"random":                  GCUnknown,
	}
	for in, want := range cases {
		if got := detectGlobalCustodian(in); got != want {
			t.Fatalf("detectGlobalCustodian(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectDGTCountry(t *testing.T) {
	cases := map[string]DGTTreatyCountry{
		"USA":            DGTUSA,
		"United States":  DGTUSA,
		"Spain":          DGTSpain,
		"Espana":         DGTSpain,
		"Chile":          DGTChile,
		"Brazil":         DGTBrazil,
		"Brasil":         DGTBrazil,
		"Germany":        DGTGermany,
		"Alemania":       DGTGermany,
		"UK":             DGTUK,
		"United Kingdom": DGTUK,
		"Reino Unido":    DGTUK,
		"Canada":         DGTCanada,
		"Italy":          DGTItaly,
		"France":         DGTFrance,
		"Netherlands":    DGTNetherlands,
		"Holanda":        DGTNetherlands,
		"Paises Bajos":   DGTNetherlands,
		"Switzerland":    DGTSwitzerland,
		"Suiza":          DGTSwitzerland,
		"random":         DGTUnknown,
	}
	for in, want := range cases {
		if got := detectDGTCountry(in); got != want {
			t.Fatalf("detectDGTCountry(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindForeignBORoster, KindFXClearance,
		KindWithholdingCert, KindIIGGNonResidentFiling,
		KindAFIPRG5527Filing, KindCVSAReconciliation,
		KindOmnibusAccount, KindADRChain,
		KindSWIFTInstruction, KindProxyService,
		KindCorporateAction, KindSovereignImmunity,
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

func TestIsForeignInvestorPIIKind(t *testing.T) {
	yes := []ArtifactKind{
		KindForeignBORoster, KindOmnibusAccount,
		KindProxyService, KindADRChain,
	}
	for _, k := range yes {
		if !IsForeignInvestorPIIKind(k) {
			t.Fatalf("expected FII PII: %q", k)
		}
	}
}

func TestIsFXFlowIntelligenceKind(t *testing.T) {
	yes := []ArtifactKind{KindFXClearance, KindSWIFTInstruction, KindCorporateAction}
	for _, k := range yes {
		if !IsFXFlowIntelligenceKind(k) {
			t.Fatalf("expected FX flow: %q", k)
		}
	}
}

func TestIsTaxTreatyKind(t *testing.T) {
	yes := []ArtifactKind{
		KindWithholdingCert, KindIIGGNonResidentFiling,
		KindAFIPRG5527Filing, KindSovereignImmunity,
	}
	for _, k := range yes {
		if !IsTaxTreatyKind(k) {
			t.Fatalf("expected tax treaty: %q", k)
		}
	}
}

func TestAnnotateForeignInvestorPII(t *testing.T) {
	r := Row{
		ArtifactKind: KindForeignBORoster,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasForeignBORoster {
		t.Fatal("foreign BO kind must flag")
	}
	if !r.IsForeignInvestorPIIRisk {
		t.Fatal("readable + foreign BO = FII PII risk")
	}
}

func TestAnnotateFXFlowIntelligence(t *testing.T) {
	r := Row{
		ArtifactKind: KindFXClearance,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasFXClearance {
		t.Fatal("FX clearance kind must flag")
	}
	if !r.IsFXFlowIntelligenceRisk {
		t.Fatal("readable + FX clearance = FX flow intel risk")
	}
}

func TestAnnotateTaxTreatyLeak(t *testing.T) {
	r := Row{
		ArtifactKind:     KindWithholdingCert,
		DGTTreatyCountry: DGTSpain,
		FileMode:         0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasWithholdingCert {
		t.Fatal("withholding cert must flag")
	}
	if !r.IsTaxTreatyLeak {
		t.Fatal("readable + withholding cert = tax treaty leak")
	}
}

func TestAnnotateCredentialExposureViaSWIFTBIC(t *testing.T) {
	r := Row{
		ArtifactKind: KindSWIFTInstruction,
		FileMode:     0o644,
		SWIFTBICHash: "abc123",
	}
	AnnotateSecurity(&r)
	if !r.HasSWIFTBIC {
		t.Fatal("SWIFT BIC must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + SWIFT instruction + BIC = cred exposure")
	}
}

func TestAnnotateLargeOmnibus(t *testing.T) {
	r := Row{
		ArtifactKind:    KindOmnibusAccount,
		OmnibusValueARS: LargeOmnibusValueARSThreshold + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasLargeOmnibusValue {
		t.Fatal("> 50B ARS must flag large omnibus")
	}
}

func TestParseSubCust(t *testing.T) {
	body := []byte(`Foreign BO Roster
subcust_bank: BNY Galicia
global_custodian: BNY Mellon
dgt_treaty_country: Spain
subcust_cuit: 30-50000446-7
foreign_tin: ES-A12345678
swift_bic: BSCHESMMXXX
omnibus_account: OMN-BNY-001-AR
foreign_bo_count: 1250
omnibus_account_count: 18
omnibus_value_ars: 125000000000
fx_clearance_amount_usd: 50000000
withholding_amount_ars: 2500000000
`)
	f := ParseSubCust(body)
	if f.SubCustBank != BankBNYGalicia {
		t.Fatalf("bank=%q", f.SubCustBank)
	}
	if f.GlobalCustodian != GCBNYMellon {
		t.Fatalf("gc=%q", f.GlobalCustodian)
	}
	if f.DGTTreatyCountry != DGTSpain {
		t.Fatalf("dgt=%q", f.DGTTreatyCountry)
	}
	if f.SubCustCuitRaw == "" {
		t.Fatal("cuit must extract")
	}
	if f.ForeignTINCountry != "ES" {
		t.Fatalf("tin country=%q", f.ForeignTINCountry)
	}
	if f.ForeignTINRaw != "A12345678" {
		t.Fatalf("tin raw=%q", f.ForeignTINRaw)
	}
	if f.SWIFTBIC != "BSCHESMMXXX" {
		t.Fatalf("bic=%q", f.SWIFTBIC)
	}
	if f.OmnibusAccountRaw != "OMN-BNY-001-AR" {
		t.Fatalf("omni=%q", f.OmnibusAccountRaw)
	}
	if f.ForeignBOCount != 1250 {
		t.Fatalf("bo=%d", f.ForeignBOCount)
	}
	if f.OmnibusAccountCount != 18 {
		t.Fatalf("omni count=%d", f.OmnibusAccountCount)
	}
	if f.OmnibusValueARS != 125_000_000_000 {
		t.Fatalf("omni val=%d", f.OmnibusValueARS)
	}
	if f.FXClearanceAmountUSD != 50_000_000 {
		t.Fatalf("fx=%d", f.FXClearanceAmountUSD)
	}
	if f.WithholdingAmountARS != 2_500_000_000 {
		t.Fatalf("wh=%d", f.WithholdingAmountARS)
	}
}

func TestParseSubCustJSONForm(t *testing.T) {
	body := []byte(`{
  "subcust_bank": "Citibank AR",
  "global_custodian": "State Street",
  "api_key": "secret"
}`)
	f := ParseSubCust(body)
	if !f.HasPassword {
		t.Fatal("api_key must trigger password")
	}
	if f.SubCustBank != BankCitibankAR {
		t.Fatalf("bank=%q", f.SubCustBank)
	}
	if f.GlobalCustodian != GCStateStreet {
		t.Fatalf("gc=%q", f.GlobalCustodian)
	}
}

func TestTINSuffix4(t *testing.T) {
	cases := map[string]string{
		"A12345678":    "5678",
		"a12345678":    "5678",
		"ES-A12345678": "5678",
		"abc":          "ABC",
		"":             "",
	}
	for in, want := range cases {
		if got := TINSuffix4(in); got != want {
			t.Fatalf("TINSuffix4(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	scDir := filepath.Join(usersBase, "alice", "subcust")
	must(t, os.MkdirAll(scDir, 0o755))

	boPath := filepath.Join(scDir, "foreign_bo_roster_bny_202606.csv")
	must(t, os.WriteFile(boPath, []byte(`holder,nominee
JOHN-DOE-FII,BNY-NOMINEE
subcust_bank: BNY Galicia
global_custodian: BNY Mellon
foreign_bo_count: 1250
subcust_cuit: 30-50000446-7
`), 0o644))

	fxPath := filepath.Join(scDir, "fx_clearance_20260624.csv")
	must(t, os.WriteFile(fxPath, []byte(`txid,amount_usd,direction
1,50000000,inbound
fx_clearance_amount_usd: 50000000
`), 0o644))

	dgtPath := filepath.Join(scDir, "withholding_cert_spain_2026.pdf")
	must(t, os.WriteFile(dgtPath, []byte(`DGT Treaty Cert
dgt_treaty_country: Spain
foreign_tin: ES-A12345678
withholding_amount_ars: 2500000000
`), 0o644))

	swiftPath := filepath.Join(scDir, "swift_instruction_20260624.txt")
	must(t, os.WriteFile(swiftPath, []byte(`{1:F01BANKARG1XXX0000000000}{2:I540BSCHESMMXXXN}
swift_bic: BSCHESMMXXX
omnibus_account: OMN-001-AR
`), 0o644))

	omniPath := filepath.Join(scDir, "omnibus_account_state_street_202606.csv")
	must(t, os.WriteFile(omniPath, []byte(`omnibus_id,ticker,qty
OMN-001,YPF,500000
omnibus_value_ars: 80000000000
`), 0o644))

	must(t, os.WriteFile(filepath.Join(scDir, "random.txt"),
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
	if len(got) != 5 {
		t.Fatalf("want 5 (bo+fx+dgt+swift+omni), got %d: %+v", len(got), got)
	}

	var bo, fx, dgt, sw, omni Row
	for _, r := range got {
		switch r.FilePath {
		case boPath:
			bo = r
		case fxPath:
			fx = r
		case dgtPath:
			dgt = r
		case swiftPath:
			sw = r
		case omniPath:
			omni = r
		}
	}

	if bo.ArtifactKind != KindForeignBORoster {
		t.Fatalf("bo kind=%q", bo.ArtifactKind)
	}
	if bo.SubCustBank != BankBNYGalicia {
		t.Fatalf("bo bank=%q", bo.SubCustBank)
	}
	if !bo.IsForeignInvestorPIIRisk {
		t.Fatalf("bo must flag FII PII: %+v", bo)
	}
	if !bo.HasBankCuit {
		t.Fatalf("bo must flag bank cuit: %+v", bo)
	}
	if !bo.HasGlobalCustodian {
		t.Fatalf("bo must flag global custodian: %+v", bo)
	}

	if fx.ArtifactKind != KindFXClearance {
		t.Fatalf("fx kind=%q", fx.ArtifactKind)
	}
	if !fx.IsFXFlowIntelligenceRisk {
		t.Fatalf("fx must flag FX intel: %+v", fx)
	}

	if dgt.ArtifactKind != KindWithholdingCert {
		t.Fatalf("dgt kind=%q", dgt.ArtifactKind)
	}
	if dgt.DGTTreatyCountry != DGTSpain {
		t.Fatalf("dgt country=%q", dgt.DGTTreatyCountry)
	}
	if !dgt.IsTaxTreatyLeak {
		t.Fatalf("dgt must flag tax treaty leak: %+v", dgt)
	}
	if dgt.ForeignTINCountry != "ES" || dgt.ForeignTINSuffix4 != "5678" {
		t.Fatalf("dgt tin country/suffix=%q/%q", dgt.ForeignTINCountry, dgt.ForeignTINSuffix4)
	}

	if sw.ArtifactKind != KindSWIFTInstruction {
		t.Fatalf("sw kind=%q", sw.ArtifactKind)
	}
	if !sw.HasSWIFTBIC {
		t.Fatalf("sw must flag SWIFT BIC: %+v", sw)
	}
	if !sw.IsCredentialExposureRisk {
		t.Fatalf("sw must flag cred exposure: %+v", sw)
	}

	if omni.ArtifactKind != KindOmnibusAccount {
		t.Fatalf("omni kind=%q", omni.ArtifactKind)
	}
	if !omni.HasLargeOmnibusValue {
		t.Fatalf("omni must flag large value: %+v", omni)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-subcust")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "subcust_config.ini"),
		[]byte(`[SubCust]
subcust_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "SUBCUST_DIR" {
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
		installRoots: []string{"/nope-subcust"},
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
		{FilePath: "/b", ArtifactKind: KindForeignBORoster},
		{FilePath: "/a", ArtifactKind: KindFXClearance},
		{FilePath: "/a", ArtifactKind: KindForeignBORoster},
	}
	SortRows(rs)
	// "subcust-foreign-bo-roster" < "subcust-fx-clearance" alphabetically.
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindForeignBORoster {
		t.Fatalf("sort drift: %+v", rs)
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("BSCHESMMXXX")
	b := HashSecret("bscheSMMXXX")
	if a != b {
		t.Fatal("hash must be case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func TestCuitEntityOnlyFingerprint(t *testing.T) {
	prefix, suffix4 := CuitEntityOnlyFingerprint("subcust_cuit: 30-50000446-7")
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
	if got := PeriodFromFilename("foreign_bo_roster_bny_202606.csv"); got != "202606" {
		t.Fatalf("got=%q", got)
	}
	if got := PeriodFromFilename("withholding_cert_spain_2026.pdf"); got != "2026" {
		t.Fatalf("got=%q", got)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
