package winargssn

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindInvestmentPortfolio), "ssn-investment-portfolio"},
		{string(KindCustodyProof), "ssn-custody-proof"},
		{string(KindFinancialStatement), "ssn-financial-statement"},
		{string(KindPremiumReport), "ssn-premium-report"},
		{string(KindClaimReport), "ssn-claim-report"},
		{string(KindCyberPolicyReport), "ssn-cyber-policy-report"},
		{string(KindReinsuranceTreaty), "ssn-reinsurance-treaty"},
		{string(KindARTClaimRecord), "ssn-art-claim-record"},
		{string(KindFilingReceipt), "ssn-filing-receipt"},
		{string(InsurerLife), "life-insurer"},
		{string(InsurerART), "art-insurer"},
		{string(InsurerReinsurer), "reinsurer"},
		{string(InsurerComplianceOfficer), "compliance-officer"},
		{string(PortfolioARSovBond), "ar-sovereign-bond"},
		{string(PortfolioARFCI), "ar-fci"},
		{string(PortfolioCEDEAR), "cedear"},
		{string(LOBCyber), "cyber"},
		{string(LOBRiesgosTrabajo), "riesgos-del-trabajo"},
		{string(LOBReaseguro), "reaseguro"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"inversiones_202606.xml",
		"inversiones_202606.xlsx",
		"custodia_202606.pdf",
		"estados_contables_2026.xlsx",
		"primas_emitidas_202606.csv",
		"siniestros_202606.csv",
		"encaje_tecnico_202606.csv",
		"cyber_policy_202606.csv",
		"reaseguro_treaty_001.xml",
		"art_claim_202606.csv",
		"trabajador_30-12345678-9.json",
		"ssn_config.ini",
		"poliza_27-11111111-4.pdf",
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
		"inversiones_202606.xml":      KindInvestmentPortfolio,
		"inversiones_202606.xlsx":     KindInvestmentPortfolio,
		"custodia_202606.pdf":         KindCustodyProof,
		"estados_contables_2026.xlsx": KindFinancialStatement,
		"primas_emitidas_202606.csv":  KindPremiumReport,
		"siniestros_202606.csv":       KindClaimReport,
		"encaje_tecnico_202606.csv":   KindReserveReport,
		"cyber_policy_202606.csv":     KindCyberPolicyReport,
		"reaseguro_treaty_001.xml":    KindReinsuranceTreaty,
		"art_claim_202606.csv":        KindARTClaimRecord,
		"ssn_receipt_202606.xml":      KindFilingReceipt,
		"ssn_config.ini":              KindConfig,
		"credentials.json":            KindCredentials,
		"ssn_setup.msi":               KindInstaller,
		"":                            KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
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
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestCuilFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"trabajador 27-11111111-4", "27", "1114"},
		// Entity prefix 30 rejected for CUIL (individuals only).
		{"empresa 30-71234567-8", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuilFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuilFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestARSovereignBondStem(t *testing.T) {
	yes := []string{"AL30", "GD30", "AE38", "TX26", "PARP"}
	no := []string{"", "AAPL", "GGAL"}
	for _, v := range yes {
		if !IsARSovereignBondStem(v) {
			t.Fatalf("expected sov bond: %q", v)
		}
	}
	for _, v := range no {
		if IsARSovereignBondStem(v) {
			t.Fatalf("expected NOT sov bond: %q", v)
		}
	}
}

func TestAREquityStem(t *testing.T) {
	yes := []string{"GGAL", "YPFD", "ALUA"}
	no := []string{"", "AAPL", "AL30"}
	for _, v := range yes {
		if !IsAREquityStem(v) {
			t.Fatalf("expected AR equity: %q", v)
		}
	}
	for _, v := range no {
		if IsAREquityStem(v) {
			t.Fatalf("expected NOT AR equity: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindInvestmentPortfolio, KindCustodyProof,
		KindFinancialStatement, KindPremiumReport,
		KindClaimReport, KindReserveReport,
		KindCyberPolicyReport, KindReinsuranceTreaty,
		KindARTClaimRecord, KindFilingReceipt,
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

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindInvestmentPortfolio,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "30",
		ClienteCuitSuffix4:  "5678",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.HasInvestmentPortfolio {
		t.Fatal("portfolio kind must auto-flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + cliente = exposure")
	}
}

func TestAnnotateInstitutionalPIIRisk(t *testing.T) {
	r := Row{
		ArtifactKind:         KindARTClaimRecord,
		TrabajadorCuilPrefix: "27",
		FileMode:             0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasTrabajadorCuil {
		t.Fatal("trabajador CUIL must flag")
	}
	if !r.IsInstitutionalPIIRisk {
		t.Fatal("readable + ART + trabajador CUIL = institutional PII risk")
	}
}

func TestAnnotateCyberPolicyAuto(t *testing.T) {
	r := Row{ArtifactKind: KindCyberPolicyReport}
	AnnotateSecurity(&r)
	if !r.HasCyberPolicyReport {
		t.Fatal("cyber kind must flag")
	}
}

func TestAnnotateReinsuranceAuto(t *testing.T) {
	r := Row{ArtifactKind: KindReinsuranceTreaty}
	AnnotateSecurity(&r)
	if !r.HasReinsuranceTreaty {
		t.Fatal("reinsurance kind must flag")
	}
}

func TestAnnotateInstitutionalPortfolio(t *testing.T) {
	r := Row{
		ArtifactKind:              KindInvestmentPortfolio,
		PortfolioInstrumentsCount: InstitutionalPortfolioInstrumentsThreshold + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasInstitutionalPortfolio {
		t.Fatal("> 100 instruments must flag institutional portfolio")
	}
}

func TestParseInvestmentPortfolio(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<SSN_Inversiones>
  <ssn_entity_code>10342</ssn_entity_code>
  <Position>
    <especie>AL30</especie>
    <cantidad>1000000</cantidad>
  </Position>
  <Position>
    <especie>GD30</especie>
    <cantidad>500000</cantidad>
  </Position>
  <Position>
    <especie>GGAL</especie>
    <cantidad>250000</cantidad>
  </Position>
  <Position>
    <especie>AAPL</especie>
    <cantidad>100</cantidad>
  </Position>
  <portfolio_total>5000000000</portfolio_total>
  <LimitBreach>true</LimitBreach>
  <cliente_cuit>30-71234567-8</cliente_cuit>
</SSN_Inversiones>`)
	f := ParseInvestmentPortfolio(body)
	if f.PortfolioInstrumentsCount != 4 {
		t.Fatalf("instruments=%d want 4", f.PortfolioInstrumentsCount)
	}
	if f.SovBondPositionCount < 2 {
		t.Fatalf("sov=%d want >=2 (AL30+GD30)", f.SovBondPositionCount)
	}
	if f.EquityPositionCount < 1 {
		t.Fatalf("equity=%d want >=1 (GGAL)", f.EquityPositionCount)
	}
	if f.CEDEARPositionCount < 1 {
		t.Fatalf("cedear=%d want >=1 (AAPL)", f.CEDEARPositionCount)
	}
	if f.SSNEntityCode != "10342" {
		t.Fatalf("entity=%q", f.SSNEntityCode)
	}
	if !f.HasLimitBreach {
		t.Fatal("limit breach must flag")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cuit must extract")
	}
}

func TestParseARTClaim(t *testing.T) {
	body := []byte(`Fecha,Trabajador,Importe,Estado
15/06/2026,27-11111111-4,150000,Pagado
16/06/2026,20-22222222-3,200000,Pagado
17/06/2026,23-33333333-4,180000,Pendiente
trabajador_cuil: 27-11111111-4
`)
	f := ParseARTClaim(body)
	if f.ClaimCount < 3 {
		t.Fatalf("claims=%d", f.ClaimCount)
	}
	if f.LineOfBusiness != LOBRiesgosTrabajo {
		t.Fatalf("LOB=%q want riesgos-del-trabajo", f.LineOfBusiness)
	}
	if f.TrabajadorCuilRaw == "" {
		t.Fatal("trabajador CUIL must extract")
	}
}

func TestParseReinsuranceTreaty(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<ReinsuranceTreaty>
  <Reinsurer>Munich Re</Reinsurer>
  <reinsurer_country>DE</reinsurer_country>
  <Premium>50000000</Premium>
</ReinsuranceTreaty>`)
	f := ParseReinsuranceTreaty(body)
	if !f.HasCrossBorderReinsurance {
		t.Fatal("non-AR reinsurer must flag cross-border")
	}
	if f.LineOfBusiness != LOBReaseguro {
		t.Fatalf("LOB=%q want reaseguro", f.LineOfBusiness)
	}
}

func TestParseCyberPolicyReport(t *testing.T) {
	body := []byte(`Fecha,Cuenta,Suma_Asegurada,Prima
15/06/2026,12345,10000000,150000
16/06/2026,12346,5000000,75000
rama: cyber
`)
	f := ParseCyberPolicyReport(body)
	if f.LineOfBusiness != LOBCyber {
		t.Fatalf("LOB=%q want cyber", f.LineOfBusiness)
	}
	if f.ClaimCount < 2 {
		t.Fatalf("rows=%d", f.ClaimCount)
	}
}

func TestDetectLineOfBusiness(t *testing.T) {
	cases := map[string]LineOfBusiness{
		"vida individual":       LOBVidaIndividual,
		"vida colectivo":        LOBVidaColectivo,
		"automotor":             LOBAutomotor,
		"caución":               LOBCaucion,
		"responsabilidad civil": LOBRespCivil,
		"riesgos del trabajo":   LOBRiesgosTrabajo,
		"reaseguro":             LOBReaseguro,
		"cyber":                 LOBCyber,
		"unknown":               LOBUnknown,
	}
	for in, want := range cases {
		got := detectLineOfBusiness(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyInsurer(t *testing.T) {
	if got := classifyInsurer(Row{HasFilingReceipt: true}); got != InsurerComplianceOfficer {
		t.Fatalf("receipt -> compliance, got %q", got)
	}
	if got := classifyInsurer(Row{HasARTClaimRecord: true}); got != InsurerART {
		t.Fatalf("art -> art-insurer, got %q", got)
	}
	if got := classifyInsurer(Row{HasReinsuranceTreaty: true}); got != InsurerReinsurer {
		t.Fatalf("reinsurance -> reinsurer, got %q", got)
	}
	if got := classifyInsurer(Row{LineOfBusiness: LOBVidaIndividual}); got != InsurerLife {
		t.Fatalf("vida -> life, got %q", got)
	}
	if got := classifyInsurer(Row{LineOfBusiness: LOBAutomotor}); got != InsurerNonLife {
		t.Fatalf("automotor -> non-life, got %q", got)
	}
	if got := classifyInsurer(Row{LineOfBusiness: LOBSalud}); got != InsurerHealth {
		t.Fatalf("salud -> health, got %q", got)
	}
	if got := classifyInsurer(Row{HasReserveReport: true}); got != InsurerActuary {
		t.Fatalf("reserve -> actuary, got %q", got)
	}
	if got := classifyInsurer(Row{ArtifactKind: KindConfig}); got != InsurerAPI {
		t.Fatalf("config -> api, got %q", got)
	}
	if got := classifyInsurer(Row{}); got != InsurerUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyPortfolio(t *testing.T) {
	if got := classifyPortfolio(Row{SovBondPositionCount: 5, EquityPositionCount: 3}); got != PortfolioMultiAsset {
		t.Fatalf("multi -> multi-asset, got %q", got)
	}
	if got := classifyPortfolio(Row{SovBondPositionCount: 5}); got != PortfolioARSovBond {
		t.Fatalf("sov -> ar-sovereign-bond, got %q", got)
	}
	if got := classifyPortfolio(Row{FCIPositionCount: 3}); got != PortfolioARFCI {
		t.Fatalf("fci -> ar-fci, got %q", got)
	}
	if got := classifyPortfolio(Row{EquityPositionCount: 3}); got != PortfolioAREquity {
		t.Fatalf("equity -> ar-equity, got %q", got)
	}
	if got := classifyPortfolio(Row{CEDEARPositionCount: 3}); got != PortfolioCEDEAR {
		t.Fatalf("cedear -> cedear, got %q", got)
	}
	if got := classifyPortfolio(Row{}); got != PortfolioUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	ssnDir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "SSN")
	invDir := filepath.Join(ssnDir, "inversiones")
	artDir := filepath.Join(ssnDir, "art")
	receiptDir := filepath.Join(ssnDir, "receipt")
	must(t, os.MkdirAll(invDir, 0o755))
	must(t, os.MkdirAll(artDir, 0o755))
	must(t, os.MkdirAll(receiptDir, 0o755))

	invPath := filepath.Join(invDir, "inversiones_202606.xml")
	must(t, os.WriteFile(invPath, []byte(`<?xml version="1.0"?>
<SSN_Inversiones>
  <ssn_entity_code>10342</ssn_entity_code>
  <Position><especie>AL30</especie></Position>
  <Position><especie>GD30</especie></Position>
  <Position><especie>GGAL</especie></Position>
  <cliente_cuit>30-71234567-8</cliente_cuit>
</SSN_Inversiones>`), 0o644))

	artPath := filepath.Join(artDir, "art_claim_202606.csv")
	must(t, os.WriteFile(artPath, []byte(`Fecha,Trabajador,Importe,Estado
15/06/2026,27-11111111-4,150000,Pagado
16/06/2026,20-22222222-3,200000,Pagado
trabajador_cuil: 27-11111111-4
`), 0o644))

	receiptPath := filepath.Join(receiptDir, "ssn_receipt_202606.xml")
	must(t, os.WriteFile(receiptPath, []byte(`<?xml version="1.0"?>
<Receipt>
  <ssn_receipt>SSN-2026-001234</ssn_receipt>
</Receipt>`), 0o644))

	must(t, os.WriteFile(filepath.Join(invDir, "random.txt"),
		[]byte(`nope`), 0o644))

	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "SSN")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "inversiones_202606.xml"),
		[]byte(`<SSN_Inversiones/>`), 0o644))

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
		t.Fatalf("want 3 (inv+art+receipt), got %d: %+v", len(got), got)
	}

	var inv, art, receipt Row
	for _, r := range got {
		switch r.FilePath {
		case invPath:
			inv = r
		case artPath:
			art = r
		case receiptPath:
			receipt = r
		}
	}

	if inv.ArtifactKind != KindInvestmentPortfolio {
		t.Fatalf("inv kind=%q", inv.ArtifactKind)
	}
	if !inv.HasInvestmentPortfolio {
		t.Fatalf("inv must flag portfolio: %+v", inv)
	}
	if inv.SovBondPositionCount < 2 {
		t.Fatalf("inv sov=%d", inv.SovBondPositionCount)
	}
	if inv.SSNEntityCode != "10342" {
		t.Fatalf("inv entity=%q", inv.SSNEntityCode)
	}
	if inv.PortfolioClass != PortfolioMultiAsset {
		t.Fatalf("inv should be multi-asset, got %q", inv.PortfolioClass)
	}
	if !inv.HasClienteCuit {
		t.Fatalf("inv must flag cliente cuit: %+v", inv)
	}
	if !inv.IsInstitutionalPIIRisk {
		t.Fatalf("inv must flag institutional PII (cuit + portfolio + readable): %+v", inv)
	}

	if art.ArtifactKind != KindARTClaimRecord {
		t.Fatalf("art kind=%q", art.ArtifactKind)
	}
	if !art.HasARTClaimRecord {
		t.Fatalf("art must flag: %+v", art)
	}
	if !art.HasTrabajadorCuil {
		t.Fatalf("art must flag trabajador CUIL: %+v", art)
	}
	if art.InsurerClass != InsurerART {
		t.Fatalf("art should classify as art-insurer, got %q", art.InsurerClass)
	}
	if !art.IsInstitutionalPIIRisk {
		t.Fatalf("art must flag institutional PII (cuil + art + readable): %+v", art)
	}

	if receipt.ArtifactKind != KindFilingReceipt {
		t.Fatalf("receipt kind=%q", receipt.ArtifactKind)
	}
	if !receipt.HasFilingReceipt {
		t.Fatalf("receipt must flag: %+v", receipt)
	}
	if receipt.InsurerClass != InsurerComplianceOfficer {
		t.Fatalf("receipt should classify as compliance-officer, got %q", receipt.InsurerClass)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-ssn")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "ssn_config.ini"),
		[]byte(`[SSN]
ssn_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "SSN_DIR" {
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
		installRoots: []string{"/nope-ssn"},
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
		{FilePath: "/b", ArtifactKind: KindInvestmentPortfolio},
		{FilePath: "/a", ArtifactKind: KindClaimReport},
		{FilePath: "/a", ArtifactKind: KindInvestmentPortfolio},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindClaimReport {
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
