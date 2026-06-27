package winargallaria

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "allaria-config"},
		{string(KindCredentials), "allaria-credentials"},
		{string(KindPositionsCache), "allaria-positions-cache"},
		{string(KindOrdersCache), "allaria-orders-cache"},
		{string(KindBlockTrade), "allaria-block-trade"},
		{string(KindCustodyReport), "allaria-custody-report"},
		{string(KindCustodyRecon), "allaria-custody-recon"},
		{string(KindANSeSFlows), "allaria-anses-flows"},
		{string(KindSSNHoldings), "allaria-ssn-holdings"},
		{string(KindInstaller), "allaria-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountInstitutional), "institutional"},
		{string(AccountPensionFund), "pension-fund"},
		{string(AccountInsurance), "insurance"},
		{string(AccountFCIManager), "fci-manager"},
		{string(AccountFamilyOffice), "family-office"},
		{string(AccountCorporateTreasury), "corporate-treasury"},
		{string(AccountRetailPlus), "retail-plus"},
		{string(AccountAPI), "api"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"allaria_config.xml",
		"alinvest_credentials.json",
		"al_invest_positions.json",
		"block_trade_202506.csv",
		"block-trade-202506.csv",
		"custody_report_202506.xml",
		"custody_recon_202506.xml",
		"anses_flows_202506.csv",
		"ssn_holdings_202506.xml",
		"allaria_installer.msi",
	}
	no := []string{"", "factura.xml", "random.txt", "report.pdf"}
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
		"allaria_config.xml":            KindConfig,
		"alinvest_settings.json":        KindConfig,
		"allaria_credentials.json":      KindCredentials,
		"allaria_api_token.json":        KindCredentials,
		"allaria_positions_202506.json": KindPositionsCache,
		"allaria_orders_202506.json":    KindOrdersCache,
		"block_trade_202506.csv":        KindBlockTrade,
		"blocktrade_book.csv":           KindBlockTrade,
		"custody_report_202506.xml":     KindCustodyReport,
		"custody_recon_202506.xml":      KindCustodyRecon,
		"anses_flows_202506.csv":        KindANSeSFlows,
		"ssn_holdings_202506.xml":       KindSSNHoldings,
		"allaria_installer.msi":         KindInstaller,
		"":                              KindUnknown,
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

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("block_trade_202506.csv") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.csv") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsCERUVASymbol(t *testing.T) {
	yes := []string{"CER", "UVA", "TX26", "TC27", "T2X5", "BONCER", "DICP"}
	no := []string{"", "GGAL", "AAPL", "DLR"}
	for _, v := range yes {
		if !IsCERUVASymbol(v) {
			t.Fatalf("expected CER/UVA: %q", v)
		}
	}
	for _, v := range no {
		if IsCERUVASymbol(v) {
			t.Fatalf("expected NOT CER/UVA: %q", v)
		}
	}
}

func TestIsLetraSymbol(t *testing.T) {
	yes := []string{
		"LECAP", "BONCER", "S29M6", "AL30", "GD30",
		"BOPREAL", "TX26", "AY24",
	}
	no := []string{"", "GGAL", "AAPL", "DLR"}
	for _, v := range yes {
		if !IsLetraSymbol(v) {
			t.Fatalf("expected letra: %q", v)
		}
	}
	for _, v := range no {
		if IsLetraSymbol(v) {
			t.Fatalf("expected NOT letra: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindPositionsCache,
		KindOrdersCache, KindBlockTrade, KindCustodyReport,
		KindCustodyRecon, KindANSeSFlows, KindSSNHoldings,
	}
	no := []ArtifactKind{KindInstaller, KindOther, KindUnknown}
	for _, k := range yes {
		if !IsCredentialKind(k) {
			t.Fatalf("expected cred kind: %q", k)
		}
	}
	for _, k := range no {
		if IsCredentialKind(k) {
			t.Fatalf("expected NOT cred kind: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:       KindCredentials,
		HasBearerToken:     true,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + bearer + cliente = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:   KindCredentials,
		HasBearerToken: true,
		FileMode:       0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateBlockTradeDisclosure(t *testing.T) {
	r := Row{
		ArtifactKind:          KindBlockTrade,
		BlockTradeCount:       3,
		BlockTradeMaxUSDCents: 200_000_000,
	}
	AnnotateSecurity(&r)
	if !r.HasBlockTrade {
		t.Fatal("block-trade count must flag")
	}
	if !r.HasDisclosureObligation {
		t.Fatal("block > USD 1 M must flag disclosure")
	}
}

func TestAnnotateCustodyRecon(t *testing.T) {
	r := Row{ArtifactKind: KindCustodyRecon}
	AnnotateSecurity(&r)
	if !r.HasFCICustodyRecon {
		t.Fatal("custody-recon kind must auto-flag")
	}
	if !r.HasCustodyBankRole {
		t.Fatal("recon implies custody-bank role")
	}
}

func TestAnnotatePensionFund(t *testing.T) {
	r := Row{ArtifactKind: KindANSeSFlows, PensionFundCount: 1}
	AnnotateSecurity(&r)
	if !r.HasPensionFundAccount {
		t.Fatal("pension-fund must flag")
	}
}

func TestAnnotateInsurance(t *testing.T) {
	r := Row{ArtifactKind: KindSSNHoldings, InsuranceCount: 1}
	AnnotateSecurity(&r)
	if !r.HasInsuranceAccount {
		t.Fatal("insurance must flag")
	}
}

func TestAnnotateHighAUM(t *testing.T) {
	r := Row{
		ArtifactKind:         KindCustodyReport,
		PortfolioAUMUSDCents: 5_000_000_000,
	}
	AnnotateSecurity(&r)
	if !r.HasHighAUMInstitutional {
		t.Fatal("USD 50 M AUM must flag institutional")
	}
}

func TestAnnotateCERUVAAndLetras(t *testing.T) {
	r := Row{
		ArtifactKind:        KindCustodyReport,
		CERUVAPositionCount: 2,
		LetrasPositionCount: 3,
	}
	AnnotateSecurity(&r)
	if !r.HasCERUVAHoldings {
		t.Fatal("CER/UVA must flag")
	}
	if !r.HasLetrasTesoro {
		t.Fatal("Letras must flag")
	}
}

func TestParseAllariaCredentials(t *testing.T) {
	body := []byte(`<Allaria>
<matricula>117</matricula>
<access_token>aBcDeFgHiJkLmNoPqRsTuVwX12345</access_token>
<username>alice@allaria.com.ar</username>
<password>secret123</password>
<cliente_cuit>30-71234567-8</cliente_cuit>
</Allaria>`)
	f := ParseAllariaCredentials(body)
	if f.BearerToken == "" {
		t.Fatal("bearer must extract")
	}
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
	if f.BrokerMatricula != "117" {
		t.Fatalf("matricula=%q", f.BrokerMatricula)
	}
}

func TestParseAllariaBlockTradeCSV(t *testing.T) {
	body := []byte(`block_id,trade_id,symbol,notional_usd,counterparty
1,B-001,AL30,5000000.00,30-71234567-8
2,B-002,GD30,3000000.00,30-99999999-1
3,B-003,GGAL,2000000.00,30-71234567-8
`)
	f := ParseAllariaBlockTrade(body)
	if f.BlockTradeCount < 3 {
		t.Fatalf("blocks=%d want >=3", f.BlockTradeCount)
	}
	if f.BlockTradeMaxUSDCents != 500_000_000 {
		t.Fatalf("max=%d want 500_000_000", f.BlockTradeMaxUSDCents)
	}
	if f.PortfolioAUMUSDCents < 1_000_000_000 {
		t.Fatalf("volume=%d", f.PortfolioAUMUSDCents)
	}
}

func TestParseAllariaCustodyRecon(t *testing.T) {
	body := []byte(`<custody_recon>
<sociedad_depositaria>Allaria Ledesma</sociedad_depositaria>
<recon_id>R-001</recon_id>
<fci_id>BALANZ_AHORRO</fci_id>
<recon_id>R-002</recon_id>
<fci_id>COCOS_RV_AR</fci_id>
</custody_recon>`)
	f := ParseAllariaCustodyRecon(body)
	if f.FCICustodyReconCount < 2 {
		t.Fatalf("recon=%d", f.FCICustodyReconCount)
	}
}

func TestParseAllariaANSeSFlows(t *testing.T) {
	body := []byte(`anses_flow_202506,ANSeS_FGS,LECAP,importe_usd=10000000.00
anses_flow_202506,FCAA,BONCER,importe_usd=5000000.00
`)
	f := ParseAllariaANSeSFlows(body)
	if f.PensionFundCount < 1 {
		t.Fatalf("pension=%d", f.PensionFundCount)
	}
	if f.LetrasPositionCount < 2 {
		t.Fatalf("letras=%d", f.LetrasPositionCount)
	}
}

func TestParseAllariaSSNHoldings(t *testing.T) {
	body := []byte(`<ssn_holdings>
<aseguradora>La Caja</aseguradora>
<resol_38708>true</resol_38708>
<symbol>TX26</symbol>
<importe_usd>3000000.00</importe_usd>
</ssn_holdings>`)
	f := ParseAllariaSSNHoldings(body)
	if f.InsuranceCount < 1 {
		t.Fatalf("insurance=%d", f.InsuranceCount)
	}
	if f.CERUVAPositionCount < 1 {
		t.Fatalf("cer/uva=%d", f.CERUVAPositionCount)
	}
}

func TestParseAllariaEmpty(t *testing.T) {
	f := ParseAllariaCredentials(nil)
	if f.BearerToken != "" || f.HasPassword {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "Allaria")
	must(t, os.MkdirAll(filepath.Join(dir, "books"), 0o755))

	cfgPath := filepath.Join(dir, "allaria_config.xml")
	must(t, os.WriteFile(cfgPath, []byte(`<Allaria>
<matricula>117</matricula>
<access_token>aBcDeFgHiJkLmNoPqRsTuVwX12345</access_token>
<password>secret123</password>
<cliente_cuit>30-71234567-8</cliente_cuit>
</Allaria>`), 0o644))

	blockPath := filepath.Join(dir, "books", "block_trade_202506.csv")
	must(t, os.WriteFile(blockPath, []byte(`block_id,trade_id,symbol,notional_usd,counterparty
1,B-001,AL30,5000000.00,30-71234567-8
2,B-002,GD30,3000000.00,30-99999999-1
`), 0o644))

	reconPath := filepath.Join(dir, "books", "custody_recon_202506.xml")
	must(t, os.WriteFile(reconPath, []byte(`<custody_recon>
<sociedad_depositaria>Allaria Ledesma</sociedad_depositaria>
<recon_id>R-001</recon_id>
<fci_id>BALANZ_AHORRO</fci_id>
</custody_recon>`), 0o644))

	ansesPath := filepath.Join(dir, "books", "anses_flows_202506.csv")
	must(t, os.WriteFile(ansesPath, []byte(`ANSeS_FGS,LECAP,importe_usd=10000000.00
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "Allaria")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "allaria_config.xml"),
		[]byte(`<x/>`), 0o644))

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
		t.Fatalf("want 4 (cfg+block+recon+anses), got %d: %+v", len(got), got)
	}

	var cfg, block, recon, anses Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case blockPath:
			block = r
		case reconPath:
			recon = r
		case ansesPath:
			anses = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasBearerToken {
		t.Fatalf("cfg must flag bearer: %+v", cfg)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if cfg.BrokerMatricula != "117" {
		t.Fatalf("cfg matricula=%q", cfg.BrokerMatricula)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + bearer + password = exposure: %+v", cfg)
	}

	if block.ArtifactKind != KindBlockTrade {
		t.Fatalf("block kind=%q", block.ArtifactKind)
	}
	if !block.HasBlockTrade {
		t.Fatalf("block must flag: %+v", block)
	}
	if !block.HasDisclosureObligation {
		t.Fatalf("USD 5 M block must trigger disclosure: %+v", block)
	}
	if block.AccountClass != AccountInstitutional {
		t.Fatalf("block account=%q want institutional", block.AccountClass)
	}

	if recon.ArtifactKind != KindCustodyRecon {
		t.Fatalf("recon kind=%q", recon.ArtifactKind)
	}
	if !recon.HasFCICustodyRecon {
		t.Fatalf("recon must flag: %+v", recon)
	}
	if !recon.HasCustodyBankRole {
		t.Fatalf("recon implies custody-bank role: %+v", recon)
	}
	if recon.AccountClass != AccountFCIManager {
		t.Fatalf("recon account=%q want fci-manager", recon.AccountClass)
	}

	if anses.ArtifactKind != KindANSeSFlows {
		t.Fatalf("anses kind=%q", anses.ArtifactKind)
	}
	if !anses.HasPensionFundAccount {
		t.Fatalf("anses must flag: %+v", anses)
	}
	if !anses.HasLetrasTesoro {
		t.Fatalf("LECAP must flag letras: %+v", anses)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-allaria")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "allaria_config.xml"),
		[]byte(`<Allaria><matricula>117</matricula></Allaria>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "ALLARIA_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindConfig {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-allaria"},
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
		{FilePath: "z", ArtifactKind: KindConfig},
		{FilePath: "a", ArtifactKind: KindBlockTrade},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	// At "a", "allaria-block-trade" < "allaria-config" alphabetically.
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindBlockTrade {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("abc")
	b := HashSecret("abc")
	c := HashSecret("ABC")
	if a != b {
		t.Fatal("hash drift")
	}
	if a != c {
		t.Fatal("hash must be case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func TestClassifyAccount(t *testing.T) {
	if classifyAccount(Row{ArtifactKind: KindANSeSFlows}, AllariaFields{PensionFundCount: 1}) != AccountPensionFund {
		t.Fatal("anses -> pension-fund")
	}
	if classifyAccount(Row{ArtifactKind: KindSSNHoldings}, AllariaFields{InsuranceCount: 1}) != AccountInsurance {
		t.Fatal("ssn -> insurance")
	}
	if classifyAccount(Row{ArtifactKind: KindCustodyRecon}, AllariaFields{}) != AccountFCIManager {
		t.Fatal("custody-recon -> fci-manager")
	}
	if classifyAccount(Row{}, AllariaFields{PortfolioAUMUSDCents: InstitutionalAUMUSDCents}) != AccountInstitutional {
		t.Fatal("high aum -> institutional")
	}
	if classifyAccount(Row{ArtifactKind: KindBlockTrade}, AllariaFields{BlockTradeCount: 1}) != AccountInstitutional {
		t.Fatal("block trade -> institutional")
	}
	if classifyAccount(Row{HasPasswordInConfig: true}, AllariaFields{}) != AccountRetailPlus {
		t.Fatal("password -> retail-plus")
	}
	if classifyAccount(Row{}, AllariaFields{}) != AccountUnknown {
		t.Fatal("unknown")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
