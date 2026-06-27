package winargppi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "ppi-config"},
		{string(KindCredentials), "ppi-credentials"},
		{string(KindPositionsCache), "ppi-positions-cache"},
		{string(KindOrdersCache), "ppi-orders-cache"},
		{string(KindWealthPortfolio), "ppi-wealth-portfolio"},
		{string(KindCorporateTreasury), "ppi-corporate-treasury"},
		{string(KindPerfilInversor), "ppi-perfil-inversor"},
		{string(KindQuantScript), "ppi-quant-script"},
		{string(KindInternacional), "ppi-internacional"},
		{string(KindAccountExport), "ppi-account-export"},
		{string(KindTaxStatement), "ppi-tax-statement"},
		{string(KindInstaller), "ppi-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountRetail), "retail"},
		{string(AccountWealth), "wealth"},
		{string(AccountPrivateBanking), "private-banking"},
		{string(AccountCorporateTreasury), "corporate-treasury"},
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
		"ppi_config.json",
		"ppi_credentials.json",
		"ppi_positions_202506.json",
		"ppi_orders_202506.json",
		"wealth_portfolio.json",
		"ppi_wealth.json",
		"cuenta_empresa.json",
		"perfil_inversor.json",
		"ppi_internacional_202506.json",
		"ppi-quant-strategy.py",
		"portfolio_personal_export.csv",
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
		"ppi_config.json":               KindConfig,
		"ppi_credentials.json":          KindCredentials,
		"ppi_api_key.json":              KindCredentials,
		"ppi_positions_202506.json":     KindPositionsCache,
		"ppi_orders_202506.json":        KindOrdersCache,
		"wealth_portfolio.json":         KindWealthPortfolio,
		"ppi_wealth_2026.json":          KindWealthPortfolio,
		"cuenta_empresa.json":           KindCorporateTreasury,
		"perfil_inversor.json":          KindPerfilInversor,
		"ppi-quant-strategy.py":         KindQuantScript,
		"ppi_internacional_202506.json": KindInternacional,
		"ppi_extracto_202506.xlsx":      KindAccountExport,
		"ppi_bienes_personales.xlsx":    KindTaxStatement,
		"ppi_installer.msi":             KindInstaller,
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
	if PeriodFromFilename("ppi_positions_202506.json") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.json") != "" {
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

func TestIsUSEquityCEDEAR(t *testing.T) {
	yes := []string{"AAPL", "MSFT", "GOOGL", "TSLA", "BABA"}
	no := []string{"", "GGAL", "YPFD", "DLR"}
	for _, v := range yes {
		if !IsUSEquityCEDEAR(v) {
			t.Fatalf("expected CEDEAR: %q", v)
		}
	}
	for _, v := range no {
		if IsUSEquityCEDEAR(v) {
			t.Fatalf("expected NOT CEDEAR: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindPositionsCache,
		KindOrdersCache, KindWealthPortfolio,
		KindCorporateTreasury, KindPerfilInversor,
		KindQuantScript, KindInternacional,
		KindAccountExport, KindTaxStatement,
	}
	no := []ArtifactKind{
		KindInstaller, KindOther, KindUnknown,
	}
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

func TestAnnotatePerfilInversor(t *testing.T) {
	r := Row{ArtifactKind: KindPerfilInversor}
	AnnotateSecurity(&r)
	if !r.HasPerfilInversor {
		t.Fatal("perfil-inversor kind must auto-flag")
	}
}

func TestAnnotateWealth(t *testing.T) {
	r := Row{ArtifactKind: KindWealthPortfolio}
	AnnotateSecurity(&r)
	if !r.HasWealthPortfolio {
		t.Fatal("wealth kind must auto-flag")
	}
}

func TestAnnotateCorporateTreasury(t *testing.T) {
	r := Row{ArtifactKind: KindCorporateTreasury}
	AnnotateSecurity(&r)
	if !r.HasCorporateTreasury {
		t.Fatal("corp-treasury kind must auto-flag")
	}
}

func TestAnnotateInternational(t *testing.T) {
	r := Row{ArtifactKind: KindInternacional}
	AnnotateSecurity(&r)
	if !r.HasInternationalAssets {
		t.Fatal("internacional kind must auto-flag")
	}
}

func TestAnnotateQuant(t *testing.T) {
	r := Row{ArtifactKind: KindQuantScript}
	AnnotateSecurity(&r)
	if !r.HasQuantStrategy {
		t.Fatal("quant-script kind must auto-flag")
	}
}

func TestAnnotateCERUVA(t *testing.T) {
	r := Row{
		ArtifactKind:        KindPositionsCache,
		CERUVAPositionCount: 3,
	}
	AnnotateSecurity(&r)
	if !r.HasCERUVAHoldings {
		t.Fatal("CER/UVA count must flag")
	}
}

func TestAnnotateHighAUM(t *testing.T) {
	r := Row{
		ArtifactKind:         KindWealthPortfolio,
		PortfolioAUMUSDCents: 50_000_000,
	}
	AnnotateSecurity(&r)
	if !r.HasHighAUM {
		t.Fatal("USD 500 K AUM must flag high")
	}
}

func TestParsePPICredentials(t *testing.T) {
	body := []byte(`{
"endpoint": "https://api.portfoliopersonal.com",
"access_token": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
"galicia_sso": "bgssoTokenAbCdEfGhIjKlMn123456",
"username": "alice@ppi.com.ar",
"password": "secret123",
"cliente_cuit": "27-11111111-4"
}`)
	f := ParsePPICredentials(body)
	if f.BearerToken == "" {
		t.Fatal("bearer must extract")
	}
	if f.GaliciaSSO == "" {
		t.Fatal("galicia SSO must extract")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParsePPIPositionsCERUVA(t *testing.T) {
	body := []byte(`{
"positions": [
{ "symbol": "GGAL" },
{ "symbol": "YPFD" },
{ "symbol": "TX26" },
{ "symbol": "UVA" },
{ "symbol": "AAPL" }
],
"cliente_cuit": "27-11111111-4"
}`)
	f := ParsePPIPositions(body)
	if f.DistinctSymbols < 5 {
		t.Fatalf("distinct=%d", f.DistinctSymbols)
	}
	if f.CERUVACount < 2 {
		t.Fatalf("cer/uva=%d", f.CERUVACount)
	}
	if f.InternationalCount < 1 {
		t.Fatalf("international=%d", f.InternationalCount)
	}
}

func TestParsePPIWealthPortfolio(t *testing.T) {
	body := []byte(`{
"product": "ppi_wealth",
"managed_portfolio": true,
"aum_usd": 250000.00,
"positions": [{"symbol":"AAPL"},{"symbol":"MSFT"}]
}`)
	f := ParsePPIWealthPortfolio(body)
	if !f.HasWealthMarker {
		t.Fatal("wealth marker must flag")
	}
	if f.PortfolioAUMUSDCents != 25_000_000 {
		t.Fatalf("aum=%d want 25_000_000", f.PortfolioAUMUSDCents)
	}
	if f.InternationalCount < 2 {
		t.Fatalf("international=%d", f.InternationalCount)
	}
}

func TestParsePPICorporateTreasury(t *testing.T) {
	body := []byte(`{
"product": "cuenta_empresa",
"persona_juridica": true,
"cuit_empresa": "30-71234567-8"
}`)
	f := ParsePPICorporateTreasury(body)
	if !f.HasCorporateMarker {
		t.Fatal("corporate marker must flag")
	}
}

func TestParsePPIPerfilInversor(t *testing.T) {
	body := []byte(`<perfil_inversor>
<cliente_cuit>27-11111111-4</cliente_cuit>
<tolerancia_al_riesgo>moderada</tolerancia_al_riesgo>
<horizonte_temporal>5 años</horizonte_temporal>
<objetivo_inversion>preservar capital</objetivo_inversion>
</perfil_inversor>`)
	f := ParsePPIPerfilInversor(body)
	if !f.HasPerfilInversorMarker {
		t.Fatal("perfil-inversor marker must flag")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParsePPIQuantScript(t *testing.T) {
	body := []byte(`from ppi_quant import Client
client = Client(api_token="aBcDeFgHiJkLmNoPqRsTuVwXyZ12345", password="hardcoded123")
`)
	f := ParsePPIQuantScript(body)
	if !f.HasQuantImport {
		t.Fatal("ppi_quant import must flag")
	}
	if !f.HasPassword {
		t.Fatal("hardcoded password must flag")
	}
	if f.BearerToken == "" {
		t.Fatal("api token must extract")
	}
}

func TestParsePPIInternacional(t *testing.T) {
	body := []byte(`{
"product": "ppi_internacional",
"us_equity": true,
"positions": [
{"symbol":"AAPL","value_usd":50000.00},
{"symbol":"MSFT","value_usd":30000.00},
{"symbol":"GOOGL","value_usd":20000.00}
]
}`)
	f := ParsePPIInternacional(body)
	if !f.HasInternacionalMarker {
		t.Fatal("internacional marker must flag")
	}
	if f.InternationalCount < 3 {
		t.Fatalf("international=%d", f.InternationalCount)
	}
}

func TestParsePPIEmpty(t *testing.T) {
	f := ParsePPICredentials(nil)
	if f.BearerToken != "" || f.HasPassword {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "PPI")
	must(t, os.MkdirAll(filepath.Join(dir, "cache"), 0o755))

	cfgPath := filepath.Join(dir, "ppi_credentials.json")
	must(t, os.WriteFile(cfgPath, []byte(`{
"endpoint": "https://api.portfoliopersonal.com",
"access_token": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
"galicia_sso": "bgssoTokenAbCdEfGhIjKlMn123456",
"username": "alice@ppi.com.ar",
"cliente_cuit": "27-11111111-4"
}`), 0o644))

	wealthPath := filepath.Join(dir, "cache", "wealth_portfolio.json")
	must(t, os.WriteFile(wealthPath, []byte(`{
"product": "ppi_wealth",
"managed_portfolio": true,
"aum_usd": 250000.00,
"positions": [{"symbol":"TX26"},{"symbol":"AAPL"}]
}`), 0o644))

	perfilPath := filepath.Join(dir, "perfil_inversor.json")
	must(t, os.WriteFile(perfilPath, []byte(`<perfil_inversor>
<cliente_cuit>27-11111111-4</cliente_cuit>
<tolerancia_al_riesgo>moderada</tolerancia_al_riesgo>
</perfil_inversor>`), 0o644))

	internacionalPath := filepath.Join(dir, "cache", "ppi_internacional_202506.json")
	must(t, os.WriteFile(internacionalPath, []byte(`{
"product": "ppi_internacional",
"positions": [{"symbol":"AAPL","value_usd":50000.00}]
}`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "PPI")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "ppi_credentials.json"),
		[]byte(`{"x":1}`), 0o644))

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
		t.Fatalf("want 4 (cfg+wealth+perfil+internacional), got %d: %+v", len(got), got)
	}

	var cfg, wealth, perfil, intl Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case wealthPath:
			wealth = r
		case perfilPath:
			perfil = r
		case internacionalPath:
			intl = r
		}
	}

	if cfg.ArtifactKind != KindCredentials {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasBearerToken {
		t.Fatalf("cfg must flag bearer: %+v", cfg)
	}
	if !cfg.HasGaliciaSSO {
		t.Fatalf("cfg must flag galicia SSO: %+v", cfg)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + bearer + galicia + cliente = exposure: %+v", cfg)
	}

	if wealth.ArtifactKind != KindWealthPortfolio {
		t.Fatalf("wealth kind=%q", wealth.ArtifactKind)
	}
	if !wealth.HasWealthPortfolio {
		t.Fatalf("wealth must flag: %+v", wealth)
	}
	if wealth.PortfolioAUMUSDCents != 25_000_000 {
		t.Fatalf("wealth aum=%d want 25_000_000", wealth.PortfolioAUMUSDCents)
	}
	if !wealth.HasHighAUM {
		t.Fatalf("wealth must flag high AUM: %+v", wealth)
	}
	if !wealth.HasCERUVAHoldings {
		t.Fatalf("wealth must flag CER/UVA (TX26): %+v", wealth)
	}

	if perfil.ArtifactKind != KindPerfilInversor {
		t.Fatalf("perfil kind=%q", perfil.ArtifactKind)
	}
	if !perfil.HasPerfilInversor {
		t.Fatalf("perfil must flag: %+v", perfil)
	}

	if intl.ArtifactKind != KindInternacional {
		t.Fatalf("intl kind=%q", intl.ArtifactKind)
	}
	if !intl.HasInternationalAssets {
		t.Fatalf("intl must flag international: %+v", intl)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-ppi")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "ppi_credentials.json"),
		[]byte(`{"access_token":"abcdefghijklmnopqrst"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "PPI_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindCredentials {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-ppi"},
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
		{FilePath: "a", ArtifactKind: KindPositionsCache},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,ppi-config)", in[0])
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
	if classifyAccount(Row{ArtifactKind: KindQuantScript}, PPIFields{}) != AccountAPI {
		t.Fatal("quant -> api")
	}
	if classifyAccount(Row{ArtifactKind: KindCorporateTreasury}, PPIFields{}) != AccountCorporateTreasury {
		t.Fatal("corp -> corporate-treasury")
	}
	if classifyAccount(Row{ArtifactKind: KindWealthPortfolio}, PPIFields{}) != AccountWealth {
		t.Fatal("wealth")
	}
	if classifyAccount(Row{HasHighAUM: true}, PPIFields{}) != AccountPrivateBanking {
		t.Fatal("high aum -> private-banking")
	}
	if classifyAccount(Row{}, PPIFields{Username: "x"}) != AccountRetail {
		t.Fatal("username -> retail")
	}
	if classifyAccount(Row{}, PPIFields{}) != AccountUnknown {
		t.Fatal("unknown")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
