package winargib

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "ib-config"},
		{string(KindGatewayConfig), "ib-gateway-config"},
		{string(KindCredentials), "ib-credentials"},
		{string(KindTWSSettings), "ib-tws-settings"},
		{string(KindPositions), "ib-positions"},
		{string(KindOrders), "ib-orders"},
		{string(KindStrategyPy), "ib-strategy-py"},
		{string(KindTradeLog), "ib-trade-log"},
		{string(KindFlexQuery), "ib-flex-query"},
		{string(KindTaxStatement), "ib-tax-statement"},
		{string(KindInstaller), "ib-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountRetail), "retail"},
		{string(AccountPro), "pro"},
		{string(AccountInstitutional), "institutional"},
		{string(AccountAPI), "api"},
		{string(AccountPaper), "paper"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(ProductUSEquity), "us-equity"},
		{string(ProductGlobalEquity), "global-equity"},
		{string(ProductFuturesCME), "futures-cme"},
		{string(ProductOptionsCBOE), "options-cboe"},
		{string(ProductForex), "forex"},
		{string(ProductBonds), "bonds"},
		{string(ProductCrypto), "crypto"},
		{string(ProductMultiAsset), "multi-asset"},
		{string(ProductOther), "other"},
		{string(ProductUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPortConstants(t *testing.T) {
	if PortTWSLive != 7496 || PortTWSPaper != 7497 ||
		PortGatewayLive != 4001 || PortGatewayPaper != 4002 {
		t.Fatalf("port constants drift: %d %d %d %d",
			PortTWSLive, PortTWSPaper, PortGatewayLive, PortGatewayPaper)
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"jts.ini",
		"ibgateway_config.ini",
		"ib_gateway_settings.cfg",
		"ibapi_strategy.py",
		"ib_insync_bot.py",
		"twsstart.bat",
		"flex_query_202506.xml",
		"flexquery_202506.csv",
		"tws_settings.xml",
		"ibkr_installer.msi",
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
		"jts.ini":                 KindConfig,
		"ibgateway_config.ini":    KindGatewayConfig,
		"ib_gateway_config.cfg":   KindGatewayConfig,
		"ib-gateway-settings.xml": KindGatewayConfig,
		"tws_settings.xml":        KindTWSSettings,
		"ibapi_credentials.json":  KindCredentials,
		"ib_api_token.json":       KindCredentials,
		"ibapi_strategy.py":       KindStrategyPy,
		"ib_insync_bot.py":        KindStrategyPy,
		"ibkr_quant.ipynb":        KindStrategyPy,
		"ibapi_positions.csv":     KindPositions,
		"ibapi_orders_202506.csv": KindOrders,
		"ibapi_execution.log":     KindTradeLog,
		"flex_query_202506.xml":   KindFlexQuery,
		"flexquery_202506.csv":    KindFlexQuery,
		"ibapi_tax_statement.csv": KindTaxStatement,
		"1099_202506.csv":         KindTaxStatement,
		"ibkr_installer.msi":      KindInstaller,
		"":                        KindUnknown,
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
	if PeriodFromFilename("flex_query_202506.xml") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.xml") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIBAccountSuffix4(t *testing.T) {
	cases := map[string]string{
		"account U1234567 created":          "4567",
		"<ib_account>U9876543</ib_account>": "6543",
		"no account here":                   "",
	}
	for in, want := range cases {
		if got := IBAccountSuffix4(in); got != want {
			t.Fatalf("IBAccountSuffix4(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPortToAccountClass(t *testing.T) {
	cases := map[int]AccountClass{
		PortTWSLive:      AccountRetail,
		PortTWSPaper:     AccountPaper,
		PortGatewayLive:  AccountRetail,
		PortGatewayPaper: AccountPaper,
		1234:             AccountUnknown,
	}
	for port, want := range cases {
		if got := PortToAccountClass(port); got != want {
			t.Fatalf("PortToAccountClass(%d)=%q want %q", port, got, want)
		}
	}
}

func TestIsLivePort(t *testing.T) {
	if !IsLivePort(PortTWSLive) || !IsLivePort(PortGatewayLive) {
		t.Fatal("live ports must flag")
	}
	if IsLivePort(PortTWSPaper) || IsLivePort(PortGatewayPaper) {
		t.Fatal("paper ports must NOT flag live")
	}
}

func TestExchangeMarkers(t *testing.T) {
	if !HasUSEquityMarker([]byte(`{"exchange":"NASDAQ"}`)) {
		t.Fatal("NASDAQ must flag US")
	}
	if !HasGlobalEquityMarker([]byte(`{"exchange":"LSE"}`)) {
		t.Fatal("LSE must flag global")
	}
	if !HasCMEFuturesMarker([]byte(`{"exchange":"CME"}`)) {
		t.Fatal("CME must flag futures")
	}
	if !HasForexMarker([]byte(`pair=EUR.USD`)) {
		t.Fatal("EUR.USD must flag forex")
	}
	if !HasCryptoMarker([]byte(`{"symbol":"BTC"}`)) {
		t.Fatal("BTC must flag crypto")
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindGatewayConfig, KindCredentials,
		KindTWSSettings, KindPositions, KindOrders,
		KindStrategyPy, KindTradeLog, KindFlexQuery,
		KindTaxStatement,
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
		ArtifactKind:        KindConfig,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + cliente = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:        KindConfig,
		HasPasswordInConfig: true,
		FileMode:            0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateHighAUM(t *testing.T) {
	r := Row{
		ArtifactKind:         KindFlexQuery,
		PortfolioAUMUSDCents: 50_000_000,
	}
	AnnotateSecurity(&r)
	if !r.HasHighAUM {
		t.Fatal("USD 500 K must flag high AUM")
	}
}

func TestAnnotateBCRAAboveCap(t *testing.T) {
	r := Row{
		ArtifactKind:  KindFlexQuery,
		AboveCapCount: 3,
	}
	AnnotateSecurity(&r)
	if !r.HasBCRAAboveCap {
		t.Fatal("above-cap count must flag")
	}
}

func TestParseIBConfig(t *testing.T) {
	body := []byte(`[IBGateway]
TwsUsername=alice@example.com
TwsPassword=secret123
LocalServerPort=7496
LocalServerAddress=0.0.0.0
TradingMode=live
ib_account=U1234567
`)
	f := ParseIBConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APISocketPort != 7496 {
		t.Fatalf("port=%d want 7496", f.APISocketPort)
	}
	if f.APISocketAddress != "0.0.0.0" {
		t.Fatalf("addr=%q want 0.0.0.0", f.APISocketAddress)
	}
	if !f.HasAPIExposed {
		t.Fatal("0.0.0.0 must flag exposed")
	}
	if !f.HasLive {
		t.Fatal("live mode must flag")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.IBAccountSuffix4 != "4567" {
		t.Fatalf("ib account suffix=%q", f.IBAccountSuffix4)
	}
}

func TestParseIBPositions(t *testing.T) {
	body := []byte(`{
"positions": [
{ "symbol": "AAPL", "exchange": "NASDAQ", "market_value": 50000.00 },
{ "symbol": "ASML", "exchange": "AEB", "market_value": 30000.00 },
{ "symbol": "ESM26", "exchange": "CME", "market_value": 10000.00 },
{ "symbol": "BTC", "market_value": 5000.00 },
{ "symbol": "EUR.USD", "market_value": 2000.00 }
]
}`)
	f := ParseIBPositions(body)
	if !f.HasUSEquity {
		t.Fatal("NASDAQ must flag US")
	}
	if !f.HasGlobalEquity {
		t.Fatal("AEB must flag global")
	}
	if !f.HasFutures {
		t.Fatal("CME must flag futures")
	}
	if !f.HasCrypto {
		t.Fatal("BTC must flag crypto")
	}
	if !f.HasForex {
		t.Fatal("EUR.USD must flag forex")
	}
	if f.PortfolioAUMUSDCents < 9_700_000 {
		t.Fatalf("aum=%d want >=9_700_000", f.PortfolioAUMUSDCents)
	}
}

func TestParseIBFlexQuery(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<FlexQueryResponse queryName="MonthlyActivity">
<FlexStatements count="1">
<FlexStatement accountId="U1234567">
<AccountInformation/>
<Trade symbol="AAPL" exchange="NASDAQ" cash_balance="50000.00"/>
<Trade symbol="ASML" exchange="AEB" cash_balance="300000.00"/>
</FlexStatement>
</FlexStatements>
</FlexQueryResponse>`)
	f := ParseIBFlexQuery(body)
	if !f.HasFlexExport {
		t.Fatal("FlexQueryResponse must flag")
	}
	if f.IBAccountSuffix4 != "4567" {
		t.Fatalf("ib account=%q", f.IBAccountSuffix4)
	}
	if !f.HasUSEquity || !f.HasGlobalEquity {
		t.Fatalf("US=%t Global=%t", f.HasUSEquity, f.HasGlobalEquity)
	}
}

func TestParseIBStrategyPy(t *testing.T) {
	body := []byte(`from ib_insync import IB, Stock
ib = IB()
ib.connect("127.0.0.1", 7496, clientId=1)
contract = Stock("AAPL", "NASDAQ", "USD")
password = "hardcoded123"
`)
	f := ParseIBStrategyPy(body)
	if !f.HasPassword {
		t.Fatal("hardcoded password must flag")
	}
	if !f.HasUSEquity {
		t.Fatal("NASDAQ must flag US")
	}
	if f.APISocketPort != 7496 {
		t.Fatalf("port=%d", f.APISocketPort)
	}
	if !f.HasLive {
		t.Fatal("port 7496 = live")
	}
}

func TestParseIBEmpty(t *testing.T) {
	f := ParseIBConfig(nil)
	if f.HasPassword || f.APISocketPort != 0 {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestClassifyProduct(t *testing.T) {
	if classifyProduct(IBFields{HasUSEquity: true}) != ProductUSEquity {
		t.Fatal("us")
	}
	if classifyProduct(IBFields{HasCrypto: true}) != ProductCrypto {
		t.Fatal("crypto")
	}
	if classifyProduct(IBFields{HasUSEquity: true, HasCrypto: true}) != ProductMultiAsset {
		t.Fatal("multi")
	}
	if classifyProduct(IBFields{}) != ProductUnknown {
		t.Fatal("unknown")
	}
}

func TestClassifyAccount(t *testing.T) {
	if classifyAccount(Row{}, IBFields{APISocketPort: PortTWSPaper}) != AccountPaper {
		t.Fatal("paper port -> paper")
	}
	if classifyAccount(Row{}, IBFields{APISocketPort: PortTWSLive}) != AccountRetail {
		t.Fatal("live port -> retail")
	}
	if classifyAccount(Row{ArtifactKind: KindStrategyPy}, IBFields{}) != AccountAPI {
		t.Fatal("py -> api")
	}
	if classifyAccount(Row{HasPasswordInConfig: true}, IBFields{}) != AccountRetail {
		t.Fatal("password -> retail")
	}
	if classifyAccount(Row{}, IBFields{}) != AccountUnknown {
		t.Fatal("unknown")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Jts")
	must(t, os.MkdirAll(dir, 0o755))

	cfgPath := filepath.Join(dir, "jts.ini")
	must(t, os.WriteFile(cfgPath, []byte(`[IBGateway]
TwsUsername=alice@example.com
TwsPassword=secret123
LocalServerPort=7496
LocalServerAddress=0.0.0.0
TradingMode=live
ib_account=U1234567
cliente_cuit=27-11111111-4
`), 0o644))

	flexPath := filepath.Join(dir, "flex_query_202506.xml")
	must(t, os.WriteFile(flexPath, []byte(`<?xml version="1.0"?>
<FlexQueryResponse queryName="MonthlyActivity">
<FlexStatement accountId="U1234567">
<Trade symbol="AAPL" exchange="NASDAQ" market_value="500000.00"/>
<Trade symbol="ASML" exchange="AEB" market_value="300000.00"/>
</FlexStatement>
</FlexQueryResponse>`), 0o644))

	stratPath := filepath.Join(usersBase, "alice", "projects", "quant", "ibapi_strategy.py")
	must(t, os.MkdirAll(filepath.Dir(stratPath), 0o755))
	must(t, os.WriteFile(stratPath, []byte(`from ib_insync import IB, Stock
ib = IB()
ib.connect("127.0.0.1", 7496, clientId=1)
contract = Stock("AAPL", "NASDAQ", "USD")
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Jts")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "jts.ini"),
		[]byte(`x`), 0o644))

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
		t.Fatalf("want 3 (cfg+flex+strat), got %d: %+v", len(got), got)
	}

	var cfg, flex, strat Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case flexPath:
			flex = r
		case stratPath:
			strat = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if !cfg.HasAPISocketExposed {
		t.Fatalf("cfg must flag exposed socket: %+v", cfg)
	}
	if !cfg.HasLiveAccount {
		t.Fatalf("cfg must flag live: %+v", cfg)
	}
	if cfg.APISocketPort != 7496 {
		t.Fatalf("cfg port=%d", cfg.APISocketPort)
	}
	if cfg.IBAccountSuffix4 != "4567" {
		t.Fatalf("cfg account=%q", cfg.IBAccountSuffix4)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cliente = exposure: %+v", cfg)
	}

	if flex.ArtifactKind != KindFlexQuery {
		t.Fatalf("flex kind=%q", flex.ArtifactKind)
	}
	if !flex.HasFlexQueryExport {
		t.Fatalf("flex must flag export: %+v", flex)
	}
	if !flex.HasUSEquityPositions || !flex.HasGlobalEquityPositions {
		t.Fatalf("flex must flag both US + global: %+v", flex)
	}

	if strat.ArtifactKind != KindStrategyPy {
		t.Fatalf("strat kind=%q", strat.ArtifactKind)
	}
	if !strat.HasUSEquityPositions {
		t.Fatalf("strat must flag NASDAQ: %+v", strat)
	}
	if strat.AccountClass != AccountRetail {
		t.Fatalf("strat account=%q want retail (live port)", strat.AccountClass)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-ib")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "jts.ini"),
		[]byte(`LocalServerPort=7496`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "IB_DIR" {
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
		installRoots: []string{"/nope-ib"},
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
		{FilePath: "a", ArtifactKind: KindPositions},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	// At "a": "ib-config" < "ib-positions" alphabetically.
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,ib-config)", in[0])
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

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
