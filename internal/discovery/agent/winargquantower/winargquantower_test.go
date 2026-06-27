package winargquantower

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "quantower-config"},
		{string(KindCredentials), "quantower-credentials"},
		{string(KindWorkspace), "quantower-workspace"},
		{string(KindSymbols), "quantower-symbols"},
		{string(KindConnectionConfig), "quantower-connection-config"},
		{string(KindAlgoSDKScript), "quantower-algo-sdk-script"},
		{string(KindAlgoBuilder), "quantower-algo-builder"},
		{string(KindMultiStrategyLauncher), "quantower-multi-strategy-launcher"},
		{string(KindDOMConfig), "quantower-dom-config"},
		{string(KindTradeLog), "quantower-trade-log"},
		{string(KindInstaller), "quantower-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountProFutures), "pro-futures"},
		{string(AccountCryptoArbitrageur), "crypto-arbitrageur"},
		{string(AccountPropTrader), "prop-trader"},
		{string(AccountHFT), "hft"},
		{string(AccountBacktestResearcher), "backtest-researcher"},
		{string(AccountAlgotrader), "algotrader"},
		{string(AccountMultiAsset), "multi-asset"},
		{string(AccountAPI), "api"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(ProductMATbaRofex), "matba-rofex"},
		{string(ProductCMEFutures), "cme-futures"},
		{string(ProductUSEquity), "us-equity"},
		{string(ProductCrypto), "crypto"},
		{string(ProductForex), "forex"},
		{string(ProductMultiAsset), "multi-asset"},
		{string(ProductHFTExecution), "hft-execution"},
		{string(ProductOther), "other"},
		{string(ProductUnknown), "unknown"},
		{string(PluginBinance), "binance"},
		{string(PluginBybit), "bybit"},
		{string(PluginBitfinex), "bitfinex"},
		{string(PluginKraken), "kraken"},
		{string(PluginCoinbase), "coinbase"},
		{string(PluginRithmic), "rithmic"},
		{string(PluginCQG), "cqg"},
		{string(PluginTT), "tt"},
		{string(PluginIB), "ib"},
		{string(PluginDXFeed), "dxfeed"},
		{string(PluginOanda), "oanda"},
		{string(PluginCustom), "custom"},
		{string(PluginNone), "none"},
		{string(PluginUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"quantower.cfg",
		"quantower_credentials.json",
		"workspace.qwt",
		"symbols.json",
		"connection_config_binance.json",
		"strategy_xyz.cs",
		"quantower_strategy.dll",
		"algo_builder_cfg.json",
		"multi_strategy_launcher.json",
		"dom_config.json",
		"trade_log_202506.csv",
		"quantower_installer.msi",
	}
	no := []string{"", "factura.xml", "random.bin", "report.pdf"}
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
		"quantower.cfg":                  KindConfig,
		"quantower_credentials.json":     KindCredentials,
		"quantower_api_token.json":       KindCredentials,
		"workspace.qwt":                  KindWorkspace,
		"symbols.json":                   KindSymbols,
		"connection_config_binance.json": KindConnectionConfig,
		"strategy_xyz.cs":                KindAlgoSDKScript,
		"quantower_indicator.cs":         KindAlgoSDKScript,
		"quantower_strategy.dll":         KindAlgoSDKScript,
		"algo_builder_cfg.json":          KindAlgoBuilder,
		"multi_strategy_launcher.json":   KindMultiStrategyLauncher,
		"dom_config.json":                KindDOMConfig,
		"trade_log_202506.csv":           KindTradeLog,
		"quantower_installer.msi":        KindInstaller,
		"":                               KindUnknown,
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
	if PeriodFromFilename("trade_log_202506.csv") != "202506" {
		t.Fatal("period mismatch")
	}
}

func TestIsMATbaRofexSymbol(t *testing.T) {
	yes := []string{"DLR", "MTR-USD", "SOJ", "MERV"}
	no := []string{"", "ES", "AAPL"}
	for _, v := range yes {
		if !IsMATbaRofexSymbol(v) {
			t.Fatalf("expected MATba: %q", v)
		}
	}
	for _, v := range no {
		if IsMATbaRofexSymbol(v) {
			t.Fatalf("expected NOT MATba: %q", v)
		}
	}
}

func TestIsCMEFuturesSymbol(t *testing.T) {
	yes := []string{"ES", "NQ", "CL", "GC", "BTC"}
	no := []string{"", "DLR", "AAPL"}
	for _, v := range yes {
		if !IsCMEFuturesSymbol(v) {
			t.Fatalf("expected CME: %q", v)
		}
	}
	for _, v := range no {
		if IsCMEFuturesSymbol(v) {
			t.Fatalf("expected NOT CME: %q", v)
		}
	}
}

func TestIsUSEquityStem(t *testing.T) {
	yes := []string{"AAPL", "MSFT", "SPY"}
	no := []string{"", "DLR", "ES"}
	for _, v := range yes {
		if !IsUSEquityStem(v) {
			t.Fatalf("expected US: %q", v)
		}
	}
	for _, v := range no {
		if IsUSEquityStem(v) {
			t.Fatalf("expected NOT US: %q", v)
		}
	}
}

func TestIsCryptoSymbol(t *testing.T) {
	yes := []string{"BTC", "ETH", "USDT/ARS", "USDT", "USDT-ARS"}
	no := []string{"", "AAPL", "DLR", "ES"}
	for _, v := range yes {
		if !IsCryptoSymbol(v) {
			t.Fatalf("expected crypto: %q", v)
		}
	}
	for _, v := range no {
		if IsCryptoSymbol(v) {
			t.Fatalf("expected NOT crypto: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindWorkspace, KindSymbols,
		KindConnectionConfig, KindAlgoSDKScript, KindAlgoBuilder,
		KindMultiStrategyLauncher, KindDOMConfig, KindTradeLog,
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
		ArtifactKind:        KindConnectionConfig,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.HasBrokerPluginCredentials {
		t.Fatal("connection-config kind must auto-flag plug-in creds")
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

func TestAnnotateAlgoSDKAuto(t *testing.T) {
	r := Row{ArtifactKind: KindAlgoSDKScript}
	AnnotateSecurity(&r)
	if !r.HasAlgoSDKScript {
		t.Fatal("algo-sdk-script kind must auto-flag")
	}
}

func TestAnnotateAlgoBuilderAuto(t *testing.T) {
	r := Row{ArtifactKind: KindAlgoBuilder}
	AnnotateSecurity(&r)
	if !r.HasVisualAlgoBuilder {
		t.Fatal("algo-builder kind must auto-flag")
	}
}

func TestAnnotateMultiStrategyAuto(t *testing.T) {
	r := Row{ArtifactKind: KindMultiStrategyLauncher}
	AnnotateSecurity(&r)
	if !r.HasMultiStrategyLauncher {
		t.Fatal("multi-strategy-launcher kind must auto-flag")
	}
}

func TestAnnotateCrossVenue(t *testing.T) {
	r := Row{
		ArtifactKind:       KindWorkspace,
		MATbaSymbolsCount:  1,
		CMESymbolsCount:    1,
		CryptoSymbolsCount: 1,
	}
	AnnotateSecurity(&r)
	if !r.HasMATbaRofexRouting {
		t.Fatal("MATba count must flag")
	}
	if !r.HasCMEFutures {
		t.Fatal("CME count must flag")
	}
	if !r.HasCryptoData {
		t.Fatal("crypto count must flag")
	}
	if !r.HasCrossVenueArb {
		t.Fatal("multi-venue must flag cross-venue")
	}
}

func TestAnnotateHighMsgRate(t *testing.T) {
	r := Row{
		ArtifactKind:  KindTradeLog,
		PeakMsgPerSec: 1500,
	}
	AnnotateSecurity(&r)
	if !r.HasHighMessageRate {
		t.Fatal("1500/s must flag HFT")
	}
}

func TestParseQuantowerConfig(t *testing.T) {
	body := []byte(`# Quantower config
quantower_username=alice@example.com
quantower_password=secret123
broker_password=AnotherSecret
api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
api_secret=zYxWvUtSrQpOnMlKjIhGfEdCbA0123
quantower_account=ACME-001
[Binance]
binance_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
hmac_secret=zYxWvUtSrQpOnMlKjIhGfEdCbA0123
paper_trading=true
symbol=DLR
symbol=ES
symbol=AAPL
symbol=BTC/USDT
cliente_cuit=27-11111111-4
`)
	f := ParseQuantowerConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if f.APISecret == "" {
		t.Fatal("api secret must extract")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.QuantowerAccountID == "" {
		t.Fatalf("account=%q", f.QuantowerAccountID)
	}
	if f.BrokerPlugin != PluginBinance {
		t.Fatalf("plugin=%q want binance", f.BrokerPlugin)
	}
	if !f.HasPaperTradingMode {
		t.Fatal("paper-trading must flag")
	}
	if f.MATbaSymbolsCount < 1 {
		t.Fatalf("matba=%d", f.MATbaSymbolsCount)
	}
	if f.CMESymbolsCount < 1 {
		t.Fatalf("cme=%d", f.CMESymbolsCount)
	}
	if f.USEquitySymbolsCount < 1 {
		t.Fatalf("us=%d", f.USEquitySymbolsCount)
	}
	if f.CryptoSymbolsCount < 1 {
		t.Fatalf("crypto=%d", f.CryptoSymbolsCount)
	}
}

func TestParseQuantowerDOMArmed(t *testing.T) {
	body := []byte(`[DOM]
dom_armed=true
auto_execute=1
one_click_trading=true
`)
	f := ParseQuantowerDOMConfig(body)
	if !f.HasDOMArmed {
		t.Fatal("DOM armed must flag")
	}
}

func TestParseQuantowerAlgoSDKScript(t *testing.T) {
	body := []byte(`using System;
using Quantower.Algos;

public class MyStrategy : Strategy {
    public override void OnQuote() {
        // brecha cambiaria USDT/ARS arbitrage logic
        if (usdt_ars > dolar_blue * 1.02) {
            PlaceOrder("USDT/ARS", "SELL");
        }
    }
}
api_key="aBcDeFgHiJkLmNoPqRsTuVwX12345"
`)
	f := ParseQuantowerAlgoSDKScript(body)
	if f.StrategyCount < 1 {
		t.Fatalf("strategies=%d", f.StrategyCount)
	}
	if !f.HasUSDTARSArbitrage {
		t.Fatal("USDT/ARS arb must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
}

func TestParseQuantowerEmpty(t *testing.T) {
	f := ParseQuantowerConfig(nil)
	if f.HasPassword || f.APIKey != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestDetectBrokerPlugin(t *testing.T) {
	cases := map[string]BrokerPlugin{
		`[Binance]`:                  PluginBinance,
		`[Bybit]`:                    PluginBybit,
		`[Rithmic]`:                  PluginRithmic,
		`[CQG]`:                      PluginCQG,
		`tradingtechnologies_token=`: PluginTT,
		`tws_port=7497`:              PluginIB,
		`[dxFeed]`:                   PluginDXFeed,
		`[OANDA]`:                    PluginOanda,
		`generic config`:             PluginUnknown,
	}
	for in, want := range cases {
		got := detectBrokerPlugin([]byte(in))
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyProduct(t *testing.T) {
	if got := classifyProduct(Row{HasDOMArmed: true}); got != ProductHFTExecution {
		t.Fatalf("DOM -> hft-execution, got %q", got)
	}
	if got := classifyProduct(Row{
		HasMATbaRofexRouting: true,
		HasCMEFutures:        true,
	}); got != ProductMultiAsset {
		t.Fatalf("multi -> multi-asset, got %q", got)
	}
	if got := classifyProduct(Row{HasMATbaRofexRouting: true}); got != ProductMATbaRofex {
		t.Fatalf("matba -> matba-rofex, got %q", got)
	}
	if got := classifyProduct(Row{HasCryptoData: true}); got != ProductCrypto {
		t.Fatalf("crypto -> crypto, got %q", got)
	}
	if got := classifyProduct(Row{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyAccount(t *testing.T) {
	if got := classifyAccount(Row{HasDOMArmed: true}); got != AccountHFT {
		t.Fatalf("DOM -> hft, got %q", got)
	}
	if got := classifyAccount(Row{
		HasMATbaRofexRouting: true,
		HasCMEFutures:        true, HasUSEquity: true,
	}); got != AccountMultiAsset {
		t.Fatalf(">=3 venues -> multi-asset, got %q", got)
	}
	if got := classifyAccount(Row{
		HasCryptoData: true,
		HasCMEFutures: true,
	}); got != AccountCryptoArbitrageur {
		t.Fatalf("crypto + futures -> crypto-arbitrageur, got %q", got)
	}
	if got := classifyAccount(Row{HasUSDTARSArbitrage: true}); got != AccountCryptoArbitrageur {
		t.Fatalf("USDT/ARS arb -> crypto-arbitrageur, got %q", got)
	}
	if got := classifyAccount(Row{HasAlgoSDKScript: true}); got != AccountAlgotrader {
		t.Fatalf("SDK -> algotrader, got %q", got)
	}
	if got := classifyAccount(Row{HasCMEFutures: true}); got != AccountProFutures {
		t.Fatalf("cme -> pro-futures, got %q", got)
	}
	if got := classifyAccount(Row{HasPaperTradingMode: true}); got != AccountBacktestResearcher {
		t.Fatalf("paper -> backtest-researcher, got %q", got)
	}
	if got := classifyAccount(Row{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", ".quantower")
	must(t, os.MkdirAll(dir, 0o755))

	cfgPath := filepath.Join(dir, "quantower.cfg")
	must(t, os.WriteFile(cfgPath, []byte(`# Quantower config
quantower_username=alice@example.com
quantower_password=secret123
api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
quantower_account=ACME-001
[Binance]
binance_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
hmac_secret=zYxWvUtSrQpOnMlKjIhGfEdCbA0123
symbol=BTC/USDT
symbol=ES
cliente_cuit=27-11111111-4
`), 0o644))

	sdkPath := filepath.Join(dir, "my_strategy.cs")
	must(t, os.WriteFile(sdkPath, []byte(`using System;
using Quantower.Algos;
public class MyStrategy : Strategy {
    public override void OnQuote() {
        if (usdt_ars > dolar_blue * 1.02) PlaceOrder("USDT/ARS", "SELL");
    }
}
api_key="aBcDeFgHiJkLmNoPqRsTuVwX12345"
`), 0o644))

	domPath := filepath.Join(dir, "dom_config.json")
	must(t, os.WriteFile(domPath, []byte(`{
"dom_armed": true,
"auto_execute": true,
"symbol": "BTC/USDT"
}`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", ".quantower")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "quantower.cfg"),
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
	if len(got) != 3 {
		t.Fatalf("want 3 (cfg+sdk+dom), got %d: %+v", len(got), got)
	}

	var cfg, sdk, dom Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case sdkPath:
			sdk = r
		case domPath:
			dom = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if cfg.BrokerPlugin != PluginBinance {
		t.Fatalf("cfg plugin=%q want binance", cfg.BrokerPlugin)
	}
	if !cfg.HasCryptoData {
		t.Fatalf("cfg must flag crypto: %+v", cfg)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cliente = exposure: %+v", cfg)
	}

	if sdk.ArtifactKind != KindAlgoSDKScript {
		t.Fatalf("sdk kind=%q", sdk.ArtifactKind)
	}
	if !sdk.HasAlgoSDKScript {
		t.Fatalf("sdk must auto-flag: %+v", sdk)
	}
	if !sdk.HasUSDTARSArbitrage {
		t.Fatalf("sdk must flag USDT/ARS arb: %+v", sdk)
	}
	if sdk.AccountClass != AccountCryptoArbitrageur {
		t.Fatalf("sdk account=%q want crypto-arbitrageur", sdk.AccountClass)
	}

	if dom.ArtifactKind != KindDOMConfig {
		t.Fatalf("dom kind=%q", dom.ArtifactKind)
	}
	if !dom.HasDOMArmed {
		t.Fatalf("dom must flag armed: %+v", dom)
	}
	if dom.AccountClass != AccountHFT {
		t.Fatalf("dom account=%q want hft", dom.AccountClass)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-qt")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "quantower.cfg"),
		[]byte(`quantower_account=ACME`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "QUANTOWER_DIR" {
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
		installRoots: []string{"/nope-quantower"},
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
		{FilePath: "a", ArtifactKind: KindTradeLog},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,quantower-config)", in[0])
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
