package winargmulticharts

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "mc-config"},
		{string(KindCredentials), "mc-credentials"},
		{string(KindPLAStrategy), "mc-pla-strategy"},
		{string(KindELAStrategy), "mc-ela-strategy"},
		{string(KindWorkspace), "mc-workspace"},
		{string(KindPortfolio), "mc-portfolio"},
		{string(KindQuoteManagerDB), "mc-quotemanager-db"},
		{string(KindBrokerPlugin), "mc-broker-plugin"},
		{string(KindPortfolioTraderConfig), "mc-portfolio-trader-config"},
		{string(KindDOMConfig), "mc-dom-config"},
		{string(KindNetScript), "mc-net-script"},
		{string(KindBacktestReport), "mc-backtest-report"},
		{string(KindTradeLog), "mc-trade-log"},
		{string(KindInstaller), "mc-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountProFutures), "pro-futures"},
		{string(AccountPropTrader), "prop-trader"},
		{string(AccountArbitrageur), "arbitrageur"},
		{string(AccountHFT), "hft"},
		{string(AccountBacktestResearcher), "backtest-researcher"},
		{string(AccountAlgotrader), "algotrader"},
		{string(AccountAPI), "api"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(ProductCMEFutures), "cme-futures"},
		{string(ProductMATbaRofex), "matba-rofex"},
		{string(ProductMultiVenue), "multi-venue"},
		{string(ProductOptions), "options"},
		{string(ProductForex), "forex"},
		{string(ProductCrypto), "crypto"},
		{string(ProductHFTExecution), "hft-execution"},
		{string(ProductOther), "other"},
		{string(ProductUnknown), "unknown"},
		{string(PluginIB), "ib"},
		{string(PluginRithmic), "rithmic"},
		{string(PluginCQG), "cqg"},
		{string(PluginIQFeed), "iqfeed"},
		{string(PluginInteractiveData), "interactive_data"},
		{string(PluginTT), "tt"},
		{string(PluginMATbaRofex), "matba_rofex"},
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
		"multicharts.cfg",
		"profile.cfg",
		"my_strat.pla",
		"my_strat.ela",
		"my_chart.wsp",
		"my_port.pls",
		"strategy_xyz.cs",
		"quotemanager.db",
		"broker_profiles_ib.cfg",
		"portfolio_trader_config.json",
		"dom_config.json",
		"trade_log_202506.csv",
		"backtest_report.csv",
		"multicharts_installer.msi",
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
		"multicharts.cfg":              KindConfig,
		"profile.cfg":                  KindConfig,
		"brokerprofiles_ib.cfg":        KindConfig,
		"mc_credentials.json":          KindCredentials,
		"mc_api_token.json":            KindCredentials,
		"my_strat.pla":                 KindPLAStrategy,
		"my_strat.ela":                 KindELAStrategy,
		"my_chart.wsp":                 KindWorkspace,
		"my_port.pls":                  KindPortfolio,
		"strategy_xyz.cs":              KindNetScript,
		"mc_signal.cs":                 KindNetScript,
		"quotemanager.db":              KindQuoteManagerDB,
		"quotemanager.sqlite":          KindQuoteManagerDB,
		"multicharts_rithmic.dll":      KindBrokerPlugin,
		"ibcontroller.dll":             KindBrokerPlugin,
		"portfolio_trader_config.json": KindPortfolioTraderConfig,
		"dom_config.json":              KindDOMConfig,
		"backtest_report.csv":          KindBacktestReport,
		"trade_log_202506.csv":         KindTradeLog,
		"multicharts_installer.msi":    KindInstaller,
		"":                             KindUnknown,
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
	if PeriodFromFilename("random.csv") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsMATbaRofexSymbol(t *testing.T) {
	yes := []string{
		"DLR", "DOM", "ROS-DLR", "MTR-USD",
		"SOJ", "MAI", "TRI", "CER", "UVA", "MERV",
	}
	no := []string{"", "ES", "CL", "GC", "AAPL"}
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
	yes := []string{
		"ES", "NQ", "YM", "CL", "NG", "GC", "SI",
		"ZC", "ZN", "6E", "DXY", "BTC", "ETH",
	}
	no := []string{"", "DLR", "SOJ", "AAPL"}
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

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindPLAStrategy, KindELAStrategy,
		KindWorkspace, KindPortfolio, KindBrokerPlugin,
		KindPortfolioTraderConfig, KindDOMConfig, KindNetScript,
		KindBacktestReport, KindTradeLog,
	}
	no := []ArtifactKind{
		KindQuoteManagerDB, KindInstaller, KindOther, KindUnknown,
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

func TestAnnotatePLAAuto(t *testing.T) {
	r := Row{ArtifactKind: KindPLAStrategy}
	AnnotateSecurity(&r)
	if !r.HasPLAEncrypted {
		t.Fatal("PLA kind must auto-flag")
	}
}

func TestAnnotateCSAuto(t *testing.T) {
	r := Row{ArtifactKind: KindNetScript}
	AnnotateSecurity(&r)
	if !r.HasCSNativeStrategy {
		t.Fatal(".cs kind must auto-flag")
	}
}

func TestAnnotateQuoteManagerLarge(t *testing.T) {
	r := Row{
		ArtifactKind: KindQuoteManagerDB,
		FileSize:     LargeQuoteManagerBytes + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasQuoteManagerDB {
		t.Fatal("QM kind must flag")
	}
	if !r.HasLargeQuoteManagerDB {
		t.Fatal("> 1 GB must flag large")
	}
}

func TestAnnotateCrossVenueArb(t *testing.T) {
	r := Row{
		ArtifactKind:      KindWorkspace,
		MATbaSymbolsCount: 2,
		CMESymbolsCount:   3,
	}
	AnnotateSecurity(&r)
	if !r.HasMATbaRofexRouting {
		t.Fatal("MATba count must flag")
	}
	if !r.HasCMEFutures {
		t.Fatal("CME count must flag")
	}
	if !r.HasCrossVenueArb {
		t.Fatal("both must flag cross-venue arb")
	}
}

func TestAnnotatePortfolioTraderAuto(t *testing.T) {
	r := Row{ArtifactKind: KindPortfolioTraderConfig}
	AnnotateSecurity(&r)
	if !r.HasPortfolioTrader {
		t.Fatal("portfolio-trader-config must auto-flag")
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

func TestParseMCConfig(t *testing.T) {
	body := []byte(`[MultiCharts]
mc_username=alice@example.com
broker_password=secret123
mc_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
mc_account=ACME-FUTURES-001
[Rithmic]
rithmic_user=alice
rithmic_server=Rithmic 01
symbol=DLR
symbol=ES
cliente_cuit=27-11111111-4
`)
	f := ParseMCConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.MCAccountID == "" {
		t.Fatalf("account=%q", f.MCAccountID)
	}
	if !f.HasBrokerPluginCreds {
		t.Fatal("plug-in creds must flag")
	}
	if f.BrokerPlugin != PluginRithmic {
		t.Fatalf("plugin=%q want rithmic", f.BrokerPlugin)
	}
	if f.MATbaSymbolsCount < 1 {
		t.Fatalf("matba=%d", f.MATbaSymbolsCount)
	}
	if f.CMESymbolsCount < 1 {
		t.Fatalf("cme=%d", f.CMESymbolsCount)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseMCWorkspaceSendOrder(t *testing.T) {
	body := []byte(`<Workspace>
<Symbol>DLR</Symbol>
<Symbol>ES</Symbol>
SendOrders="true"
AutomatedTrading="enabled"
account_id=ACME-001
</Workspace>`)
	f := ParseMCWorkspace(body)
	if !f.HasSendOrderStrategy {
		t.Fatal("send-order must flag")
	}
	if f.MATbaSymbolsCount < 1 {
		t.Fatalf("matba=%d", f.MATbaSymbolsCount)
	}
	if f.CMESymbolsCount < 1 {
		t.Fatalf("cme=%d", f.CMESymbolsCount)
	}
}

func TestParseMCPortfolio(t *testing.T) {
	body := []byte(`<PortfolioSession>
<sym>DLR/JUN26</sym>
<sym>MTR-USD/JUN26</sym>
<sym>ES/JUN26</sym>
autoExecution=true
</PortfolioSession>`)
	f := ParseMCPortfolio(body)
	if !f.HasPortfolioTrader {
		t.Fatal("portfolio trader must flag")
	}
	if !f.HasSendOrderStrategy {
		t.Fatal("autoexecution must flag send-order")
	}
	if f.PortfolioSymbolCount < 3 {
		t.Fatalf("portfolio symbols=%d", f.PortfolioSymbolCount)
	}
}

func TestParseMCDOMArmed(t *testing.T) {
	body := []byte(`[DOM]
DOMTrading=true
OrderBarArmed=1
symbol=DLR
`)
	f := ParseMCDOMConfig(body)
	if !f.HasDOMArmed {
		t.Fatal("DOM armed must flag")
	}
}

func TestParseMCTradeLog(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 OrderFilled symbol=DLR/JUN26 qty=5 px=1234.5
2026-06-15 09:30:02 OrderFilled symbol=ES/JUN26 qty=2 px=5400.25
2026-06-15 09:30:03 OrderFilled symbol=MTR-USD/JUN26 qty=1 px=900
account_id=ACME-001
`)
	f := ParseMCTradeLog(body)
	if f.FillCount < 3 {
		t.Fatalf("fills=%d", f.FillCount)
	}
	if f.MATbaSymbolsCount < 1 {
		t.Fatalf("matba=%d", f.MATbaSymbolsCount)
	}
	if f.CMESymbolsCount < 1 {
		t.Fatalf("cme=%d", f.CMESymbolsCount)
	}
}

func TestParseMCBrokerPlugin(t *testing.T) {
	cases := map[string]BrokerPlugin{
		"multicharts_rithmic.dll": PluginRithmic,
		"multicharts_cqg.dll":     PluginCQG,
		"multicharts_iqfeed.dll":  PluginIQFeed,
		"ibcontroller.dll":        PluginIB,
		"tws.dll":                 PluginIB,
		"matbarofex_plugin.dll":   PluginMATbaRofex,
		"mc_custom_plugin.dll":    PluginCustom,
		"random.dll":              PluginUnknown,
	}
	for in, want := range cases {
		f := ParseMCBrokerPlugin(nil, in)
		if f.BrokerPlugin != want {
			t.Fatalf("plugin(%q)=%q want %q", in, f.BrokerPlugin, want)
		}
	}
}

func TestParseMCEmpty(t *testing.T) {
	f := ParseMCConfig(nil)
	if f.HasPassword || f.APIKey != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestClassifyProduct(t *testing.T) {
	if got := classifyProduct(Row{HasDOMArmed: true}); got != ProductHFTExecution {
		t.Fatalf("DOM armed -> hft-execution, got %q", got)
	}
	if got := classifyProduct(Row{PeakMsgPerSec: HighMessageRateThreshold + 1}); got != ProductHFTExecution {
		t.Fatalf("high msg rate -> hft-execution, got %q", got)
	}
	if got := classifyProduct(Row{MATbaSymbolsCount: 1, CMESymbolsCount: 1}); got != ProductMultiVenue {
		t.Fatalf("both -> multi-venue, got %q", got)
	}
	if got := classifyProduct(Row{MATbaSymbolsCount: 1}); got != ProductMATbaRofex {
		t.Fatalf("matba -> matba-rofex, got %q", got)
	}
	if got := classifyProduct(Row{CMESymbolsCount: 1}); got != ProductCMEFutures {
		t.Fatalf("cme -> cme-futures, got %q", got)
	}
	if got := classifyProduct(Row{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyAccount(t *testing.T) {
	if got := classifyAccount(Row{HasDOMArmed: true}); got != AccountHFT {
		t.Fatalf("DOM -> hft, got %q", got)
	}
	if got := classifyAccount(Row{PeakMsgPerSec: HighMessageRateThreshold + 1}); got != AccountHFT {
		t.Fatalf("high msg rate -> hft, got %q", got)
	}
	if got := classifyAccount(Row{HasSendOrderStrategy: true, HasPortfolioTrader: true}); got != AccountAlgotrader {
		t.Fatalf("send + portfolio -> algotrader, got %q", got)
	}
	if got := classifyAccount(Row{HasSendOrderStrategy: true}); got != AccountAlgotrader {
		t.Fatalf("send -> algotrader, got %q", got)
	}
	if got := classifyAccount(Row{HasPortfolioTrader: true}); got != AccountAlgotrader {
		t.Fatalf("portfolio -> algotrader, got %q", got)
	}
	if got := classifyAccount(Row{MATbaSymbolsCount: 1, CMESymbolsCount: 1}); got != AccountArbitrageur {
		t.Fatalf("cross-venue -> arbitrageur, got %q", got)
	}
	if got := classifyAccount(Row{ArtifactKind: KindBacktestReport}); got != AccountBacktestResearcher {
		t.Fatalf("backtest -> researcher, got %q", got)
	}
	if got := classifyAccount(Row{MATbaSymbolsCount: 1}); got != AccountProFutures {
		t.Fatalf("matba -> pro-futures, got %q", got)
	}
	if got := classifyAccount(Row{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestDetectBrokerPluginFromName(t *testing.T) {
	cases := map[string]BrokerPlugin{
		"multicharts_rithmic.dll": PluginRithmic,
		"multicharts_cqg.dll":     PluginCQG,
		"multicharts_iqfeed.dll":  PluginIQFeed,
		"matbarofex.dll":          PluginMATbaRofex,
		"tradingtechnologies.dll": PluginTT,
		"ibcontroller.dll":        PluginIB,
		"tws.dll":                 PluginIB,
		"custom_plugin.dll":       PluginCustom,
		"random.bin":              PluginUnknown,
	}
	for in, want := range cases {
		got := detectBrokerPluginFromName(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	mcDir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "TS Support", "MultiCharts")
	must(t, os.MkdirAll(mcDir, 0o755))

	cfgPath := filepath.Join(mcDir, "multicharts.cfg")
	must(t, os.WriteFile(cfgPath, []byte(`[MultiCharts]
mc_username=alice@example.com
broker_password=secret123
mc_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
mc_account=ACME-FUTURES-001
[Rithmic]
rithmic_user=alice
rithmic_server=Rithmic 01
cliente_cuit=27-11111111-4
`), 0o644))

	wspPath := filepath.Join(mcDir, "dlr_es_arb.wsp")
	must(t, os.WriteFile(wspPath, []byte(`<Workspace>
<Symbol>DLR</Symbol>
<Symbol>ES</Symbol>
<Symbol>MTR-USD</Symbol>
SendOrders="true"
AutomatedTrading="enabled"
account_id=ACME-001
</Workspace>`), 0o644))

	plsPath := filepath.Join(mcDir, "ar_basket.pls")
	must(t, os.WriteFile(plsPath, []byte(`<PortfolioSession>
<sym>DLR/JUN26</sym>
<sym>MTR-USD/JUN26</sym>
<sym>ES/JUN26</sym>
autoExecution=true
</PortfolioSession>`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(mcDir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "TS Support", "MultiCharts")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "multicharts.cfg"),
		[]byte(`[MultiCharts]`), 0o644))

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
		t.Fatalf("want 3 (cfg+wsp+pls), got %d: %+v", len(got), got)
	}

	var cfg, wsp, pls Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case wspPath:
			wsp = r
		case plsPath:
			pls = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if !cfg.HasBrokerPluginCredentials {
		t.Fatalf("cfg must flag plug-in creds: %+v", cfg)
	}
	if cfg.BrokerPlugin != PluginRithmic {
		t.Fatalf("cfg plugin=%q want rithmic", cfg.BrokerPlugin)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cliente = exposure: %+v", cfg)
	}

	if wsp.ArtifactKind != KindWorkspace {
		t.Fatalf("wsp kind=%q", wsp.ArtifactKind)
	}
	if !wsp.HasSendOrderStrategy {
		t.Fatalf("wsp must flag send-order: %+v", wsp)
	}
	if !wsp.HasMATbaRofexRouting {
		t.Fatalf("wsp must flag MATba: %+v", wsp)
	}
	if !wsp.HasCMEFutures {
		t.Fatalf("wsp must flag CME: %+v", wsp)
	}
	if !wsp.HasCrossVenueArb {
		t.Fatalf("wsp must flag cross-venue: %+v", wsp)
	}
	if wsp.AccountClass != AccountAlgotrader {
		t.Fatalf("wsp account=%q want algotrader", wsp.AccountClass)
	}

	if pls.ArtifactKind != KindPortfolio {
		t.Fatalf("pls kind=%q", pls.ArtifactKind)
	}
	if !pls.HasPortfolioTrader {
		t.Fatalf("pls must flag portfolio trader: %+v", pls)
	}
	if pls.PortfolioSymbolCount < 3 {
		t.Fatalf("pls portfolio symbols=%d", pls.PortfolioSymbolCount)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-mc")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "multicharts.cfg"),
		[]byte(`[MultiCharts]
mc_account=ACME
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "MULTICHARTS_DIR" {
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
		installRoots: []string{"/nope-mc"},
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
		{FilePath: "a", ArtifactKind: KindWorkspace},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,mc-config)", in[0])
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
