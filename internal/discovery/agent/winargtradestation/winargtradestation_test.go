package winargtradestation

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "ts-config"},
		{string(KindCredentials), "ts-credentials"},
		{string(KindELSSource), "ts-els-source"},
		{string(KindELDPackage), "ts-eld-package"},
		{string(KindELCCompiled), "ts-elc-compiled"},
		{string(KindIndicator), "ts-indicator"},
		{string(KindStrategy), "ts-strategy"},
		{string(KindChartGroup), "ts-chartgroup"},
		{string(KindWorkspace), "ts-workspace"},
		{string(KindWFOResult), "ts-wfo-result"},
		{string(KindRadarScreen), "ts-radarscreen"},
		{string(KindOrderLog), "ts-orderlog"},
		{string(KindTradeManager), "ts-trademanager"},
		{string(KindTradeLog), "ts-trade-log"},
		{string(KindNetworkLog), "ts-network-log"},
		{string(KindAPIScript), "ts-api-script"},
		{string(KindInstaller), "ts-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountUSEquityDaytrader), "us-equity-daytrader"},
		{string(AccountProFutures), "pro-futures"},
		{string(AccountPropTrader), "prop-trader"},
		{string(AccountHFT), "hft"},
		{string(AccountBacktestResearcher), "backtest-researcher"},
		{string(AccountAlgotrader), "algotrader"},
		{string(AccountAPI), "api"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(ProductUSEquity), "us-equity"},
		{string(ProductCMEFutures), "cme-futures"},
		{string(ProductMATbaRofex), "matba-rofex"},
		{string(ProductOptions), "options"},
		{string(ProductForex), "forex"},
		{string(ProductCrypto), "crypto"},
		{string(ProductMultiAsset), "multi-asset"},
		{string(ProductHFTExecution), "hft-execution"},
		{string(ProductOther), "other"},
		{string(ProductUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"tsserver.cfg",
		"tradingaccount12345.cfg",
		"my_strat.els",
		"vendor_pkg.eld",
		"my_strat.elc",
		"my_ind.tsi",
		"my_strat.tss",
		"my_chart.tsg",
		"workspace.wkspace",
		"my_wfo.wfo",
		"my_scan.rds",
		"orderlog.txt",
		"trademanager_202506.csv",
		"radarscreen.rds",
		"tradestation_installer.msi",
		"ts_credentials.json",
		"tradestation_api_token.json",
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
		"tsserver.cfg":               KindConfig,
		"tradingaccount12345.cfg":    KindConfig,
		"ts_credentials.json":        KindCredentials,
		"ts_api_token.json":          KindCredentials,
		"my_strat.els":               KindELSSource,
		"vendor_pkg.eld":             KindELDPackage,
		"my_strat.elc":               KindELCCompiled,
		"my_ind.tsi":                 KindIndicator,
		"my_strat.tss":               KindStrategy,
		"my_chart.tsg":               KindChartGroup,
		"workspace.wkspace":          KindWorkspace,
		"my_wfo.wfo":                 KindWFOResult,
		"walk_forward_202506.csv":    KindWFOResult,
		"my_scan.rds":                KindRadarScreen,
		"radarscreen_top100.json":    KindRadarScreen,
		"orderlog.txt":               KindOrderLog,
		"order_log_202506.csv":       KindOrderLog,
		"trademanager_202506.csv":    KindTradeManager,
		"trade_manager.csv":          KindTradeManager,
		"ts_api_script.py":           KindAPIScript,
		"tradestation_ws_log.txt":    KindNetworkLog,
		"tradestation_installer.msi": KindInstaller,
		"":                           KindUnknown,
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
	if PeriodFromFilename("orderlog_202506.txt") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.txt") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsUSEquityStem(t *testing.T) {
	yes := []string{"AAPL", "MSFT", "SPY", "QQQ", "TSLA", "MELI"}
	no := []string{"", "DLR", "ES", "GGAL"}
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

func TestIsCMEFuturesSymbol(t *testing.T) {
	yes := []string{"ES", "NQ", "CL", "GC", "ZC", "6E", "BTC"}
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

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials,
		KindELSSource, KindELDPackage, KindELCCompiled,
		KindIndicator, KindStrategy, KindChartGroup,
		KindWorkspace, KindWFOResult, KindRadarScreen,
		KindOrderLog, KindTradeManager, KindTradeLog,
		KindNetworkLog, KindAPIScript,
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

func TestAnnotateELSAuto(t *testing.T) {
	r := Row{ArtifactKind: KindELSSource}
	AnnotateSecurity(&r)
	if !r.HasEasyLanguageEncrypted {
		t.Fatal(".els kind must auto-flag")
	}
}

func TestAnnotateELDAuto(t *testing.T) {
	r := Row{ArtifactKind: KindELDPackage}
	AnnotateSecurity(&r)
	if !r.HasELDDownloadPackage {
		t.Fatal(".eld kind must auto-flag")
	}
}

func TestAnnotateRadarScreenLarge(t *testing.T) {
	r := Row{
		ArtifactKind:            KindRadarScreen,
		RadarScreenSymbolsCount: LargeRadarScreenSymbols + 5,
	}
	AnnotateSecurity(&r)
	if !r.HasRadarScreen {
		t.Fatal("radar kind must flag")
	}
	if !r.HasLargeRadarScreen {
		t.Fatal("> 100 symbols must flag large")
	}
}

func TestAnnotateWFOAuto(t *testing.T) {
	r := Row{ArtifactKind: KindWFOResult}
	AnnotateSecurity(&r)
	if !r.HasWalkForwardOptimization {
		t.Fatal("WFO kind must auto-flag")
	}
}

func TestAnnotateOrderLogAuto(t *testing.T) {
	r := Row{ArtifactKind: KindOrderLog}
	AnnotateSecurity(&r)
	if !r.HasOrderLogExport {
		t.Fatal("orderlog kind must auto-flag")
	}
}

func TestAnnotateTradeManagerAuto(t *testing.T) {
	r := Row{ArtifactKind: KindTradeManager}
	AnnotateSecurity(&r)
	if !r.HasTradeManagerExport {
		t.Fatal("trademanager kind must auto-flag")
	}
}

func TestAnnotateCrossVenue(t *testing.T) {
	r := Row{
		ArtifactKind:         KindWorkspace,
		USEquitySymbolsCount: 2,
		CMESymbolsCount:      1,
	}
	AnnotateSecurity(&r)
	if !r.HasUSEquity {
		t.Fatal("US equity count must flag")
	}
	if !r.HasCMEFutures {
		t.Fatal("CME count must flag")
	}
	if !r.HasCrossVenueArb {
		t.Fatal("US + CME must flag cross-venue")
	}
}

func TestAnnotateHighMsgRate(t *testing.T) {
	r := Row{
		ArtifactKind:  KindNetworkLog,
		PeakMsgPerSec: 1500,
	}
	AnnotateSecurity(&r)
	if !r.HasHighMessageRate {
		t.Fatal("1500/s must flag HFT")
	}
}

func TestParseTSConfig(t *testing.T) {
	body := []byte(`[TradeStation]
ts_username=alice@example.com
ts_password=secret123
ts_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
ts_account=12345678
symbol=AAPL
symbol=ES
cliente_cuit=27-11111111-4
`)
	f := ParseTSConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if !f.HasAPICredentials {
		t.Fatal("API creds must flag")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.TSAccountID == "" {
		t.Fatalf("account=%q", f.TSAccountID)
	}
	if f.USEquitySymbolsCount < 1 {
		t.Fatalf("us=%d", f.USEquitySymbolsCount)
	}
	if f.CMESymbolsCount < 1 {
		t.Fatalf("cme=%d", f.CMESymbolsCount)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseTSStrategyAutotrade(t *testing.T) {
	body := []byte(`<Strategy>
<Symbol>ES</Symbol>
AutomatedTrading="true"
EnableAutoTrade=true
account_id=12345678
</Strategy>`)
	f := ParseTSStrategy(body)
	if !f.HasStrategyAutotrade {
		t.Fatal("auto-trade must flag")
	}
	if f.CMESymbolsCount < 1 {
		t.Fatalf("cme=%d", f.CMESymbolsCount)
	}
}

func TestParseTSRadarScreen(t *testing.T) {
	body := []byte(`<RadarScreen>
<Symbol>AAPL</Symbol>
<Symbol>MSFT</Symbol>
<Symbol>TSLA</Symbol>
<Symbol>NVDA</Symbol>
<Symbol>SPY</Symbol>
</RadarScreen>`)
	f := ParseTSRadarScreen(body)
	if f.RadarScreenSymbols != 5 {
		t.Fatalf("radar symbols=%d want 5", f.RadarScreenSymbols)
	}
}

func TestParseTSWFOResult(t *testing.T) {
	body := []byte(`<WFO>
<WalkForwardRun id="1"/>
<WalkForwardRun id="2"/>
<WalkForwardRun id="3"/>
</WFO>`)
	f := ParseTSWFOResult(body)
	if f.WFORunCount < 3 {
		t.Fatalf("wfo runs=%d", f.WFORunCount)
	}
}

func TestParseTSOrderLog(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 OrderFilled symbol=AAPL qty=100 px=200.50
2026-06-15 09:30:02 OrderFilled symbol=ES/JUN26 qty=2 px=5400.25
2026-06-15 09:30:03 OrderFilled symbol=MSFT qty=50 px=425
account_id=12345678
`)
	f := ParseTSOrderLog(body)
	if f.FillCount < 3 {
		t.Fatalf("fills=%d", f.FillCount)
	}
	if f.USEquitySymbolsCount < 1 {
		t.Fatalf("us=%d", f.USEquitySymbolsCount)
	}
}

func TestParseTSEmpty(t *testing.T) {
	f := ParseTSConfig(nil)
	if f.HasPassword || f.APIKey != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestClassifyProduct(t *testing.T) {
	if got := classifyProduct(Row{PeakMsgPerSec: HighMessageRateThreshold + 1}); got != ProductHFTExecution {
		t.Fatalf("high msg rate -> hft-execution, got %q", got)
	}
	if got := classifyProduct(Row{HasUSEquity: true, HasCMEFutures: true}); got != ProductMultiAsset {
		t.Fatalf("us+cme -> multi-asset, got %q", got)
	}
	if got := classifyProduct(Row{HasCMEFutures: true}); got != ProductCMEFutures {
		t.Fatalf("cme -> cme-futures, got %q", got)
	}
	if got := classifyProduct(Row{HasUSEquity: true}); got != ProductUSEquity {
		t.Fatalf("us -> us-equity, got %q", got)
	}
	if got := classifyProduct(Row{HasMATbaRofexRouting: true}); got != ProductMATbaRofex {
		t.Fatalf("matba -> matba-rofex, got %q", got)
	}
	if got := classifyProduct(Row{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyAccount(t *testing.T) {
	if got := classifyAccount(Row{PeakMsgPerSec: HighMessageRateThreshold + 1}); got != AccountHFT {
		t.Fatalf("high msg rate -> hft, got %q", got)
	}
	if got := classifyAccount(Row{HasStrategyAutotrade: true}); got != AccountAlgotrader {
		t.Fatalf("autotrade -> algotrader, got %q", got)
	}
	if got := classifyAccount(Row{ArtifactKind: KindAPIScript}); got != AccountAPI {
		t.Fatalf("api script -> api, got %q", got)
	}
	if got := classifyAccount(Row{ArtifactKind: KindWFOResult}); got != AccountBacktestResearcher {
		t.Fatalf("wfo -> researcher, got %q", got)
	}
	if got := classifyAccount(Row{HasUSEquity: true, HasCMEFutures: true}); got != AccountAlgotrader {
		t.Fatalf("multi-venue -> algotrader, got %q", got)
	}
	if got := classifyAccount(Row{HasCMEFutures: true}); got != AccountProFutures {
		t.Fatalf("cme -> pro-futures, got %q", got)
	}
	if got := classifyAccount(Row{HasUSEquity: true}); got != AccountUSEquityDaytrader {
		t.Fatalf("us -> us-equity-daytrader, got %q", got)
	}
	if got := classifyAccount(Row{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "TradeStation 10.0")
	must(t, os.MkdirAll(dir, 0o755))

	cfgPath := filepath.Join(dir, "tsserver.cfg")
	must(t, os.WriteFile(cfgPath, []byte(`[TradeStation]
ts_username=alice@example.com
ts_password=secret123
ts_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
ts_account=12345678
cliente_cuit=27-11111111-4
`), 0o644))

	strPath := filepath.Join(dir, "es_strategy.tss")
	must(t, os.WriteFile(strPath, []byte(`<Strategy>
<Symbol>ES</Symbol>
AutomatedTrading="true"
account_id=12345678
</Strategy>`), 0o644))

	olPath := filepath.Join(dir, "orderlog.txt")
	must(t, os.WriteFile(olPath, []byte(`2026-06-15 09:30:01 OrderFilled symbol=AAPL qty=100 px=200.50
2026-06-15 09:30:02 OrderFilled symbol=ES/JUN26 qty=2 px=5400.25
2026-06-15 09:30:03 OrderFilled symbol=MSFT qty=50 px=425
account_id=12345678
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "TradeStation 10.0")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "tsserver.cfg"),
		[]byte(`[TradeStation]`), 0o644))

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
		t.Fatalf("want 3 (cfg+str+ol), got %d: %+v", len(got), got)
	}

	var cfg, str, ol Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case strPath:
			str = r
		case olPath:
			ol = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if !cfg.HasAPICredentials {
		t.Fatalf("cfg must flag api creds: %+v", cfg)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cliente = exposure: %+v", cfg)
	}

	if str.ArtifactKind != KindStrategy {
		t.Fatalf("str kind=%q", str.ArtifactKind)
	}
	if !str.HasStrategyAutotrade {
		t.Fatalf("str must flag autotrade: %+v", str)
	}
	if !str.HasCMEFutures {
		t.Fatalf("str must flag CME: %+v", str)
	}
	if str.AccountClass != AccountAlgotrader {
		t.Fatalf("str account=%q want algotrader", str.AccountClass)
	}

	if ol.ArtifactKind != KindOrderLog {
		t.Fatalf("ol kind=%q", ol.ArtifactKind)
	}
	if !ol.HasOrderLogExport {
		t.Fatalf("ol must flag orderlog: %+v", ol)
	}
	if ol.FillCount < 3 {
		t.Fatalf("ol fills=%d", ol.FillCount)
	}
	if !ol.HasUSEquity {
		t.Fatalf("ol must flag US equity: %+v", ol)
	}
	if !ol.HasCMEFutures {
		t.Fatalf("ol must flag CME: %+v", ol)
	}
	if !ol.HasCrossVenueArb {
		t.Fatalf("ol must flag cross-venue: %+v", ol)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-ts")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "tsserver.cfg"),
		[]byte(`[TradeStation]
ts_account=12345678
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "TRADESTATION_DIR" {
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
		installRoots: []string{"/nope-ts"},
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
		{FilePath: "a", ArtifactKind: KindOrderLog},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,ts-config)", in[0])
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
