package winargninja

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "ninja-config"},
		{string(KindStrategy), "ninja-strategy"},
		{string(KindIndicator), "ninja-indicator"},
		{string(KindAddOn), "ninja-addon"},
		{string(KindWorkspace), "ninja-workspace"},
		{string(KindConnection), "ninja-connection"},
		{string(KindCompiledDLL), "ninja-compiled-dll"},
		{string(KindTradePerformance), "ninja-trade-performance"},
		{string(KindPropFirmConfig), "ninja-prop-firm-config"},
		{string(AccountPropFirmTrainee), "prop-firm-trainee"},
		{string(AccountAlgotrader), "algotrader"},
		{string(AccountFuturesDaytrader), "futures-daytrader"},
		{string(ProductFutures), "futures"},
		{string(ProductOptions), "options"},
		{string(ProductMultiAsset), "multi-asset"},
		{string(FeedContinuum), "continuum"},
		{string(FeedRithmic), "rithmic"},
		{string(FeedCQG), "cqg"},
		{string(PropFirmApex), "apex-trader-funding"},
		{string(PropFirmTopstepX), "topstepx"},
		{string(PropFirmEarn2Trade), "earn2trade"},
		{string(PropFirmMyFundedFutures), "myfundedfutures"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"MyStrategy.cs",
		"NinjaTrader.Custom.dll",
		"Connections.xml",
		"workspace_intraday.xml",
		"TradePerformance-20260615.csv",
		"apex_trader_funding.json",
		"topstepx_account.json",
		"earn2trade.json",
		"chart_template_es.xml",
		"strategy_template_momentum.xml",
		"continuum_creds.xml",
		"NinjaTrader 8 Setup.msi",
		"strategy_export.zip",
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
		"momentum_strategy.cs":           KindStrategy,
		"my_indicator.cs":                KindIndicator,
		"custom_addon.cs":                KindAddOn,
		"NinjaTrader.Custom.dll":         KindCompiledDLL,
		"workspace_intraday.xml":         KindWorkspace,
		"chart_template_es.xml":          KindChartTemplate,
		"strategy_template_momentum.xml": KindStrategyTemplate,
		"Connections.xml":                KindConnection,
		"TradePerformance-20260615.csv":  KindTradePerformance,
		"apex_trader_funding.json":       KindPropFirmConfig,
		"topstepx_account.json":          KindPropFirmConfig,
		"earn2trade.json":                KindPropFirmConfig,
		"NinjaTrader 8 Setup.msi":        KindInstaller,
		"strategy_export.zip":            KindExportPackage,
		"trace_20260615.log":             KindLog,
		"ninja_config.json":              KindConfig,
		"credentials.json":               KindCredentials,
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
	cases := map[string]string{
		"TradePerformance-20260615.csv": "202606",
		"trace_20260615.log":            "202606",
		"workspace.xml":                 "",
	}
	for in, want := range cases {
		if got := PeriodFromFilename(in); got != want {
			t.Fatalf("PeriodFromFilename(%q)=%q want %q", in, got, want)
		}
	}
}

func TestFuturesStem(t *testing.T) {
	yes := []string{"ES", "NQ", "MES", "MNQ", "MGC", "MCL", "ZN"}
	no := []string{"", "AAPL", "MSFT"}
	for _, v := range yes {
		if !IsFuturesStem(v) {
			t.Fatalf("expected futures: %q", v)
		}
	}
	for _, v := range no {
		if IsFuturesStem(v) {
			t.Fatalf("expected NOT futures: %q", v)
		}
	}
}

func TestMicroFuturesStem(t *testing.T) {
	yes := []string{"MES", "MNQ", "M2K", "MYM", "MGC", "MCL", "M6E"}
	no := []string{"", "ES", "NQ", "GC", "AAPL"}
	for _, v := range yes {
		if !IsMicroFuturesStem(v) {
			t.Fatalf("expected micro: %q", v)
		}
	}
	for _, v := range no {
		if IsMicroFuturesStem(v) {
			t.Fatalf("expected NOT micro: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindStrategy, KindIndicator,
		KindAddOn, KindWorkspace, KindConnection, KindCompiledDLL,
		KindTradePerformance, KindPropFirmConfig,
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
		ArtifactKind:        KindConnection,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.HasConnectionCredentials {
		t.Fatal("connection kind must auto-flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + cliente = exposure")
	}
}

func TestAnnotateStrategyAuto(t *testing.T) {
	r := Row{ArtifactKind: KindStrategy, EnterOrderCallCount: 3}
	AnnotateSecurity(&r)
	if !r.HasNinjaScriptStrategy {
		t.Fatal("strategy kind + order calls must flag")
	}
}

func TestAnnotateAddOnAuto(t *testing.T) {
	r := Row{ArtifactKind: KindAddOn}
	AnnotateSecurity(&r)
	if !r.HasNinjaScriptAddOn {
		t.Fatal("addon kind must flag")
	}
}

func TestAnnotatePDT(t *testing.T) {
	r := Row{ArtifactKind: KindTradePerformance, FillCount: 10}
	AnnotateSecurity(&r)
	if !r.HasPatternDayTrader {
		t.Fatal("≥4 fills in trade-performance must flag PDT")
	}
	if !r.HasTradePerformanceExport {
		t.Fatal("trade-performance kind must flag export")
	}
}

func TestAnnotateHighVolume(t *testing.T) {
	r := Row{
		ArtifactKind: KindTradePerformance,
		FillCount:    HighVolumeTraderDailyFills + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasHighVolumeTrader {
		t.Fatal("> 1000 fills must flag high-volume")
	}
}

func TestParseNinjaConfig(t *testing.T) {
	body := []byte(`<NinjaConnection>
  <username>alice@example.com</username>
  <password>secret123</password>
  <ninja_api_key>aBcDeFgHiJkLmNoPqRsTuVwX12345</ninja_api_key>
  <account_id>APX12345</account_id>
  <feed>Continuum</feed>
  <prop_firm>Apex Trader Funding</prop_firm>
  <symbol>ES 09-26</symbol>
  <symbol>MES 09-26</symbol>
  <cliente_cuit>27-11111111-4</cliente_cuit>
</NinjaConnection>`)
	f := ParseNinjaConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if f.NinjaAccountID != "APX12345" {
		t.Fatalf("account=%q", f.NinjaAccountID)
	}
	if f.DataFeed != FeedContinuum {
		t.Fatalf("feed=%q want continuum", f.DataFeed)
	}
	if !f.HasApexProp {
		t.Fatal("apex marker must flag")
	}
	if f.PropFirm != PropFirmApex {
		t.Fatalf("prop firm=%q want apex", f.PropFirm)
	}
	if f.FuturesSymbolsCount < 2 {
		t.Fatalf("futures=%d", f.FuturesSymbolsCount)
	}
	if f.MicroFuturesCount < 1 {
		t.Fatalf("micro=%d", f.MicroFuturesCount)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cuit must extract")
	}
}

func TestParseNinjaStrategy(t *testing.T) {
	body := []byte(`namespace NinjaTrader.NinjaScript.Strategies
{
    public class MomentumStrategy : Strategy
    {
        protected override void OnBarUpdate()
        {
            if (Close[0] > Open[0])
            {
                EnterLong(1, "Buy");
                EnterShortLimit(1, Close[0] + 1, "ShortLimit");
                SubmitOrderUnmanaged(0, OrderAction.Buy, OrderType.Market, 1, 0, 0, "", "OCO");
            }
        }
    }
}`)
	f := ParseNinjaStrategy(body)
	if !f.HasNinjaStrategy {
		t.Fatal("strategy class must flag")
	}
	if f.EnterOrderCallCount < 3 {
		t.Fatalf("order-call count=%d want >=3", f.EnterOrderCallCount)
	}
}

func TestParseNinjaAddOn(t *testing.T) {
	body := []byte(`namespace NinjaTrader.NinjaScript.AddOns
{
    public class MyCustomAddOn : AddOnBase
    {
        protected override void OnStateChange() { }
    }
}`)
	f := ParseNinjaAddOn(body)
	if !f.HasNinjaAddOn {
		t.Fatal("addon class must flag")
	}
	if f.AddOnCount < 1 {
		t.Fatalf("addon count=%d", f.AddOnCount)
	}
}

func TestParseNinjaTradePerformance(t *testing.T) {
	body := []byte(`Instrument,Account,Strategy,MarketPosition,Quantity,EntryPrice,ExitPrice
MES 09-26,APX12345,Momentum,Long,1,5000.25,5005.00
MNQ 09-26,APX12345,Momentum,Short,1,18000.50,17995.25
MGC 12-26,APX12345,Scalper,Long,1,2050.10,2055.00
MES 09-26,APX12345,Momentum,Long,2,5010.00,5015.50
MCL 09-26,APX12345,Energy,Short,1,72.50,72.10
account_id=APX12345
`)
	f := ParseNinjaTradePerformance(body)
	if f.FillCount < 5 {
		t.Fatalf("fills=%d", f.FillCount)
	}
	if f.NinjaAccountID != "APX12345" {
		t.Fatalf("account=%q", f.NinjaAccountID)
	}
	if f.MicroFuturesCount < 1 {
		t.Fatalf("micro=%d", f.MicroFuturesCount)
	}
}

func TestDetectDataFeed(t *testing.T) {
	cases := map[string]DataFeed{
		`feed=Continuum`:           FeedContinuum,
		`feed=Rithmic`:             FeedRithmic,
		`feed=CQG`:                 FeedCQG,
		`feed=Kinetick`:            FeedKinetick,
		`feed=IQFeed`:              FeedIQFeed,
		`feed=Tradovate`:           FeedTradovate,
		`feed=AMP Futures`:         FeedAMPFutures,
		`feed=Interactive Brokers`: FeedInteractiveBrokers,
		`# generic config`:         FeedUnknown,
	}
	for in, want := range cases {
		got := detectDataFeed([]byte(in))
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectPropFirm(t *testing.T) {
	cases := []struct {
		in            string
		wantPF        PropFirm
		apex, top, e2 bool
	}{
		{"prop_firm=Apex Trader Funding", PropFirmApex, true, false, false},
		{"prop_firm=TopstepX", PropFirmTopstepX, false, true, false},
		{"prop_firm=Earn2Trade", PropFirmEarn2Trade, false, false, true},
		{"prop_firm=MyFundedFutures", PropFirmMyFundedFutures, false, false, false},
		{"prop_firm=Bulenox", PropFirmBulenox, false, false, false},
		{"prop_firm=The Trading Pit", PropFirmTheTradingPit, false, false, false},
		{"prop_firm=FTMO", PropFirmFTMO, false, false, false},
		{"# generic", PropFirmUnknown, false, false, false},
	}
	for _, c := range cases {
		gotPF, gotApex, gotTop, gotE2 := detectPropFirm([]byte(c.in))
		if gotPF != c.wantPF || gotApex != c.apex || gotTop != c.top || gotE2 != c.e2 {
			t.Fatalf("detect(%q)=(%q,%v,%v,%v) want (%q,%v,%v,%v)",
				c.in, gotPF, gotApex, gotTop, gotE2,
				c.wantPF, c.apex, c.top, c.e2)
		}
	}
}

func TestPythonBridgeDetect(t *testing.T) {
	body := []byte(`using IronPython.Hosting;
var engine = Python.CreateEngine();
`)
	f := ParseNinjaAddOn(body)
	if !f.HasPythonBridge {
		t.Fatal("python bridge must flag")
	}
}

func TestClassifyAccount(t *testing.T) {
	if got := classifyAccount(Row{HasPatternDayTrader: true}); got != AccountPatternDayTrader {
		t.Fatalf("PDT -> pattern-day-trader, got %q", got)
	}
	if got := classifyAccount(Row{HasConnectionCredentials: true, HasPasswordInConfig: true}); got != AccountComplianceOfficer {
		t.Fatalf("conn+pwd -> compliance, got %q", got)
	}
	if got := classifyAccount(Row{HasHighVolumeTrader: true}); got != AccountScalper {
		t.Fatalf("high-volume -> scalper, got %q", got)
	}
	if got := classifyAccount(Row{HasNinjaScriptStrategy: true, EnterOrderCallCount: 3}); got != AccountAlgotrader {
		t.Fatalf("strategy+orders -> algotrader, got %q", got)
	}
	if got := classifyAccount(Row{HasApexProp: true}); got != AccountPropFirmTrainee {
		t.Fatalf("apex -> prop-firm-trainee, got %q", got)
	}
	if got := classifyAccount(Row{HasTopstepXProp: true}); got != AccountPropFirmTrainee {
		t.Fatalf("topstepx -> prop-firm-trainee, got %q", got)
	}
	if got := classifyAccount(Row{HasTradePerformanceExport: true}); got != AccountFuturesDaytrader {
		t.Fatalf("perf -> futures-daytrader, got %q", got)
	}
	if got := classifyAccount(Row{HasConnectionCredentials: true}); got != AccountPropTrader {
		t.Fatalf("conn -> prop-trader, got %q", got)
	}
	if got := classifyAccount(Row{HasCompiledOnlyDLL: true}); got != AccountAPI {
		t.Fatalf("compiled-only -> api, got %q", got)
	}
	if got := classifyAccount(Row{HasNinjaScriptAddOn: true}); got != AccountAPI {
		t.Fatalf("addon -> api, got %q", got)
	}
	if got := classifyAccount(Row{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyProduct(t *testing.T) {
	if got := classifyProduct(Row{HasFutures: true, OptionsSymbolsCount: 1}); got != ProductMultiAsset {
		t.Fatalf("fut+opt -> multi-asset, got %q", got)
	}
	if got := classifyProduct(Row{HasFutures: true}); got != ProductFutures {
		t.Fatalf("fut -> futures, got %q", got)
	}
	if got := classifyProduct(Row{OptionsSymbolsCount: 1}); got != ProductOptions {
		t.Fatalf("opt -> options, got %q", got)
	}
	if got := classifyProduct(Row{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	docs := filepath.Join(usersBase, "alice", "Documents", "NinjaTrader 8")
	custom := filepath.Join(docs, "bin", "Custom", "Strategies")
	addons := filepath.Join(docs, "bin", "Custom", "AddOns")
	dbConn := filepath.Join(docs, "db", "Connections")
	perf := filepath.Join(docs, "Performance")
	apex := filepath.Join(docs, "Apex")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.MkdirAll(addons, 0o755))
	must(t, os.MkdirAll(dbConn, 0o755))
	must(t, os.MkdirAll(perf, 0o755))
	must(t, os.MkdirAll(apex, 0o755))

	stratPath := filepath.Join(custom, "MomentumStrategy.cs")
	must(t, os.WriteFile(stratPath, []byte(`namespace NinjaTrader.NinjaScript.Strategies
{
    public class MomentumStrategy : Strategy
    {
        protected override void OnBarUpdate()
        {
            EnterLong(1, "Buy");
            EnterShort(1, "Short");
            SubmitOrderUnmanaged(0, OrderAction.Buy, OrderType.Market, 1, 0, 0, "", "OCO");
        }
    }
}
`), 0o644))

	addonPath := filepath.Join(addons, "MyCustomAddOn.cs")
	must(t, os.WriteFile(addonPath, []byte(`using IronPython.Hosting;
namespace NinjaTrader.NinjaScript.AddOns
{
    public class MyCustomAddOn : AddOnBase
    {
        protected override void OnStateChange() { }
    }
}
`), 0o644))

	connPath := filepath.Join(dbConn, "Connections.xml")
	must(t, os.WriteFile(connPath, []byte(`<Connections>
  <Connection>
    <Name>Continuum</Name>
    <username>alice</username>
    <password>secret123</password>
    <account_id>APX12345</account_id>
    <cliente_cuit>27-11111111-4</cliente_cuit>
  </Connection>
</Connections>
`), 0o644))

	perfPath := filepath.Join(perf, "TradePerformance-20260615.csv")
	must(t, os.WriteFile(perfPath, []byte(`Instrument,Account,Strategy,MarketPosition,Quantity,EntryPrice,ExitPrice
MES 09-26,APX12345,Momentum,Long,1,5000.25,5005.00
MNQ 09-26,APX12345,Momentum,Short,1,18000.50,17995.25
MGC 12-26,APX12345,Scalper,Long,1,2050.10,2055.00
MES 09-26,APX12345,Momentum,Long,2,5010.00,5015.50
MCL 09-26,APX12345,Energy,Short,1,72.50,72.10
`), 0o644))

	apexPath := filepath.Join(apex, "apex_trader_funding.json")
	must(t, os.WriteFile(apexPath, []byte(`{"prop_firm":"Apex Trader Funding","account_id":"APX12345"}
`), 0o644))

	must(t, os.WriteFile(filepath.Join(docs, "random.txt"),
		[]byte(`nope`), 0o644))

	pub := filepath.Join(usersBase, "Public", "Documents", "NinjaTrader 8")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "ninja_config.json"),
		[]byte(`{}`), 0o644))

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
		t.Fatalf("want 5 (strat+addon+conn+perf+apex), got %d: %+v", len(got), got)
	}

	var strat, addon, conn, perfRow, apexRow Row
	for _, r := range got {
		switch r.FilePath {
		case stratPath:
			strat = r
		case addonPath:
			addon = r
		case connPath:
			conn = r
		case perfPath:
			perfRow = r
		case apexPath:
			apexRow = r
		}
	}

	if strat.ArtifactKind != KindStrategy {
		t.Fatalf("strat kind=%q", strat.ArtifactKind)
	}
	if !strat.HasNinjaScriptStrategy {
		t.Fatalf("strat must flag NinjaScript: %+v", strat)
	}
	if strat.EnterOrderCallCount < 3 {
		t.Fatalf("strat order count=%d", strat.EnterOrderCallCount)
	}
	if strat.AccountClass != AccountAlgotrader {
		t.Fatalf("strat should classify as algotrader, got %q", strat.AccountClass)
	}

	if addon.ArtifactKind != KindAddOn {
		t.Fatalf("addon kind=%q", addon.ArtifactKind)
	}
	if !addon.HasNinjaScriptAddOn {
		t.Fatalf("addon must flag: %+v", addon)
	}
	if !addon.HasPythonBridge {
		t.Fatalf("addon must flag python bridge: %+v", addon)
	}

	if conn.ArtifactKind != KindConnection {
		t.Fatalf("conn kind=%q", conn.ArtifactKind)
	}
	if !conn.HasConnectionCredentials {
		t.Fatalf("conn must flag: %+v", conn)
	}
	if conn.DataFeed != FeedContinuum {
		t.Fatalf("conn feed=%q want continuum", conn.DataFeed)
	}
	if !conn.HasClienteCuit {
		t.Fatalf("conn must flag cliente cuit: %+v", conn)
	}
	if !conn.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cliente = exposure: %+v", conn)
	}
	if conn.AccountClass != AccountComplianceOfficer {
		t.Fatalf("conn+pwd should classify as compliance, got %q", conn.AccountClass)
	}

	if perfRow.ArtifactKind != KindTradePerformance {
		t.Fatalf("perf kind=%q", perfRow.ArtifactKind)
	}
	if !perfRow.HasTradePerformanceExport {
		t.Fatalf("perf must auto-flag: %+v", perfRow)
	}
	if !perfRow.HasPatternDayTrader {
		t.Fatalf("perf must flag PDT: %+v", perfRow)
	}
	if !perfRow.HasMicroFutures {
		t.Fatalf("perf must flag micro: %+v", perfRow)
	}
	if perfRow.AccountClass != AccountPatternDayTrader {
		t.Fatalf("perf should classify as PDT, got %q", perfRow.AccountClass)
	}

	if apexRow.ArtifactKind != KindPropFirmConfig {
		t.Fatalf("apex kind=%q", apexRow.ArtifactKind)
	}
	if !apexRow.HasApexProp {
		t.Fatalf("apex must flag apex prop: %+v", apexRow)
	}
	if apexRow.AccountClass != AccountPropFirmTrainee {
		t.Fatalf("apex should classify as prop-firm-trainee, got %q", apexRow.AccountClass)
	}
}

func TestCompiledOnlyDetection(t *testing.T) {
	tmp := t.TempDir()
	binCustom := filepath.Join(tmp, "Users", "alice", "Documents",
		"NinjaTrader 8", "bin", "Custom")
	must(t, os.MkdirAll(binCustom, 0o755))
	dllPath := filepath.Join(binCustom, "NinjaTrader.Custom.dll")
	must(t, os.WriteFile(dllPath, []byte("MZ\x90\x00mock-pe-bytes"), 0o644))
	// No .cs alongside — compiled-only.

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{filepath.Join(tmp, "Users")},
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
	if len(got) != 1 {
		t.Fatalf("want 1 dll, got %d", len(got))
	}
	if got[0].ArtifactKind != KindCompiledDLL {
		t.Fatalf("kind=%q", got[0].ArtifactKind)
	}
	if !got[0].HasCompiledOnlyDLL {
		t.Fatalf("must flag compiled-only: %+v", got[0])
	}
	if got[0].AccountClass != AccountAPI {
		t.Fatalf("compiled-only should classify as api, got %q", got[0].AccountClass)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-ninja")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "ninja_config.json"),
		[]byte(`{"password":"hello"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "NINJATRADER_DIR" {
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
		installRoots: []string{"/nope-ninja"},
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
		{FilePath: "/b", ArtifactKind: KindConfig},
		{FilePath: "/a", ArtifactKind: KindTradePerformance},
		{FilePath: "/a", ArtifactKind: KindConfig},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindConfig {
		t.Fatalf("sort drift: %+v", rs)
	}
	if rs[1].FilePath != "/a" || rs[1].ArtifactKind != KindTradePerformance {
		t.Fatalf("sort drift: %+v", rs)
	}
	if rs[2].FilePath != "/b" {
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
