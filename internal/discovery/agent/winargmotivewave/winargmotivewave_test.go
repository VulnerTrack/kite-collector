package winargmotivewave

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "motivewave-config"},
		{string(KindCredentials), "motivewave-credentials"},
		{string(KindWorkspace), "motivewave-workspace"},
		{string(KindTemplate), "motivewave-template"},
		{string(KindJavaStrategy), "motivewave-java-strategy"},
		{string(KindClassCompiled), "motivewave-class-compiled"},
		{string(KindExtensionPack), "motivewave-extension-pack"},
		{string(KindConnectionConfig), "motivewave-connection-config"},
		{string(KindDOMConfig), "motivewave-dom-config"},
		{string(KindSessionLog), "motivewave-session-log"},
		{string(KindInstaller), "motivewave-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountTechnicalAnalyst), "technical-analyst"},
		{string(AccountElliottWaveTrader), "elliott-wave-trader"},
		{string(AccountProFutures), "pro-futures"},
		{string(AccountPropTrader), "prop-trader"},
		{string(AccountHFT), "hft"},
		{string(AccountBacktestResearcher), "backtest-researcher"},
		{string(AccountAlgotrader), "algotrader"},
		{string(AccountAPI), "api"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(ProductMATbaRofex), "matba-rofex"},
		{string(ProductCMEFutures), "cme-futures"},
		{string(ProductUSEquity), "us-equity"},
		{string(ProductMultiAsset), "multi-asset"},
		{string(ProductOptions), "options"},
		{string(ProductForex), "forex"},
		{string(ProductHFTExecution), "hft-execution"},
		{string(ProductOther), "other"},
		{string(ProductUnknown), "unknown"},
		{string(PluginIB), "ib"},
		{string(PluginRithmic), "rithmic"},
		{string(PluginCQG), "cqg"},
		{string(PluginIQFeed), "iqfeed"},
		{string(PluginTradeStation), "tradestation"},
		{string(PluginTradeKing), "tradeking"},
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
		"motivewave.cfg",
		"motivewave_credentials.json",
		"my_workspace.mwk",
		"my_template.mwt",
		"my_strategy.java",
		"motivewave_strategy.class",
		"motivewave_extension.zip",
		"elliott_wave_cfg.json",
		"dom_config.json",
		"motivewave_session.log",
		"motivewave_installer.msi",
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
		"motivewave.cfg":              KindConfig,
		"motivewave_credentials.json": KindCredentials,
		"motivewave_api_token.json":   KindCredentials,
		"my_workspace.mwk":            KindWorkspace,
		"my_template.mwt":             KindTemplate,
		"strategy_xyz.java":           KindJavaStrategy,
		"motivewave_strategy.class":   KindClassCompiled,
		"motivewave_extension.zip":    KindExtensionPack,
		"study_pack.jar":              KindExtensionPack,
		"broker_profile_ib.cfg":       KindConnectionConfig,
		"dom_config.json":             KindDOMConfig,
		"motivewave_session.log":      KindSessionLog,
		"motivewave_installer.msi":    KindInstaller,
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
	if PeriodFromFilename("motivewave_session_202506.log") != "202506" {
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

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindWorkspace, KindTemplate,
		KindJavaStrategy, KindClassCompiled, KindExtensionPack,
		KindConnectionConfig, KindDOMConfig, KindSessionLog,
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

func TestAnnotateJavaStrategyAuto(t *testing.T) {
	r := Row{ArtifactKind: KindJavaStrategy}
	AnnotateSecurity(&r)
	if !r.HasJavaAlgoStrategy {
		t.Fatal("java strategy kind must auto-flag")
	}
}

func TestAnnotateExtensionPackAuto(t *testing.T) {
	r := Row{ArtifactKind: KindExtensionPack}
	AnnotateSecurity(&r)
	if !r.HasThirdPartyExtension {
		t.Fatal("extension-pack kind must auto-flag")
	}
}

func TestAnnotateElliottWaveAuto(t *testing.T) {
	r := Row{
		ArtifactKind:         KindConfig,
		ElliottWaveRuleCount: 3,
	}
	AnnotateSecurity(&r)
	if !r.HasElliottWaveRules {
		t.Fatal("EW rule count > 0 must flag")
	}
}

func TestAnnotateCrossVenue(t *testing.T) {
	r := Row{
		ArtifactKind:         KindWorkspace,
		MATbaSymbolsCount:    1,
		CMESymbolsCount:      1,
		USEquitySymbolsCount: 1,
	}
	AnnotateSecurity(&r)
	if !r.HasMATbaRofexRouting {
		t.Fatal("MATba count must flag")
	}
	if !r.HasCMEFutures {
		t.Fatal("CME count must flag")
	}
	if !r.HasUSEquity {
		t.Fatal("US count must flag")
	}
	if !r.HasCrossVenueArb {
		t.Fatal("multi-venue must flag cross-venue")
	}
}

func TestAnnotateHighMsgRate(t *testing.T) {
	r := Row{
		ArtifactKind:  KindSessionLog,
		PeakMsgPerSec: 1500,
	}
	AnnotateSecurity(&r)
	if !r.HasHighMessageRate {
		t.Fatal("1500/s must flag HFT")
	}
}

func TestParseMWConfig(t *testing.T) {
	body := []byte(`# MotiveWave config
motivewave_username=alice@example.com
motivewave_password=secret123
broker_password=AnotherSecret
api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
motivewave_account=ACME-001
[IB]
tws_port=7497
tws_username=alice
elliott_wave_rule=enabled
EW_count=true
fibonacci_retrace=0.618
paper_trading=true
symbol=DLR
symbol=ES
symbol=AAPL
cliente_cuit=27-11111111-4
`)
	f := ParseMWConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.MotiveWaveAccountID == "" {
		t.Fatalf("account=%q", f.MotiveWaveAccountID)
	}
	if f.BrokerPlugin != PluginIB {
		t.Fatalf("plugin=%q want ib", f.BrokerPlugin)
	}
	if !f.HasPaperTradingMode {
		t.Fatal("paper-trading must flag")
	}
	if f.ElliottWaveRuleCount < 3 {
		t.Fatalf("EW rules=%d want >=3", f.ElliottWaveRuleCount)
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
}

func TestParseMWJavaStrategy(t *testing.T) {
	body := []byte(`package com.example;
import com.motivewave.platform.sdk.study.Strategy;
import com.motivewave.platform.sdk.common.StrategyHeader;

@StrategyHeader(name="MyStrategy")
public class MyStrategy extends Strategy {
    @Override
    public void onBar() {
        if (isElliottWavePeak()) {
            // submit short
        }
    }
}
api_key="aBcDeFgHiJkLmNoPqRsTuVwX12345"
`)
	f := ParseMWJavaStrategy(body)
	if f.StrategyCount < 1 {
		t.Fatalf("strategies=%d", f.StrategyCount)
	}
	if f.ElliottWaveRuleCount < 1 {
		t.Fatalf("EW=%d", f.ElliottWaveRuleCount)
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
}

func TestParseMWDOMArmed(t *testing.T) {
	body := []byte(`[DOM]
dom_armed=true
auto_execute=1
one_click_trading=true
`)
	f := ParseMWDOMConfig(body)
	if !f.HasDOMArmed {
		t.Fatal("DOM armed must flag")
	}
}

func TestParseMWEmpty(t *testing.T) {
	f := ParseMWConfig(nil)
	if f.HasPassword || f.APIKey != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestDetectBrokerPlugin(t *testing.T) {
	cases := map[string]BrokerPlugin{
		`[Rithmic]`:      PluginRithmic,
		`[CQG]`:          PluginCQG,
		`[IQFeed]`:       PluginIQFeed,
		`[TradeStation]`: PluginTradeStation,
		`[TradeKing]`:    PluginTradeKing,
		`tws_port=7497`:  PluginIB,
		`[plugin]`:       PluginCustom,
		`generic config`: PluginUnknown,
	}
	for in, want := range cases {
		got := detectBrokerPlugin([]byte(in))
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyAccount(t *testing.T) {
	if got := classifyAccount(Row{HasDOMArmed: true}); got != AccountHFT {
		t.Fatalf("DOM -> hft, got %q", got)
	}
	if got := classifyAccount(Row{HasElliottWaveRules: true}); got != AccountElliottWaveTrader {
		t.Fatalf("EW -> elliott-wave-trader, got %q", got)
	}
	if got := classifyAccount(Row{HasJavaAlgoStrategy: true}); got != AccountAlgotrader {
		t.Fatalf("java -> algotrader, got %q", got)
	}
	if got := classifyAccount(Row{HasCrossVenueArb: true}); got != AccountAlgotrader {
		t.Fatalf("cross-venue -> algotrader, got %q", got)
	}
	if got := classifyAccount(Row{HasCMEFutures: true}); got != AccountProFutures {
		t.Fatalf("cme -> pro-futures, got %q", got)
	}
	if got := classifyAccount(Row{HasPaperTradingMode: true}); got != AccountBacktestResearcher {
		t.Fatalf("paper -> backtest-researcher, got %q", got)
	}
	if got := classifyAccount(Row{HasUSEquity: true}); got != AccountTechnicalAnalyst {
		t.Fatalf("us -> technical-analyst, got %q", got)
	}
	if got := classifyAccount(Row{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
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
	if got := classifyProduct(Row{HasCMEFutures: true}); got != ProductCMEFutures {
		t.Fatalf("cme -> cme-futures, got %q", got)
	}
	if got := classifyProduct(Row{HasUSEquity: true}); got != ProductUSEquity {
		t.Fatalf("us -> us-equity, got %q", got)
	}
	if got := classifyProduct(Row{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "MotiveWave")
	must(t, os.MkdirAll(dir, 0o755))

	cfgPath := filepath.Join(dir, "motivewave.cfg")
	must(t, os.WriteFile(cfgPath, []byte(`motivewave_username=alice@example.com
motivewave_password=secret123
api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
[IB]
tws_port=7497
tws_username=alice
elliott_wave_rule=enabled
EW_count=true
symbol=DLR
symbol=ES
symbol=AAPL
cliente_cuit=27-11111111-4
`), 0o644))

	stratPath := filepath.Join(dir, "elliott_strategy.java")
	must(t, os.WriteFile(stratPath, []byte(`package com.example;
import com.motivewave.platform.sdk.study.Strategy;
@StrategyHeader(name="EWStrat")
public class EWStrat extends Strategy {
    @Override public void onBar() {
        if (isElliottWavePeak()) { submitOrder(); }
    }
}
`), 0o644))

	domPath := filepath.Join(dir, "dom_config.json")
	must(t, os.WriteFile(domPath, []byte(`{
"dom_armed": true,
"auto_execute": true,
"symbol": "ES"
}`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "MotiveWave")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "motivewave.cfg"),
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
		t.Fatalf("want 3 (cfg+strat+dom), got %d: %+v", len(got), got)
	}

	var cfg, strat, dom Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case stratPath:
			strat = r
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
	if cfg.BrokerPlugin != PluginIB {
		t.Fatalf("cfg plugin=%q want ib", cfg.BrokerPlugin)
	}
	if !cfg.HasElliottWaveRules {
		t.Fatalf("cfg must flag EW: %+v", cfg)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cliente = exposure: %+v", cfg)
	}

	if strat.ArtifactKind != KindJavaStrategy {
		t.Fatalf("strat kind=%q", strat.ArtifactKind)
	}
	if !strat.HasJavaAlgoStrategy {
		t.Fatalf("strat must auto-flag: %+v", strat)
	}
	if !strat.HasElliottWaveRules {
		t.Fatalf("strat must flag EW: %+v", strat)
	}
	if strat.AccountClass != AccountElliottWaveTrader {
		t.Fatalf("strat account=%q want elliott-wave-trader", strat.AccountClass)
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
	envDir := filepath.Join(tmp, "custom-mw")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "motivewave.cfg"),
		[]byte(`motivewave_account=ACME`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "MOTIVEWAVE_DIR" {
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
		installRoots: []string{"/nope-mw"},
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
		{FilePath: "a", ArtifactKind: KindSessionLog},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,motivewave-config)", in[0])
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
