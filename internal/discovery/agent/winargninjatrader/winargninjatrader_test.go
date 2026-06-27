package winargninjatrader

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindStrategyCS), "ninja-strategy-cs"},
		{string(KindIndicatorCS), "ninja-indicator-cs"},
		{string(KindBarTypeCS), "ninja-bartype-cs"},
		{string(KindDrawingCS), "ninja-drawing-cs"},
		{string(KindAddonCS), "ninja-addon-cs"},
		{string(KindTemplatesXML), "ninja-templates-xml"},
		{string(KindAccountDB), "ninja-account-db"},
		{string(KindInstrumentDB), "ninja-instrument-db"},
		{string(KindPositionCache), "ninja-position-cache"},
		{string(KindLog), "ninja-log"},
		{string(KindInstaller), "ninja-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountLive), "live"},
		{string(AccountDemo), "demo"},
		{string(AccountReplay), "replay"},
		{string(AccountContinuousFutures), "continuous-futures"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(BrokerNinjaTraderBrokerage), "ninjatrader-brokerage"},
		{string(BrokerContinuum), "continuum-data"},
		{string(BrokerKinetick), "kinetick"},
		{string(BrokerRithmic), "rithmic"},
		{string(BrokerAMPFutures), "amp-futures"},
		{string(BrokerTradeStation), "tradestation"},
		{string(BrokerInteractiveBrokers), "interactive-brokers"},
		{string(BrokerOther), "other"},
		{string(BrokerUnknown), "unknown"},
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
		"helper.dll",
		"connections.xml",
		"templates_chart.xml",
		"accounts.db",
		"instruments.db",
		"positions.db",
		"Output_20260615.txt",
		"Trace_20260615.txt",
		"ninjatrader_install.exe",
	}
	no := []string{"", "factura.xml", "random.pdf"}
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

func TestArtifactKindFromPath(t *testing.T) {
	cases := map[string]ArtifactKind{
		`C:\Users\alice\Documents\NinjaTrader 8\bin\Custom\Strategies\MyEA.cs`:   KindStrategyCS,
		`C:\Users\alice\Documents\NinjaTrader 8\bin\Custom\Indicators\MyInd.cs`:  KindIndicatorCS,
		`C:\Users\alice\Documents\NinjaTrader 8\bin\Custom\BarsTypes\MyBar.cs`:   KindBarTypeCS,
		`C:\Users\alice\Documents\NinjaTrader 8\bin\Custom\DrawingTools\Draw.cs`: KindDrawingCS,
		`C:\Users\alice\Documents\NinjaTrader 8\bin\Custom\AddOns\MyAddon.cs`:    KindAddonCS,
		`C:\Users\alice\Documents\NinjaTrader 8\bin\helper.dll`:                  KindAddonCS,
		`C:\Users\alice\Documents\NinjaTrader 8\db\accounts.db`:                  KindAccountDB,
		`C:\Users\alice\Documents\NinjaTrader 8\db\instruments.db`:               KindInstrumentDB,
		`C:\Users\alice\Documents\NinjaTrader 8\db\positions.db`:                 KindPositionCache,
		`C:\Users\alice\Documents\NinjaTrader 8\log\Output_20260615.txt`:         KindLog,
		`C:\Users\alice\Documents\NinjaTrader 8\templates\Strategy\MyStrat.xml`:  KindTemplatesXML,
		`C:\Setup\ninjatrader_v8_installer.exe`:                                  KindInstaller,
		"":                                                                       KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromPath(in); got != want {
			t.Fatalf("ArtifactKindFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBrokerRouteFromBody(t *testing.T) {
	cases := map[string]BrokerRoute{
		`<endpoint>rithmic.com/api</endpoint>`:          BrokerRithmic,
		`<endpoint>https://www.continuum.io</endpoint>`: BrokerContinuum,
		`<endpoint>kinetick.com</endpoint>`:             BrokerKinetick,
		`<endpoint>ampfutures.com</endpoint>`:           BrokerAMPFutures,
		`<endpoint>tradestation.com</endpoint>`:         BrokerTradeStation,
		`<endpoint>interactivebrokers.com</endpoint>`:   BrokerInteractiveBrokers,
		`<endpoint>ibkr.com</endpoint>`:                 BrokerInteractiveBrokers,
		`<endpoint>ninjatraderbrokerage.com</endpoint>`: BrokerNinjaTraderBrokerage,
		`Rithmic R | Order: live session`:               BrokerRithmic,
		`<endpoint>unknown</endpoint>`:                  BrokerUnknown,
		"":                                              BrokerUnknown,
	}
	for in, want := range cases {
		if got := BrokerRouteFromBody([]byte(in)); got != want {
			t.Fatalf("BrokerRouteFromBody(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsLiveBrokerRoute(t *testing.T) {
	yes := []BrokerRoute{
		BrokerRithmic, BrokerAMPFutures, BrokerInteractiveBrokers,
		BrokerNinjaTraderBrokerage, BrokerTradeStation,
	}
	no := []BrokerRoute{
		BrokerContinuum, BrokerKinetick, BrokerOther, BrokerUnknown,
	}
	for _, v := range yes {
		if !IsLiveBrokerRoute(v) {
			t.Fatalf("expected live: %q", v)
		}
	}
	for _, v := range no {
		if IsLiveBrokerRoute(v) {
			t.Fatalf("expected NOT live: %q", v)
		}
	}
}

func TestIsArgentineFuturesSymbol(t *testing.T) {
	yes := []string{"DLR", "DOM", "ROS", "DLRMAR26", "SOJ", "MAI"}
	no := []string{"ES", "NQ", "CL", "GC", "BTC", "", "FOO"}
	for _, v := range yes {
		if !IsArgentineFuturesSymbol(v) {
			t.Fatalf("expected ARG futures: %q", v)
		}
	}
	for _, v := range no {
		if IsArgentineFuturesSymbol(v) {
			t.Fatalf("expected NOT ARG futures: %q", v)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("Output_202506.txt") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.txt") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsStrategyOrAddonKind(t *testing.T) {
	yes := []ArtifactKind{
		KindStrategyCS, KindIndicatorCS, KindBarTypeCS,
		KindDrawingCS, KindAddonCS,
	}
	no := []ArtifactKind{
		KindTemplatesXML, KindAccountDB, KindInstrumentDB,
		KindPositionCache, KindLog, KindInstaller,
		KindOther, KindUnknown,
	}
	for _, k := range yes {
		if !IsStrategyOrAddonKind(k) {
			t.Fatalf("expected strategy/addon: %q", k)
		}
	}
	for _, k := range no {
		if IsStrategyOrAddonKind(k) {
			t.Fatalf("expected NOT strategy/addon: %q", k)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateCompiledStrategy(t *testing.T) {
	r := Row{
		ArtifactKind: KindStrategyCS,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasCompiledStrategy {
		t.Fatal(".cs strategy must flag compiled")
	}
}

func TestAnnotateLiveBrokerRoute(t *testing.T) {
	r := Row{
		ArtifactKind: KindTemplatesXML,
		BrokerRoute:  BrokerRithmic,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasLiveBrokerRoute {
		t.Fatal("rithmic must flag live route")
	}
}

func TestAnnotateAccountCredentials(t *testing.T) {
	r := Row{
		ArtifactKind: KindAccountDB,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasAccountCredentials {
		t.Fatal("accounts.db must flag credentials")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + accounts.db = exposure")
	}
}

func TestAnnotateOverfitOptimizer(t *testing.T) {
	r := Row{
		ArtifactKind:        KindTemplatesXML,
		OptimizerIterations: 10000,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasOverfitOptimization {
		t.Fatal("10000 iters must flag overfit")
	}
}

func TestAnnotateAddonDLL(t *testing.T) {
	r := Row{
		FilePath:     "helper.dll",
		ArtifactKind: KindAddonCS,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasAddonDLL {
		t.Fatal(".dll addon must flag")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind: KindAccountDB,
		FileMode:     0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseNTArtifact ----------------------------------------------

func TestParseNTArtifactStrategyCS(t *testing.T) {
	body := []byte(`namespace NinjaTrader.NinjaScript.Strategies
{
    public class MyROFEXStrategy : Strategy
    {
        protected override void OnStateChange()
        {
            // strategy
        }
    }
}
`)
	f := ParseNTArtifact(body)
	if f.StrategyName != "MyROFEXStrategy" {
		t.Fatalf("strategy name=%q", f.StrategyName)
	}
}

func TestParseNTArtifactConnectionsXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<connections>
  <connection>
    <Provider>Rithmic R | Order</Provider>
    <Endpoint>rithmic.com</Endpoint>
    <Login>alice_trader</Login>
    <Username>alice</Username>
    <Password>secret</Password>
    <Instrument>DLRMAR26</Instrument>
  </connection>
</connections>`)
	f := ParseNTArtifact(body)
	if f.BrokerRoute != BrokerRithmic {
		t.Fatalf("broker=%q", f.BrokerRoute)
	}
	if f.AccountLogin != "alice_trader" {
		t.Fatalf("login=%q", f.AccountLogin)
	}
	if !f.HasDataProviderLogin {
		t.Fatal("must flag data provider login")
	}
	if f.InstrumentCount < 1 {
		t.Fatalf("instr count=%d", f.InstrumentCount)
	}
	if !f.HasArgentineFutures {
		t.Fatal("DLRMAR26 must flag ARG futures")
	}
}

func TestParseNTArtifactOptimizer(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<optimization>
  <iterations>15000</iterations>
</optimization>`)
	f := ParseNTArtifact(body)
	if f.OptimizerIterations != 15000 {
		t.Fatalf("iters=%d", f.OptimizerIterations)
	}
}

func TestParseNTArtifactReplay(t *testing.T) {
	body := []byte(`market_replay session started 2026-06-15
session_id=12345
`)
	f := ParseNTArtifact(body)
	if !f.HasReplayDump {
		t.Fatal("market_replay must flag")
	}
}

func TestParseNTArtifactEmpty(t *testing.T) {
	f := ParseNTArtifact(nil)
	if f.AccountLogin != "" || f.OptimizerIterations != 0 {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	stratDir := filepath.Join(usersBase, "alice", "Documents",
		"NinjaTrader 8", "bin", "Custom", "Strategies")
	must(t, os.MkdirAll(stratDir, 0o755))
	libDir := filepath.Join(usersBase, "alice", "Documents",
		"NinjaTrader 8", "bin")
	must(t, os.MkdirAll(libDir, 0o755))
	dbDir := filepath.Join(usersBase, "alice", "Documents",
		"NinjaTrader 8", "db")
	must(t, os.MkdirAll(dbDir, 0o755))

	// Strategy .cs file, readable.
	stratPath := filepath.Join(stratDir, "MyROFEXStrategy.cs")
	must(t, os.WriteFile(stratPath, []byte(`namespace NinjaTrader.NinjaScript.Strategies
{
    public class MyROFEXStrategy : Strategy
    {
        // DLR futures strategy
    }
}
`), 0o644))

	// DLL addon, world-readable.
	dllPath := filepath.Join(libDir, "helper.dll")
	must(t, os.WriteFile(dllPath, []byte("MZbinary"), 0o644))

	// Accounts DB, locked down.
	accPath := filepath.Join(dbDir, "accounts.db")
	must(t, os.WriteFile(accPath, []byte("SQLite binary"), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(stratDir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents",
		"NinjaTrader 8", "bin", "Custom", "Strategies")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "Skip.cs"),
		[]byte(`namespace X {}`), 0o644))

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
		t.Fatalf("want 3 (strat+dll+acc), got %d: %+v", len(got), got)
	}

	var strat, dll, acc Row
	for _, r := range got {
		switch r.FilePath {
		case stratPath:
			strat = r
		case dllPath:
			dll = r
		case accPath:
			acc = r
		}
	}

	if strat.ArtifactKind != KindStrategyCS {
		t.Fatalf("strat kind=%q", strat.ArtifactKind)
	}
	if !strat.HasCompiledStrategy {
		t.Fatalf("strat must flag compiled: %+v", strat)
	}
	if strat.StrategyName != "MyROFEXStrategy" {
		t.Fatalf("strat name=%q", strat.StrategyName)
	}

	if dll.ArtifactKind != KindAddonCS {
		t.Fatalf("dll kind=%q", dll.ArtifactKind)
	}
	if !dll.HasAddonDLL {
		t.Fatalf("dll must flag addon: %+v", dll)
	}
	if !dll.IsCredentialExposureRisk {
		t.Fatalf("readable + addon = exposure: %+v", dll)
	}

	if acc.ArtifactKind != KindAccountDB {
		t.Fatalf("acc kind=%q", acc.ArtifactKind)
	}
	if !acc.HasAccountCredentials {
		t.Fatalf("acc must flag creds: %+v", acc)
	}
	if acc.IsCredentialExposureRisk {
		t.Fatalf("0o600 acc must NOT flag exposure: %+v", acc)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-nt")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "MyStrategy.cs"),
		[]byte(`public class MyStrategy : Strategy {}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "NINJATRADER_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindStrategyCS {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-nt"},
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
		{FilePath: "z", ArtifactKind: KindStrategyCS},
		{FilePath: "a", ArtifactKind: KindStrategyCS},
		{FilePath: "a", ArtifactKind: KindAccountDB},
	}
	SortRows(in)
	// "ninja-account-db" sorts before "ninja-strategy-cs".
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindAccountDB {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashContents(t *testing.T) {
	a := HashContents([]byte("nt"))
	b := HashContents([]byte("nt"))
	c := HashContents([]byte("NT"))
	if a != b {
		t.Fatal("hash drift")
	}
	if a == c {
		t.Fatal("hash collision case-insensitive")
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
