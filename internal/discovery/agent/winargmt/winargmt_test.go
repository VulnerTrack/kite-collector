package winargmt

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindMQ4Source), "mt-ea-mq4-source"},
		{string(KindMQ5Source), "mt-ea-mq5-source"},
		{string(KindEX4Compiled), "mt-ea-ex4-compiled"},
		{string(KindEX5Compiled), "mt-ea-ex5-compiled"},
		{string(KindIndicatorMQ), "mt-indicator-mq"},
		{string(KindScriptMQ), "mt-script-mq"},
		{string(KindTerminalConfig), "mt-terminal-config"},
		{string(KindAccountConfig), "mt-account-config"},
		{string(KindBrokerServers), "mt-broker-servers"},
		{string(KindHistoryHST), "mt-history-hst"},
		{string(KindOptimizeReport), "mt-optimize-report"},
		{string(KindBacktestReport), "mt-backtest-report"},
		{string(KindDLLPlugin), "mt-dll-plugin"},
		{string(KindInstaller), "mt-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(PlatformMT4), "mt4"},
		{string(PlatformMT5), "mt5"},
		{string(PlatformMobile), "mt-mobile"},
		{string(PlatformOther), "other"},
		{string(PlatformUnknown), "unknown"},
		{string(BrokerArgentine), "arg-broker"},
		{string(BrokerOffshore), "offshore-broker"},
		{string(BrokerDemo), "demo-server"},
		{string(BrokerPropFirm), "prop-firm"},
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
		"MyEA.ex4",
		"MyEA.mq4",
		"MyEA.ex5",
		"MyEA.mq5",
		"MyIndicator.mq4",
		"MyScript.mq5",
		"terminal.ini",
		"accounts.ini",
		"servers.dat",
		"EURUSD60.hst",
		"MyEA.set",
		"helper.dll",
		"origin.txt",
		"optimize_report.htm",
		"backtest_report.html",
		"mt4_install.exe",
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

func TestArtifactKindFromName(t *testing.T) {
	cases := map[string]ArtifactKind{
		"MyEA.ex4":             KindEX4Compiled,
		"MyEA.mq4":             KindMQ4Source,
		"MyEA.ex5":             KindEX5Compiled,
		"MyEA.mq5":             KindMQ5Source,
		"MyIndicator.mq4":      KindIndicatorMQ,
		"MyScript.mq5":         KindScriptMQ,
		"helper.dll":           KindDLLPlugin,
		"EURUSD60.hst":         KindHistoryHST,
		"terminal.ini":         KindTerminalConfig,
		"accounts.ini":         KindAccountConfig,
		"servers.dat":          KindBrokerServers,
		"origin.txt":           KindBrokerServers,
		"optimize_report.htm":  KindOptimizeReport,
		"backtest_report.html": KindBacktestReport,
		"tester_results.html":  KindBacktestReport,
		"":                     KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPlatformFromPath(t *testing.T) {
	cases := map[string]Platform{
		`C:\Program Files\MetaTrader 4\terminal.exe`:                               PlatformMT4,
		`C:\Program Files\MetaTrader 5\terminal64.exe`:                             PlatformMT5,
		`/home/alice/.wine/drive_c/Program Files/MetaTrader 4/MQL4/Experts/EA.mq4`: PlatformMT4,
		`/home/alice/Documents/MetaTrader 5/MQL5/Experts/EA.mq5`:                   PlatformMT5,
		`/home/alice/Documents/Random/file.txt`:                                    PlatformUnknown,
		"":                                                                         PlatformUnknown,
	}
	for in, want := range cases {
		if got := PlatformFromPath(in); got != want {
			t.Fatalf("PlatformFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBrokerClassFromHost(t *testing.T) {
	cases := map[string]BrokerClass{
		"ftmo.com":          BrokerPropFirm,
		"myforexfunds.com":  BrokerPropFirm,
		"fundednext.com":    BrokerPropFirm,
		"the5ers.com":       BrokerPropFirm,
		"topstepfx.com":     BrokerPropFirm,
		"tickmill.com":      BrokerOffshore,
		"pepperstone.com":   BrokerOffshore,
		"icmarkets.com":     BrokerOffshore,
		"oanda.com":         BrokerOffshore,
		"exness.com":        BrokerOffshore,
		"forexar.com.ar":    BrokerArgentine,
		"saxoxar.com.ar":    BrokerArgentine,
		"demo.broker.com":   BrokerDemo,
		"unknown-broker.io": BrokerUnknown,
		"":                  BrokerUnknown,
	}
	for in, want := range cases {
		if got := BrokerClassFromHost(in); got != want {
			t.Fatalf("BrokerClassFromHost(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("backtest_202506.htm") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.htm") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsCompiledKind(t *testing.T) {
	yes := []ArtifactKind{KindEX4Compiled, KindEX5Compiled, KindDLLPlugin}
	no := []ArtifactKind{
		KindMQ4Source, KindMQ5Source, KindIndicatorMQ, KindScriptMQ,
		KindTerminalConfig, KindAccountConfig, KindBrokerServers,
		KindHistoryHST, KindOptimizeReport, KindBacktestReport,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range yes {
		if !IsCompiledKind(k) {
			t.Fatalf("expected compiled: %q", k)
		}
	}
	for _, k := range no {
		if IsCompiledKind(k) {
			t.Fatalf("expected NOT compiled: %q", k)
		}
	}
}

func TestIsSourceKind(t *testing.T) {
	yes := []ArtifactKind{KindMQ4Source, KindMQ5Source, KindIndicatorMQ, KindScriptMQ}
	no := []ArtifactKind{
		KindEX4Compiled, KindEX5Compiled, KindDLLPlugin,
		KindTerminalConfig, KindAccountConfig, KindBrokerServers,
		KindHistoryHST, KindOptimizeReport, KindBacktestReport,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range yes {
		if !IsSourceKind(k) {
			t.Fatalf("expected source: %q", k)
		}
	}
	for _, k := range no {
		if IsSourceKind(k) {
			t.Fatalf("expected NOT source: %q", k)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateCompiledEA(t *testing.T) {
	r := Row{
		ArtifactKind: KindEX5Compiled,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasCompiledEA {
		t.Fatal(".ex5 must flag compiled EA")
	}
	if r.HasSourceEA {
		t.Fatal(".ex5 must NOT flag source")
	}
}

func TestAnnotateSourceEA(t *testing.T) {
	r := Row{
		ArtifactKind: KindMQ4Source,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasSourceEA {
		t.Fatal(".mq4 must flag source")
	}
	if r.HasCompiledEA {
		t.Fatal(".mq4 must NOT flag compiled")
	}
}

func TestAnnotateDLLPlugin(t *testing.T) {
	r := Row{
		ArtifactKind: KindDLLPlugin,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasDLLPlugin {
		t.Fatal("DLL must flag plugin")
	}
}

func TestAnnotatePasswordExposure(t *testing.T) {
	r := Row{
		ArtifactKind:       KindTerminalConfig,
		HasAccountPassword: true,
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + password = exposure: %+v", r)
	}
}

func TestAnnotateOffshoreBroker(t *testing.T) {
	r := Row{
		ArtifactKind: KindTerminalConfig,
		BrokerClass:  BrokerOffshore,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasOffshoreBroker {
		t.Fatal("offshore broker must flag")
	}
	if r.HasPropFirmAccount {
		t.Fatal("offshore must NOT flag prop firm")
	}
}

func TestAnnotatePropFirm(t *testing.T) {
	r := Row{
		ArtifactKind: KindTerminalConfig,
		BrokerClass:  BrokerPropFirm,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasPropFirmAccount {
		t.Fatal("prop firm must flag")
	}
}

func TestAnnotateOptimizerOverfit(t *testing.T) {
	r := Row{
		ArtifactKind:           KindOptimizeReport,
		OptimizerOOSDropoffPct: 80,
		FileMode:               0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasOptimizerOverfit {
		t.Fatal("80% dropoff must flag overfit")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:       KindTerminalConfig,
		HasAccountPassword: true,
		FileMode:           0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseMTTerminalConfig ----------------------------------------

func TestParseMTTerminalConfig(t *testing.T) {
	body := []byte(`[Common]
Server=Pepperstone-Demo
Login=12345678
Password=secret123
DataServer=demo.pepperstone.com
EnableExpert=true
TradingSignal=signal_provider_xyz
`)
	f := ParseMTTerminalConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if !f.HasSignalProvider {
		t.Fatal("signal provider must flag")
	}
	if f.AccountLogin != "12345678" {
		t.Fatalf("login=%q", f.AccountLogin)
	}
	if f.ServerName != "Pepperstone-Demo" {
		t.Fatalf("server=%q", f.ServerName)
	}
}

func TestParseMTOrigin(t *testing.T) {
	body := []byte(`https://download.tickmill.com/MT4Setup.exe`)
	f := ParseMTOrigin(body)
	if f.BrokerHostname == "" {
		t.Fatal("origin must extract hostname")
	}
}

func TestParseMTOptimizeReport(t *testing.T) {
	body := []byte(`<html>
<body>
<h1>Strategy Tester Report</h1>
Expert: MyEA_v1
In-Sample Profit: $5000.00
Out-of-Sample Profit: $1200.00
</body>
</html>`)
	f := ParseMTOptimizeReport(body)
	if f.OptimizerInSampleProfit != 5000 {
		t.Fatalf("IS profit=%v", f.OptimizerInSampleProfit)
	}
	if f.OptimizerOutSampleProfit != 1200 {
		t.Fatalf("OOS profit=%v", f.OptimizerOutSampleProfit)
	}
	dropoff := OOSDropoffPct(f.OptimizerInSampleProfit, f.OptimizerOutSampleProfit)
	if dropoff != 76 {
		t.Fatalf("dropoff=%d want 76", dropoff)
	}
}

func TestOOSDropoffPct(t *testing.T) {
	cases := []struct {
		in, out float64
		want    int
	}{
		{5000, 1200, 76},
		{5000, 4500, 10},
		{5000, 5000, 0},
		{5000, 6000, 0}, // OOS > IS = no over-fit
		{0, 100, 0},     // non-positive IS = no signal
		{-100, 50, 0},
	}
	for _, c := range cases {
		if got := OOSDropoffPct(c.in, c.out); got != c.want {
			t.Fatalf("OOSDropoffPct(%v,%v)=%d want %d", c.in, c.out, got, c.want)
		}
	}
}

func TestIsMQLSourceImportingDLL(t *testing.T) {
	yes := []byte(`//+------------------------------------------------------------------+
//| Expert MyEA.mq4 |
//+------------------------------------------------------------------+
#import "kernel32.dll"
   int GetTickCount();
#import
`)
	no := []byte(`//+--+
int OnInit() { return INIT_SUCCEEDED; }
`)
	if !IsMQLSourceImportingDLL(yes) {
		t.Fatal("#import must flag DLL")
	}
	if IsMQLSourceImportingDLL(no) {
		t.Fatal("no #import must NOT flag")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming",
		"MetaQuotes", "Terminal", "ABCDEF123", "MQL4")
	must(t, os.MkdirAll(filepath.Join(dir, "Experts"), 0o755))
	must(t, os.MkdirAll(filepath.Join(dir, "Indicators"), 0o755))
	must(t, os.MkdirAll(filepath.Join(dir, "Libraries"), 0o755))
	cfgDir := filepath.Join(usersBase, "alice", "AppData", "Roaming",
		"MetaQuotes", "Terminal", "ABCDEF123", "config")
	must(t, os.MkdirAll(cfgDir, 0o755))

	// Compiled EA, world-readable.
	eaPath := filepath.Join(dir, "Experts", "MyEA.ex4")
	must(t, os.WriteFile(eaPath, []byte("MQ4EX-compiled-binary"), 0o644))

	// Source EA importing a DLL.
	srcPath := filepath.Join(dir, "Experts", "MyEA.mq4")
	must(t, os.WriteFile(srcPath, []byte(`#import "kernel32.dll"
   int GetTickCount();
#import
`), 0o644))

	// Custom indicator.
	indPath := filepath.Join(dir, "Indicators", "MyInd.mq4")
	must(t, os.WriteFile(indPath, []byte(`// indicator stub`), 0o644))

	// DLL plugin.
	dllPath := filepath.Join(dir, "Libraries", "helper.dll")
	must(t, os.WriteFile(dllPath, []byte("MZbinary"), 0o644))

	// Terminal config with cleartext password + Pepperstone broker
	// + login.
	cfgPath := filepath.Join(cfgDir, "terminal.ini")
	must(t, os.WriteFile(cfgPath, []byte(`[Common]
Server=Pepperstone-Demo
Login=12345678
Password=secret123
DataServer=demo.pepperstone.com
`), 0o644))

	// Origin.txt with prop firm hostname.
	originPath := filepath.Join(usersBase, "alice", "AppData", "Roaming",
		"MetaQuotes", "Terminal", "ABCDEF123", "origin.txt")
	must(t, os.WriteFile(originPath,
		[]byte("https://ftmo.com/clients/MT4Setup.exe"), 0o644))

	// Optimize HTML report with over-fit signature.
	optPath := filepath.Join(usersBase, "alice", "AppData", "Roaming",
		"MetaQuotes", "Terminal", "ABCDEF123", "tester", "optimize_report.htm")
	must(t, os.MkdirAll(filepath.Dir(optPath), 0o755))
	must(t, os.WriteFile(optPath, []byte(`<html>
<body>
Expert: MyEA
In-Sample Profit: $5000.00
Out-of-Sample Profit: $1200.00
</body>
</html>`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming",
		"MetaQuotes", "Terminal")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "terminal.ini"),
		[]byte(`[Common]
Server=demo
`), 0o644))

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
	if len(got) != 7 {
		t.Fatalf("want 7 (ea+src+ind+dll+cfg+origin+opt), got %d: %+v", len(got), got)
	}

	var ea, src, ind, dll, cfg, opt Row
	for _, r := range got {
		switch r.FilePath {
		case eaPath:
			ea = r
		case srcPath:
			src = r
		case indPath:
			ind = r
		case dllPath:
			dll = r
		case cfgPath:
			cfg = r
		case optPath:
			opt = r
		}
	}

	if ea.ArtifactKind != KindEX4Compiled {
		t.Fatalf("ea kind=%q", ea.ArtifactKind)
	}
	if ea.Platform != PlatformMT4 {
		t.Fatalf("ea platform=%q", ea.Platform)
	}
	if !ea.HasCompiledEA {
		t.Fatalf("ea must flag compiled: %+v", ea)
	}

	if src.ArtifactKind != KindMQ4Source {
		t.Fatalf("src kind=%q", src.ArtifactKind)
	}
	if !src.HasSourceEA {
		t.Fatalf("src must flag source: %+v", src)
	}
	if !src.HasDLLPlugin {
		t.Fatalf("src #import dll must flag: %+v", src)
	}

	if ind.ArtifactKind != KindIndicatorMQ {
		t.Fatalf("ind kind=%q", ind.ArtifactKind)
	}

	if dll.ArtifactKind != KindDLLPlugin {
		t.Fatalf("dll kind=%q", dll.ArtifactKind)
	}
	if !dll.HasDLLPlugin {
		t.Fatalf("dll must flag plugin: %+v", dll)
	}

	if cfg.ArtifactKind != KindTerminalConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasAccountPassword {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if cfg.AccountLoginSuffix4 != "5678" {
		t.Fatalf("cfg login suffix=%q", cfg.AccountLoginSuffix4)
	}
	if cfg.BrokerClass != BrokerOffshore {
		t.Fatalf("cfg broker class=%q want offshore (pepperstone)", cfg.BrokerClass)
	}
	if !cfg.HasOffshoreBroker {
		t.Fatalf("cfg must flag offshore: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password = exposure: %+v", cfg)
	}

	if opt.ArtifactKind != KindOptimizeReport {
		t.Fatalf("opt kind=%q", opt.ArtifactKind)
	}
	if !opt.HasOptimizerOverfit {
		t.Fatalf("opt 76%% dropoff must flag overfit: %+v", opt)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-mt")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "terminal.ini"),
		[]byte(`[Common]
Server=ftmo-demo
Login=99999
Password=x
DataServer=demo.ftmo.com
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "METATRADER_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindTerminalConfig {
		t.Fatalf("env: %+v", got)
	}
	if !got[0].HasPropFirmAccount {
		t.Fatalf("env must flag prop firm (ftmo): %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-mt"},
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
		{FilePath: "z", ArtifactKind: KindEX4Compiled},
		{FilePath: "a", ArtifactKind: KindMQ4Source},
		{FilePath: "a", ArtifactKind: KindEX4Compiled},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindEX4Compiled {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashContents(t *testing.T) {
	a := HashContents([]byte("mt"))
	b := HashContents([]byte("mt"))
	c := HashContents([]byte("MT"))
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
