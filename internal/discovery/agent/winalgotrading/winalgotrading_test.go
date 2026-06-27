package winalgotrading

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindFIXSessionLog), "fix-session-log"},
		{string(KindFIXConfig), "fix-config"},
		{string(KindMT4EA), "mt4-ea"},
		{string(KindMT5EA), "mt5-ea"},
		{string(KindMQLSource), "mql-source"},
		{string(KindNinjaTraderStrategy), "ninjatrader-strategy"},
		{string(KindSQXStrategy), "sqx-strategy"},
		{string(KindPythonPKL), "python-pkl"},
		{string(KindOHLCVParquet), "ohlcv-parquet"},
		{string(KindJupyterNotebook), "jupyter-notebook"},
		{string(KindAlgoConfig), "algo-config"},
		{string(KindBacktestResult), "backtest-result"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AppQuickFIX), "quickfix"},
		{string(AppMetaTrader4), "metatrader-4"},
		{string(AppMetaTrader5), "metatrader-5"},
		{string(AppNinjaTrader), "ninjatrader"},
		{string(AppStrategyQuant), "strategyquant"},
		{string(AppCustomPython), "custom-python"},
		{string(AppJupyterLab), "jupyterlab"},
		{string(AppPrimaryTrader), "primarytrader"},
		{string(AppESCO), "esco"},
		{string(AppTradingView), "tradingview"},
		{string(AppOther), "other"},
		{string(AppUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateExt(t *testing.T) {
	yes := []string{
		"a.fix", "a.fixmsg", "a.cfg", "a.ini",
		"a.ex4", "a.ex5", "a.mq4", "a.mq5",
		"a.cs", "a.sqx",
		"a.pkl", "a.pickle", "a.parquet", "a.npy", "a.npz",
		"a.ipynb", "a.json", "a.yaml", "a.yml", "a.log",
	}
	no := []string{"a.pdf", "a.docx", "", "a.txt"}
	for _, v := range yes {
		if !IsCandidateExt(v) {
			t.Fatalf("expected ext: %q", v)
		}
	}
	for _, v := range no {
		if IsCandidateExt(v) {
			t.Fatalf("expected NOT ext: %q", v)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"session.fix",        // strong-match ext
		"strategy.ex5",       // strong-match ext
		"model.pkl",          // strong-match ext
		"backtest_jun.ipynb", // strong-match ext
		"quickfix.cfg",       // loose-match: quickfix token
		"FIXSession.log",     // loose-match: fixsession token
		"algo_config.json",   // loose-match: algo_ token
		"backtest_2024.json", // loose-match: backtest token
	}
	no := []string{
		"random.json",
		"factura.pdf",
		"",
	}
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
		"session.fix":             KindFIXSessionLog,
		"orders.fixmsg":           KindFIXSessionLog,
		"strategy.ex4":            KindMT4EA,
		"strategy.ex5":            KindMT5EA,
		"source.mq4":              KindMQLSource,
		"source.mq5":              KindMQLSource,
		"strat.sqx":               KindSQXStrategy,
		"model.pkl":               KindPythonPKL,
		"history.parquet":         KindOHLCVParquet,
		"notebook.ipynb":          KindJupyterNotebook,
		"weights.npy":             KindBacktestResult,
		"quickfix.cfg":            KindFIXConfig,
		"fix.ini":                 KindFIXConfig,
		"fixsession.log":          KindFIXSessionLog,
		"ninjatrader_strategy.cs": KindNinjaTraderStrategy,
		"my_strategy.cs":          KindNinjaTraderStrategy,
		"backtest_results.json":   KindBacktestResult,
		"algo_params.yaml":        KindAlgoConfig,
		"strategy_config.yml":     KindAlgoConfig,
		"random.json":             KindUnknown,
		"":                        KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestApplicationFromPath(t *testing.T) {
	cases := map[string]Application{
		`C:\PrimaryTrader\fix.cfg`:              AppPrimaryTrader,
		`C:\ESCO\PrimaryTrader\session.log`:     AppESCO,
		`C:\Program Files\MetaTrader 5\foo.ex5`: AppMetaTrader5,
		`C:\Users\u\Documents\MetaTrader 4\bar`: AppMetaTrader4,
		`C:\NinjaTrader 8\bin\strategy.cs`:      AppNinjaTrader,
		`C:\StrategyQuant\strat.sqx`:            AppStrategyQuant,
		`/home/u/.quickfix/session.cfg`:         AppQuickFIX,
		`/home/u/Documents/Jupyter/foo.ipynb`:   AppJupyterLab,
		`/srv/algo/model.pkl`:                   AppUnknown,
		"":                                      AppUnknown,
	}
	for in, want := range cases {
		if got := ApplicationFromPath(in); got != want {
			t.Fatalf("ApplicationFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseFIXConfig(t *testing.T) {
	body := []byte(`[DEFAULT]
ConnectionType=initiator
SenderCompID=ALYC338
TargetCompID=BYMA
Password=hunter2
SocketKeyStorePassword=topsecret
`)
	f := ParseFIXConfig(body)
	if f.SenderCompID != "ALYC338" {
		t.Fatalf("sender=%q", f.SenderCompID)
	}
	if f.TargetCompID != "BYMA" {
		t.Fatalf("target=%q", f.TargetCompID)
	}
	if !f.HasCredentialsInline {
		t.Fatal("must detect inline credentials")
	}
}

func TestParseFIXConfigNoCreds(t *testing.T) {
	body := []byte(`SenderCompID=ALYC338
TargetCompID=BYMA
`)
	f := ParseFIXConfig(body)
	if f.HasCredentialsInline {
		t.Fatal("must NOT flag without password row")
	}
}

func TestCountFIXMessages(t *testing.T) {
	cases := map[string]int{
		"":       0,
		"a":      1,
		"a\n":    1,
		"a\nb":   2,
		"a\nb\n": 2,
	}
	for in, want := range cases {
		if got := CountFIXMessages([]byte(in)); got != want {
			t.Fatalf("CountFIXMessages(%q)=%d want %d", in, got, want)
		}
	}
}

func TestContainsAPIKey(t *testing.T) {
	yes := [][]byte{
		[]byte(`"api_key": "sk-abcdef1234567890"`),
		[]byte(`bearer = abcdefghij1234567890`),
		[]byte(`"secret":"longvaluefornightowls"`),
		[]byte(`access_token: ya29.0.AAAfoobarbaz12345678`),
	}
	no := [][]byte{
		[]byte(""),
		[]byte("nothing relevant"),
		[]byte(`{"x":"y"}`),
	}
	for _, b := range yes {
		if !ContainsAPIKey(b) {
			t.Fatalf("expected API key in: %q", b)
		}
	}
	for _, b := range no {
		if ContainsAPIKey(b) {
			t.Fatalf("expected NOT API key in: %q", b)
		}
	}
}

func TestIsCompiledExt(t *testing.T) {
	yes := []string{".ex4", ".ex5", ".sqx", ".pkl", ".pickle", ".parquet", ".npy", ".npz"}
	no := []string{".mq4", ".mq5", ".cs", ".cfg", ".ipynb", "", ".log"}
	for _, v := range yes {
		if !IsCompiledExt(v) {
			t.Fatalf("expected compiled: %q", v)
		}
	}
	for _, v := range no {
		if IsCompiledExt(v) {
			t.Fatalf("expected NOT compiled: %q", v)
		}
	}
}

func TestIsStrategyKind(t *testing.T) {
	yes := []ArtifactKind{
		KindMT4EA, KindMT5EA, KindMQLSource,
		KindNinjaTraderStrategy, KindSQXStrategy,
		KindPythonPKL, KindJupyterNotebook,
	}
	no := []ArtifactKind{
		KindFIXSessionLog, KindFIXConfig, KindOHLCVParquet,
		KindAlgoConfig, KindBacktestResult, KindOther, KindUnknown,
	}
	for _, v := range yes {
		if !IsStrategyKind(v) {
			t.Fatalf("expected strategy: %q", v)
		}
	}
	for _, v := range no {
		if IsStrategyKind(v) {
			t.Fatalf("expected NOT strategy: %q", v)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateFIXCredExposure(t *testing.T) {
	r := Row{
		ArtifactKind:           KindFIXConfig,
		HasCredentialsInConfig: true,
		FileMode:               0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatal("FIX cred + readable = exposure")
	}
}

func TestAnnotateStrategyExposure(t *testing.T) {
	r := Row{ArtifactKind: KindMT5EA, FileMode: 0o644}
	AnnotateSecurity(&r)
	if !r.HasStrategyLogic {
		t.Fatal("MT5 EA must flag strategy")
	}
	if !r.IsCompiledBinary {
		t.Fatal("MT5 EA must flag compiled")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("strategy + readable = exposure")
	}
}

func TestAnnotateNotebookAPIKey(t *testing.T) {
	r := Row{ArtifactKind: KindJupyterNotebook, HasAPIKeyInNotebook: true, FileMode: 0o644}
	AnnotateSecurity(&r)
	if !r.HasStrategyLogic {
		t.Fatal("notebook is strategy")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("notebook + key + readable = exposure")
	}
}

func TestAnnotateBacktest0600Clean(t *testing.T) {
	r := Row{ArtifactKind: KindBacktestResult, FileMode: 0o600}
	AnnotateSecurity(&r)
	if !r.HasBacktestResults {
		t.Fatal("backtest kind must flag")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateOHLCVNoStrategy(t *testing.T) {
	r := Row{ArtifactKind: KindOHLCVParquet, FileMode: 0o644}
	AnnotateSecurity(&r)
	if r.HasStrategyLogic {
		t.Fatal("OHLCV is NOT strategy IP")
	}
	if !r.HasBacktestResults {
		t.Fatal("parquet is backtest result")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	qfDir := filepath.Join(usersBase, "alice", ".quickfix")
	must(t, os.MkdirAll(qfDir, 0o755))

	// FIX config with credentials, world-readable.
	cfgPath := filepath.Join(qfDir, "quickfix.cfg")
	must(t, os.WriteFile(cfgPath, []byte(`[DEFAULT]
SenderCompID=ALYC338
TargetCompID=BYMA
Password=hunter2
`), 0o644))

	// MT5 EA file, world-readable.
	mt5Dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "MetaQuotes", "Terminal")
	must(t, os.MkdirAll(mt5Dir, 0o755))
	mt5Path := filepath.Join(mt5Dir, "strategy.ex5")
	must(t, os.WriteFile(mt5Path, []byte("\xCC\xCC\xCCfake compiled EA bytes"), 0o644))

	// Notebook with API key, locked-down.
	jupDir := filepath.Join(usersBase, "alice", "Documents", "Jupyter")
	must(t, os.MkdirAll(jupDir, 0o755))
	nbPath := filepath.Join(jupDir, "backtest_jun.ipynb")
	must(t, os.WriteFile(nbPath, []byte(`{"cells":[{"source":["api_key = 'sk-abcdef1234567890123'"]}]}`), 0o600))

	// Random file ignored.
	must(t, os.WriteFile(filepath.Join(jupDir, "random.json"), []byte(`{}`), 0o644))

	// Public — skipped.
	pub := filepath.Join(usersBase, "Public", ".quickfix")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "quickfix.cfg"),
		[]byte("SenderCompID=skip"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 (cfg+ea+nb), got %d: %+v", len(got), got)
	}

	var cfg, mt5, nb Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case mt5Path:
			mt5 = r
		case nbPath:
			nb = r
		}
	}
	if cfg.ArtifactKind != KindFIXConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if cfg.FIXSenderCompID != "ALYC338" || cfg.FIXTargetCompID != "BYMA" {
		t.Fatalf("cfg fix ids: %+v", cfg)
	}
	if !cfg.HasCredentialsInConfig {
		t.Fatalf("cfg must flag creds: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("cfg + readable = exposure: %+v", cfg)
	}

	if mt5.ArtifactKind != KindMT5EA {
		t.Fatalf("mt5 kind=%q", mt5.ArtifactKind)
	}
	if !mt5.HasStrategyLogic || !mt5.IsCompiledBinary {
		t.Fatalf("mt5 flags: %+v", mt5)
	}

	if nb.ArtifactKind != KindJupyterNotebook {
		t.Fatalf("nb kind=%q", nb.ArtifactKind)
	}
	if !nb.HasAPIKeyInNotebook {
		t.Fatalf("nb must flag API key: %+v", nb)
	}
	if nb.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", nb)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-algo")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "quickfix.cfg"),
		[]byte("SenderCompID=ALYC338\nTargetCompID=BYMA\nPassword=x\n"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "ALGOTRADING_DIR" {
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
	if len(got) != 1 || got[0].FIXSenderCompID != "ALYC338" {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-algo"},
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
		{FilePath: "z", ArtifactKind: KindFIXConfig, Application: AppQuickFIX},
		{FilePath: "a", ArtifactKind: KindMT5EA, Application: AppMetaTrader5},
		{FilePath: "a", ArtifactKind: KindFIXConfig, Application: AppQuickFIX},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindFIXConfig {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
