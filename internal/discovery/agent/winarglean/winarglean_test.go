package winarglean

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "lean-config"},
		{string(KindCredentials), "lean-credentials"},
		{string(KindAlgorithmCS), "lean-algorithm-cs"},
		{string(KindAlgorithmPy), "lean-algorithm-py"},
		{string(KindBacktestResult), "lean-backtest-result"},
		{string(KindLiveConfig), "lean-live-config"},
		{string(KindDataSubscription), "lean-data-subscription"},
		{string(KindNodepacket), "lean-nodepacket"},
		{string(KindCLIConfig), "lean-cli-config"},
		{string(KindInstaller), "lean-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(ClassEquity), "equity"},
		{string(ClassOptions), "options"},
		{string(ClassFutures), "futures"},
		{string(ClassForex), "forex"},
		{string(ClassCrypto), "crypto"},
		{string(ClassMultiAsset), "multi-asset"},
		{string(ClassOther), "other"},
		{string(ClassUnknown), "unknown"},
		{string(TargetBacktest), "backtest"},
		{string(TargetPaper), "paper"},
		{string(TargetLivePrimary), "live-primary"},
		{string(TargetLiveIB), "live-ib"},
		{string(TargetLiveAlpaca), "live-alpaca"},
		{string(TargetLiveCoinbase), "live-coinbase"},
		{string(TargetLiveBinance), "live-binance"},
		{string(TargetLiveBitfinex), "live-bitfinex"},
		{string(TargetLiveKraken), "live-kraken"},
		{string(TargetLiveOther), "live-other"},
		{string(TargetUnknown), "unknown"},
		{string(ResolutionTick), "tick"},
		{string(ResolutionSecond), "second"},
		{string(ResolutionMinute), "minute"},
		{string(ResolutionHour), "hour"},
		{string(ResolutionDaily), "daily"},
		{string(ResolutionUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"lean.json",
		"quantconnect_config.json",
		"algorithm.py",
		"algorithm.cs",
		"main.py",
		"main.cs",
		"backtest_202506.json",
		"nodepacket.json",
		"lean-cli-config.json",
		"lean_installer.msi",
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
		"lean.json":                KindConfig,
		"quantconnect_config.json": KindConfig,
		"lean_credentials.json":    KindCredentials,
		"lean_api_token.json":      KindCredentials,
		"algorithm.cs":             KindAlgorithmCS,
		"main.cs":                  KindAlgorithmCS,
		"algorithm.py":             KindAlgorithmPy,
		"lean_strategy.py":         KindAlgorithmPy,
		"my_lean.ipynb":            KindAlgorithmPy,
		"backtest_202506.json":     KindBacktestResult,
		"live_deployment_cfg.json": KindLiveConfig,
		"live_config.json":         KindLiveConfig,
		"nodepacket.json":          KindNodepacket,
		"lean-cli-config.json":     KindCLIConfig,
		"lean_installer.msi":       KindInstaller,
		"":                         KindUnknown,
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
	if PeriodFromFilename("backtest_202506.json") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.json") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsArgentineBrokerage(t *testing.T) {
	yes := []string{"primary", "primary-rofex", "rofex", "matba-rofex"}
	no := []string{"", "alpaca", "coinbase", "ib"}
	for _, v := range yes {
		if !IsArgentineBrokerage(v) {
			t.Fatalf("expected argentine: %q", v)
		}
	}
	for _, v := range no {
		if IsArgentineBrokerage(v) {
			t.Fatalf("expected NOT argentine: %q", v)
		}
	}
}

func TestIsCryptoBrokerage(t *testing.T) {
	yes := []string{"coinbase", "binance", "binance-us", "bitfinex", "kraken", "gdax"}
	no := []string{"", "primary", "alpaca", "ib"}
	for _, v := range yes {
		if !IsCryptoBrokerage(v) {
			t.Fatalf("expected crypto: %q", v)
		}
	}
	for _, v := range no {
		if IsCryptoBrokerage(v) {
			t.Fatalf("expected NOT crypto: %q", v)
		}
	}
}

func TestIsUSEquityBrokerage(t *testing.T) {
	yes := []string{"alpaca", "interactivebrokers", "ib-gateway", "ib", "tradier"}
	no := []string{"", "primary", "coinbase", "binance"}
	for _, v := range yes {
		if !IsUSEquityBrokerage(v) {
			t.Fatalf("expected us-equity: %q", v)
		}
	}
	for _, v := range no {
		if IsUSEquityBrokerage(v) {
			t.Fatalf("expected NOT us-equity: %q", v)
		}
	}
}

func TestDeploymentTargetFromBrokerage(t *testing.T) {
	cases := map[string]DeploymentTarget{
		"primary":            TargetLivePrimary,
		"matba-rofex":        TargetLivePrimary,
		"rofex":              TargetLivePrimary,
		"interactivebrokers": TargetLiveIB,
		"ib":                 TargetLiveIB,
		"alpaca":             TargetLiveAlpaca,
		"coinbase":           TargetLiveCoinbase,
		"binance":            TargetLiveBinance,
		"bitfinex":           TargetLiveBitfinex,
		"kraken":             TargetLiveKraken,
		"unknownbroker":      TargetLiveOther,
		"":                   TargetUnknown,
	}
	for in, want := range cases {
		if got := DeploymentTargetFromBrokerage(in); got != want {
			t.Fatalf("DeploymentTargetFromBrokerage(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAlgorithmClassFromBody(t *testing.T) {
	cases := map[string]AlgorithmClass{
		`self.AddEquity("GGAL")`:                           ClassEquity,
		`self.AddCrypto("BTCUSD")`:                         ClassCrypto,
		`AddFuture("DLR")`:                                 ClassFutures,
		`AddOption("AAPL")`:                                ClassOptions,
		`self.AddForex("EURUSD")`:                          ClassForex,
		`self.AddEquity("GGAL"); self.AddCrypto("BTCUSD")`: ClassMultiAsset,
		`nothing here`:                                     ClassUnknown,
	}
	for in, want := range cases {
		if got := AlgorithmClassFromBody([]byte(in)); got != want {
			t.Fatalf("AlgorithmClassFromBody(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDataResolutionFromBody(t *testing.T) {
	cases := map[string]DataResolution{
		`Resolution.Tick`:        ResolutionTick,
		`Resolution.Second`:      ResolutionSecond,
		`"resolution": "minute"`: ResolutionMinute,
		`resolution=hour`:        ResolutionHour,
		`Resolution.Daily`:       ResolutionDaily,
		`unrelated body`:         ResolutionUnknown,
	}
	for in, want := range cases {
		if got := DataResolutionFromBody([]byte(in)); got != want {
			t.Fatalf("DataResolutionFromBody(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsHighFrequencyResolution(t *testing.T) {
	if !IsHighFrequencyResolution(ResolutionTick) {
		t.Fatal("tick must flag")
	}
	if !IsHighFrequencyResolution(ResolutionSecond) {
		t.Fatal("second must flag")
	}
	if IsHighFrequencyResolution(ResolutionMinute) {
		t.Fatal("minute must NOT flag")
	}
	if IsHighFrequencyResolution(ResolutionDaily) {
		t.Fatal("daily must NOT flag")
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindLiveConfig,
		KindCLIConfig, KindNodepacket,
		KindAlgorithmCS, KindAlgorithmPy,
	}
	no := []ArtifactKind{
		KindBacktestResult, KindDataSubscription,
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
		ArtifactKind:       KindConfig,
		HasBrokerageAPIKey: true,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + broker key + cliente = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:       KindConfig,
		HasBrokerageAPIKey: true,
		FileMode:           0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateHighFreq(t *testing.T) {
	r := Row{
		ArtifactKind:   KindAlgorithmPy,
		DataResolution: ResolutionTick,
	}
	AnnotateSecurity(&r)
	if !r.HasHighFrequencyStrategy {
		t.Fatal("tick resolution must flag HFT")
	}
}

func TestAnnotateLargeDataFootprint(t *testing.T) {
	r := Row{
		ArtifactKind:  KindDataSubscription,
		DataFileCount: 1500,
	}
	AnnotateSecurity(&r)
	if !r.HasLargeDataFootprint {
		t.Fatal("1500 files must flag large data")
	}
}

func TestParseLeanConfigPrimary(t *testing.T) {
	body := []byte(`{
"environment": "live-paper",
"live-mode": true,
"brokerage": "primary-rofex",
"primary-key": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
"password": "secret123",
"cliente_cuit": "27-11111111-4",
"algorithm-type-name": "MyROFEXStrategy"
}`)
	f := ParseLeanConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.BrokerageName != "primary-rofex" {
		t.Fatalf("brokerage=%q", f.BrokerageName)
	}
	if f.BrokerageKey == "" {
		t.Fatal("brokerage key must extract")
	}
	if !f.HasLiveMode {
		t.Fatal("live-mode must flag")
	}
	if !f.HasArgentine {
		t.Fatal("primary-rofex must flag argentine")
	}
	if f.HasCrypto || f.HasUSEquity {
		t.Fatal("primary-rofex must NOT flag crypto/us-equity")
	}
	if f.AlgorithmName != "MyROFEXStrategy" {
		t.Fatalf("alg name=%q", f.AlgorithmName)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseLeanConfigCrypto(t *testing.T) {
	body := []byte(`{
"brokerage": "binance",
"binance-key": "aBcDeFgHiJkLmNoPqRsTuVwX12345"
}`)
	f := ParseLeanConfig(body)
	if !f.HasCrypto {
		t.Fatal("binance must flag crypto")
	}
}

func TestParseLeanAlgorithmCS(t *testing.T) {
	body := []byte(`using QuantConnect;
public class GGALMomentum : QCAlgorithm {
    public override void Initialize() {
        AddEquity("GGAL", Resolution.Second);
        AddOption("AAPL");
        var apiKey = "leakedKeyAbCdEfGhIjKlMnOpQrStUv";
    }
}`)
	f := ParseLeanAlgorithmCS(body)
	if f.AlgorithmName != "GGALMomentum" {
		t.Fatalf("name=%q", f.AlgorithmName)
	}
	if f.Class != ClassMultiAsset {
		t.Fatalf("class=%q want multi-asset", f.Class)
	}
	if f.Resolution != ResolutionSecond {
		t.Fatalf("resolution=%q", f.Resolution)
	}
	if f.DistinctSymbols < 2 {
		t.Fatalf("symbols=%d", f.DistinctSymbols)
	}
}

func TestParseLeanAlgorithmPy(t *testing.T) {
	body := []byte(`from AlgorithmImports import *
class GGALMomentum(QCAlgorithm):
    def Initialize(self):
        self.AddEquity("GGAL", Resolution.Tick)
        self.AddFuture("DLR")
        api_key = "leakedSecretKeyAbCdEfGhIjKlMn"
        password = "hardcoded123"
`)
	f := ParseLeanAlgorithmPy(body)
	if f.AlgorithmName != "GGALMomentum" {
		t.Fatalf("name=%q", f.AlgorithmName)
	}
	if f.Class != ClassMultiAsset {
		t.Fatalf("class=%q", f.Class)
	}
	if f.Resolution != ResolutionTick {
		t.Fatalf("resolution=%q", f.Resolution)
	}
	if !f.HasPassword {
		t.Fatal("hardcoded password must flag")
	}
}

func TestParseLeanBacktestResult(t *testing.T) {
	body := []byte(`{
"algorithm-type-name": "GGALMomentum",
"sharpe_ratio": 1.85,
"annual_return": 0.32
}`)
	f := ParseLeanBacktestResult(body)
	if f.BacktestCount < 1 {
		t.Fatal("backtest count")
	}
	if f.SharpeRatioBps != 18500 {
		t.Fatalf("sharpe=%d want 18500", f.SharpeRatioBps)
	}
	if f.AnnualReturnBps != 3200 {
		t.Fatalf("annual=%d want 3200", f.AnnualReturnBps)
	}
}

func TestParseLeanCLIConfig(t *testing.T) {
	body := []byte(`{
"user-token": "aBcDeFgHiJkLmNoPqRsTuVwXyZ12345",
"password": "cli-pass"
}`)
	f := ParseLeanCLIConfig(body)
	if f.QCUserToken == "" {
		t.Fatal("qc user token must extract")
	}
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
}

func TestParseLeanEmpty(t *testing.T) {
	f := ParseLeanConfig(nil)
	if f.HasPassword || f.BrokerageKey != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestClassifyDeployment(t *testing.T) {
	cases := []struct {
		want DeploymentTarget
		f    LeanFields
	}{
		{want: TargetBacktest, f: LeanFields{}},
		{want: TargetPaper, f: LeanFields{BrokerageName: "primary"}},
		{want: TargetLivePrimary, f: LeanFields{HasLiveMode: true, BrokerageName: "primary"}},
		{want: TargetLiveAlpaca, f: LeanFields{HasLiveMode: true, BrokerageName: "alpaca"}},
		{want: TargetLiveBinance, f: LeanFields{HasLiveMode: true, BrokerageName: "binance"}},
		{want: TargetLiveOther, f: LeanFields{HasLiveMode: true}},
	}
	for _, c := range cases {
		if got := classifyDeployment(c.f); got != c.want {
			t.Fatalf("classifyDeployment(%+v)=%q want %q", c.f, got, c.want)
		}
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "Lean")
	must(t, os.MkdirAll(filepath.Join(dir, "backtests"), 0o755))

	cfgPath := filepath.Join(dir, "lean.json")
	must(t, os.WriteFile(cfgPath, []byte(`{
"environment": "live-paper",
"live-mode": true,
"brokerage": "primary-rofex",
"primary-key": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
"password": "secret123",
"cliente_cuit": "27-11111111-4",
"algorithm-type-name": "MyStrategy"
}`), 0o644))

	algPath := filepath.Join(dir, "algorithm.py")
	must(t, os.WriteFile(algPath, []byte(`from AlgorithmImports import *
class GGALMomentum(QCAlgorithm):
    def Initialize(self):
        self.AddEquity("GGAL", Resolution.Tick)
`), 0o644))

	btPath := filepath.Join(dir, "backtests", "backtest_202506.json")
	must(t, os.WriteFile(btPath, []byte(`{
"algorithm-type-name": "GGALMomentum",
"sharpe_ratio": 1.85
}`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "Lean")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "lean.json"),
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
	if len(got) != 3 {
		t.Fatalf("want 3 (cfg+alg+bt), got %d: %+v", len(got), got)
	}

	var cfg, alg, bt Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case algPath:
			alg = r
		case btPath:
			bt = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if !cfg.HasBrokerageAPIKey {
		t.Fatalf("cfg must flag brokerage key: %+v", cfg)
	}
	if !cfg.HasLiveDeployment {
		t.Fatalf("cfg must flag live deployment: %+v", cfg)
	}
	if !cfg.HasArgentineBrokerage {
		t.Fatalf("cfg must flag argentine brokerage: %+v", cfg)
	}
	if cfg.DeploymentTarget != TargetLivePrimary {
		t.Fatalf("cfg target=%q want live-primary", cfg.DeploymentTarget)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + broker key + cliente = exposure: %+v", cfg)
	}

	if alg.ArtifactKind != KindAlgorithmPy {
		t.Fatalf("alg kind=%q", alg.ArtifactKind)
	}
	if alg.AlgorithmClass != ClassEquity {
		t.Fatalf("alg class=%q want equity", alg.AlgorithmClass)
	}
	if alg.DataResolution != ResolutionTick {
		t.Fatalf("alg resolution=%q want tick", alg.DataResolution)
	}
	if !alg.HasHighFrequencyStrategy {
		t.Fatalf("alg tick must flag HFT: %+v", alg)
	}

	if bt.ArtifactKind != KindBacktestResult {
		t.Fatalf("bt kind=%q", bt.ArtifactKind)
	}
	if bt.SharpeRatioBps != 18500 {
		t.Fatalf("bt sharpe=%d want 18500", bt.SharpeRatioBps)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-lean")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "lean.json"),
		[]byte(`{"brokerage":"primary","primary-key":"abcdefghijklmnopqrst"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "LEAN_DIR" {
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
		installRoots: []string{"/nope-lean"},
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
		{FilePath: "a", ArtifactKind: KindBacktestResult},
		{FilePath: "a", ArtifactKind: KindAlgorithmPy},
	}
	SortRows(in)
	// At FilePath="a", "lean-algorithm-py" < "lean-backtest-result"
	// alphabetically, so AlgorithmPy sorts first.
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindAlgorithmPy {
		t.Fatalf("first=%+v want (a,lean-algorithm-py)", in[0])
	}
	if in[2].FilePath != "z" {
		t.Fatalf("last=%+v want z", in[2])
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
