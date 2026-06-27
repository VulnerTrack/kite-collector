package winargccxt

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "ccxt-config"},
		{string(KindCredentials), "ccxt-credentials"},
		{string(KindExchangeKeys), "ccxt-exchange-keys"},
		{string(KindStrategyPy), "ccxt-strategy-py"},
		{string(KindTradeLog), "ccxt-trade-log"},
		{string(KindBalanceSnapshot), "ccxt-balance-snapshot"},
		{string(KindArbitrageBot), "ccxt-arbitrage-bot"},
		{string(KindInstaller), "ccxt-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(ClassArgentineLocal), "argentine-local"},
		{string(ClassGlobalMajor), "global-major"},
		{string(ClassGlobalDerivatives), "global-derivatives"},
		{string(ClassDEX), "dex"},
		{string(ClassAggregator), "aggregator"},
		{string(ClassOther), "other"},
		{string(ClassUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"ccxt_config.json",
		"ccxt_keys_binance.json",
		"exchange_keys.json",
		"arbitrage_bot.py",
		"arbitraje_strategy.py",
		"crypto_strategy.ipynb",
		"trade_log_202506.csv",
		"balance_snapshot.json",
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
		"ccxt_config.json":       KindConfig,
		"ccxt_settings.yaml":     KindConfig,
		"ccxt_credentials.json":  KindCredentials,
		"ccxt_api_key.json":      KindCredentials,
		"exchange_keys.json":     KindExchangeKeys,
		"ccxt_keys_binance.json": KindExchangeKeys,
		"ccxt_strategy.py":       KindStrategyPy,
		"crypto_strategy.ipynb":  KindStrategyPy,
		"arbitrage_bot.py":       KindArbitrageBot,
		"arb_bot.py":             KindArbitrageBot,
		"trade_log_202506.csv":   KindTradeLog,
		"balance_snapshot.json":  KindBalanceSnapshot,
		"balance_202506.json":    KindBalanceSnapshot,
		"ccxt_installer.msi":     KindInstaller,
		"":                       KindUnknown,
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

func TestIsArgentineExchange(t *testing.T) {
	yes := []string{
		"lemoncash", "lemon", "belo", "ripio", "buenbit",
		"bitso", "decrypto", "satoshitango", "letsbit",
	}
	no := []string{"", "binance", "coinbase", "kraken"}
	for _, v := range yes {
		if !IsArgentineExchange(v) {
			t.Fatalf("expected argentine: %q", v)
		}
	}
	for _, v := range no {
		if IsArgentineExchange(v) {
			t.Fatalf("expected NOT argentine: %q", v)
		}
	}
}

func TestIsGlobalMajorExchange(t *testing.T) {
	yes := []string{
		"binance", "coinbase", "coinbasepro", "kraken",
		"bitfinex", "bybit", "okx", "kucoin", "huobi", "mexc",
	}
	no := []string{"", "lemon", "belo", "uniswap", "binanceusdm"}
	for _, v := range yes {
		if !IsGlobalMajorExchange(v) {
			t.Fatalf("expected global: %q", v)
		}
	}
	for _, v := range no {
		if IsGlobalMajorExchange(v) {
			t.Fatalf("expected NOT global: %q", v)
		}
	}
}

func TestIsDerivativesExchange(t *testing.T) {
	yes := []string{
		"binanceusdm", "binance-futures", "bitmex",
		"deribit", "dydx", "phemex",
	}
	no := []string{"", "binance", "coinbase", "lemon"}
	for _, v := range yes {
		if !IsDerivativesExchange(v) {
			t.Fatalf("expected derivatives: %q", v)
		}
	}
	for _, v := range no {
		if IsDerivativesExchange(v) {
			t.Fatalf("expected NOT derivatives: %q", v)
		}
	}
}

func TestIsDEXExchange(t *testing.T) {
	yes := []string{
		"uniswap", "pancakeswap", "sushiswap",
		"curve", "balancer", "1inch",
	}
	no := []string{"", "binance", "lemon"}
	for _, v := range yes {
		if !IsDEXExchange(v) {
			t.Fatalf("expected dex: %q", v)
		}
	}
	for _, v := range no {
		if IsDEXExchange(v) {
			t.Fatalf("expected NOT dex: %q", v)
		}
	}
}

func TestExchangeClassFor(t *testing.T) {
	cases := map[string]ExchangeClass{
		"lemoncash":       ClassArgentineLocal,
		"binance":         ClassGlobalMajor,
		"binanceusdm":     ClassGlobalDerivatives,
		"uniswap":         ClassDEX,
		"unknownexchange": ClassOther,
		"":                ClassUnknown,
	}
	for in, want := range cases {
		if got := ExchangeClassFor(in); got != want {
			t.Fatalf("ExchangeClassFor(%q)=%q want %q", in, got, want)
		}
	}
}

func TestHasUSDTARSPattern(t *testing.T) {
	yes := [][]byte{
		[]byte(`{"pair":"USDT/ARS"}`),
		[]byte(`USDTARS_book`),
		[]byte(`USDT-ARS spread`),
	}
	no := [][]byte{
		[]byte(`{"pair":"BTCUSDT"}`),
		[]byte(``),
	}
	for _, v := range yes {
		if !HasUSDTARSPattern(v) {
			t.Fatalf("expected USDT/ARS hit: %q", v)
		}
	}
	for _, v := range no {
		if HasUSDTARSPattern(v) {
			t.Fatalf("expected NOT USDT/ARS: %q", v)
		}
	}
}

func TestHasCCXTImport(t *testing.T) {
	yes := [][]byte{
		[]byte(`import ccxt`),
		[]byte(`import ccxt as exchange`),
		[]byte(`import ccxt.async_support`),
		[]byte(`from ccxt import binance`),
	}
	no := [][]byte{
		[]byte(`import requests`),
		[]byte(``),
	}
	for _, v := range yes {
		if !HasCCXTImport(v) {
			t.Fatalf("expected ccxt import: %q", v)
		}
	}
	for _, v := range no {
		if HasCCXTImport(v) {
			t.Fatalf("expected NOT ccxt import: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindExchangeKeys,
		KindStrategyPy, KindArbitrageBot,
		KindTradeLog, KindBalanceSnapshot,
	}
	no := []ArtifactKind{
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
		ArtifactKind:       KindExchangeKeys,
		HasExchangeAPIKey:  true,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + exchange key + cliente = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:      KindExchangeKeys,
		HasExchangeAPIKey: true,
		FileMode:          0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateHighFreq(t *testing.T) {
	r := Row{
		ArtifactKind:       KindTradeLog,
		PeakAPICallsPerSec: 5,
	}
	AnnotateSecurity(&r)
	if !r.HasHighFreqPolling {
		t.Fatal("5 calls/sec must flag HFreq polling")
	}
}

func TestParseCCXTConfig(t *testing.T) {
	body := []byte(`{
"exchange": "binance",
"apiKey": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
"secret": "secret-aBcDeFgHiJkLmNoPqRsTuVwXyZ",
"password": "wallet-pass"
}`)
	f := ParseCCXTConfig(body)
	if f.ExchangeID != "binance" {
		t.Fatalf("exchange=%q", f.ExchangeID)
	}
	if f.ExchangeKey == "" {
		t.Fatal("exchange key must extract")
	}
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if !f.HasGlobal {
		t.Fatal("binance must flag global")
	}
}

func TestParseCCXTStrategyPyARGGlobalArbitrage(t *testing.T) {
	body := []byte(`import ccxt
class USDTARSArbitrage:
    def __init__(self):
        self.lemon = ccxt.lemoncash({"apiKey": "leakedKeyAbCdEfGhIjKlMnOpQrStUv"})
        self.binance = ccxt.binance({"apiKey": "anotherLeakedKeyXyZ12345678901234"})

    def find_spread(self):
        # USDT/ARS triangular arbitrage
        pass
`)
	f := ParseCCXTStrategyPy(body)
	if !f.HasArgentine {
		t.Fatal("lemoncash must flag argentine")
	}
	if !f.HasGlobal {
		t.Fatal("binance must flag global")
	}
	if !f.HasArbitrageBot {
		t.Fatal("arbitrage marker must flag")
	}
	if !f.HasUSDTARSArbitrage {
		t.Fatal("USDT/ARS marker must flag")
	}
	if f.ExchangeKey == "" {
		t.Fatal("hardcoded key must extract")
	}
	if f.DistinctExchanges < 2 {
		t.Fatalf("distinct=%d want >=2", f.DistinctExchanges)
	}
}

func TestParseCCXTStrategyPyFundingRate(t *testing.T) {
	body := []byte(`import ccxt
class PerpBasis:
    def __init__(self):
        self.perp = ccxt.binanceusdm({"apiKey": "secretKey1234567890abcd"})
        self.spot = ccxt.binance({})
    def funding_rate_arb(self):
        pass
`)
	f := ParseCCXTStrategyPy(body)
	if !f.HasDerivatives {
		t.Fatal("binanceusdm must flag derivatives")
	}
	if !f.HasFundingRate {
		t.Fatal("funding rate marker must flag")
	}
}

func TestParseCCXTTradeLog(t *testing.T) {
	body := []byte(`2026-06-15 10:00:00 GET /api/v3/ticker binance pair=BTCUSDT
2026-06-15 10:00:00 GET /api/v3/order binance create
2026-06-15 10:00:00 fetch_balance lemoncash
2026-06-15 10:00:00 USDT_amount=5000.00 lemon → binance
2026-06-15 10:00:01 GET /api/v3/ticker binance pair=USDT/ARS
`)
	f := ParseCCXTTradeLog(body)
	if f.TradeCount < 4 {
		t.Fatalf("trades=%d", f.TradeCount)
	}
	if f.PeakAPICallsPerSec < 3 {
		t.Fatalf("peak=%d want >=3", f.PeakAPICallsPerSec)
	}
	if !f.HasUSDTARSArbitrage {
		t.Fatal("USDT/ARS pattern must flag")
	}
}

func TestParseCCXTArbitrageBot(t *testing.T) {
	body := []byte(`import ccxt
# triangular arbitrage between lemoncash and binance
ar = ccxt.lemoncash()
glob = ccxt.binance()
spread = compute_spread(ar.fetch_ticker("USDT/ARS"), glob.fetch_ticker("USDT/USD"))
`)
	f := ParseCCXTArbitrageBot(body)
	if !f.HasArbitrageBot {
		t.Fatal("arbitrage bot kind must auto-flag")
	}
	if !f.HasArgentine || !f.HasGlobal {
		t.Fatalf("argentine=%t global=%t", f.HasArgentine, f.HasGlobal)
	}
}

func TestParseCCXTEmpty(t *testing.T) {
	f := ParseCCXTConfig(nil)
	if f.HasPassword || f.ExchangeKey != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "projects", "arbitrage")
	must(t, os.MkdirAll(filepath.Join(dir, "keys"), 0o755))

	keysPath := filepath.Join(dir, "keys", "exchange_keys.json")
	must(t, os.WriteFile(keysPath, []byte(`{
"exchange": "lemoncash",
"apiKey": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
"secret": "secret-AbCdEfGhIjKlMnOpQrStUvWxYz"
}`), 0o644))

	botPath := filepath.Join(dir, "arbitrage_bot.py")
	must(t, os.WriteFile(botPath, []byte(`import ccxt
class USDTARSArb:
    def __init__(self):
        self.ar = ccxt.lemoncash({"apiKey": "leakedAr1234567890abcdef"})
        self.gl = ccxt.binance({"apiKey": "leakedGl1234567890abcdef"})
    def triangular(self):
        # USDT/ARS spread arbitrage
        pass
`), 0o644))

	logPath := filepath.Join(dir, "trade_log_202506.csv")
	must(t, os.WriteFile(logPath, []byte(`2026-06-15 10:00:00 GET /api/v3/ticker binance pair=USDT/ARS
2026-06-15 10:00:00 GET /api/v3/order binance create
2026-06-15 10:00:00 fetch_balance lemoncash
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "projects", "arbitrage")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "arbitrage_bot.py"),
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
		t.Fatalf("want 3 (keys+bot+log), got %d: %+v", len(got), got)
	}

	var keys, bot, lg Row
	for _, r := range got {
		switch r.FilePath {
		case keysPath:
			keys = r
		case botPath:
			bot = r
		case logPath:
			lg = r
		}
	}

	if keys.ArtifactKind != KindExchangeKeys {
		t.Fatalf("keys kind=%q", keys.ArtifactKind)
	}
	if !keys.HasExchangeAPIKey {
		t.Fatalf("keys must flag exchange key: %+v", keys)
	}
	if !keys.HasArgentineExchange {
		t.Fatalf("keys must flag argentine: %+v", keys)
	}
	if keys.ExchangeID != "lemoncash" {
		t.Fatalf("keys exchange=%q", keys.ExchangeID)
	}
	if keys.ExchangeClass != ClassArgentineLocal {
		t.Fatalf("keys class=%q", keys.ExchangeClass)
	}
	if !keys.IsCredentialExposureRisk {
		t.Fatalf("readable + key = exposure: %+v", keys)
	}

	if bot.ArtifactKind != KindArbitrageBot {
		t.Fatalf("bot kind=%q", bot.ArtifactKind)
	}
	if !bot.HasArbitrageBot {
		t.Fatalf("bot must flag: %+v", bot)
	}
	if !bot.HasArgentineExchange || !bot.HasGlobalExchange {
		t.Fatalf("bot must flag both AR + global: %+v", bot)
	}
	if !bot.HasUSDTARSArbitrage {
		t.Fatalf("bot must flag USDT/ARS arb: %+v", bot)
	}

	if lg.ArtifactKind != KindTradeLog {
		t.Fatalf("lg kind=%q", lg.ArtifactKind)
	}
	if lg.PeakAPICallsPerSec < 3 {
		t.Fatalf("lg peak=%d", lg.PeakAPICallsPerSec)
	}
	if !lg.HasHighFreqPolling {
		t.Fatalf("lg must flag HFreq: %+v", lg)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-ccxt")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "ccxt_config.json"),
		[]byte(`{"exchange":"binance","apiKey":"abcdefghijklmnop12345"}`),
		0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "CCXT_DIR" {
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
		installRoots: []string{"/nope-ccxt"},
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
		{FilePath: "a", ArtifactKind: KindStrategyPy},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	// At FilePath="a", "ccxt-config" < "ccxt-strategy-py".
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,ccxt-config)", in[0])
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
