package winargquantower

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixedClock at 2026-06-16 UTC — matches the reference collectors.
func fixedClock() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }

// fakeFileInfo is an os.FileInfo whose Sys() is caller-controlled, used
// to drive ownerUID's non-*syscall.Stat_t fallback branch.
type fakeFileInfo struct{ sys any }

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return 0 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return f.sys }

// -- trivial constructors / path sets -----------------------------

func TestCovNewCollectorName(t *testing.T) {
	c := NewCollector()
	if c.Name() != "winargquantower" {
		t.Fatalf("Name()=%q want winargquantower", c.Name())
	}
}

func TestCovDefaultPathSets(t *testing.T) {
	if got := len(DefaultInstallRoots()); got != 6 {
		t.Fatalf("install roots=%d want 6", got)
	}
	if got := len(DefaultUsersBases()); got != 3 {
		t.Fatalf("users bases=%d want 3", got)
	}
}

func TestCovConstants(t *testing.T) {
	if MaxRows != 16384 {
		t.Fatalf("MaxRows=%d want 16384", MaxRows)
	}
	if MaxFileBytes != 16<<20 {
		t.Fatalf("MaxFileBytes=%d want %d", MaxFileBytes, 16<<20)
	}
	if RecentlyWindow != 90*24*time.Hour {
		t.Fatalf("RecentlyWindow=%v", RecentlyWindow)
	}
	if HighMessageRateThreshold != 1000 {
		t.Fatalf("HighMessageRateThreshold=%d want 1000", HighMessageRateThreshold)
	}
	if MaxWalkDepth != 6 {
		t.Fatalf("MaxWalkDepth=%d want 6", MaxWalkDepth)
	}
}

// -- classifiers ---------------------------------------------------

func TestCovIsCandidateExt(t *testing.T) {
	yes := []string{
		"x.qwt", "x.cs", "x.dll", "x.cfg", "x.ini", "x.json",
		"x.xml", "x.yaml", "x.yml", "x.csv", "x.tsv", "x.log",
		"x.txt", "x.msi", "x.exe", "x.pkg", "x.dmg", "X.JSON", "Y.QWT",
	}
	no := []string{"x.pdf", "x.docx", "noext", ""}
	for _, v := range yes {
		if !IsCandidateExt(v) {
			t.Fatalf("expected candidate ext: %q", v)
		}
	}
	for _, v := range no {
		if IsCandidateExt(v) {
			t.Fatalf("expected NOT candidate ext: %q", v)
		}
	}
}

func TestCovIsCredentialKindDefault(t *testing.T) {
	if IsCredentialKind(ArtifactKind("not-a-real-kind")) {
		t.Fatal("unknown enum value must not be a credential kind")
	}
}

func TestCovArtifactKindFromNameEdges(t *testing.T) {
	cases := map[string]ArtifactKind{
		"setup.exe":            KindOther,       // installer ext, no quantower token
		"random_installer.pkg": KindOther,       // installer ext, no quantower token
		"helper.cs":            KindOther,       // .cs but no strategy/quantower/indicator
		"random.dll":           KindOther,       // .dll but no quantower/strategy
		"session_token.json":   KindCredentials, // session_token token
		"quantower_report.csv": KindOther,       // quantower token but non-config ext
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

// -- HashSecret empty ---------------------------------------------

func TestCovHashSecretEmpty(t *testing.T) {
	if HashSecret("") != "" {
		t.Fatal("empty secret must hash to empty")
	}
	if HashSecret("   ") != "" {
		t.Fatal("whitespace-only secret must hash to empty")
	}
}

// -- ownerUID fallback --------------------------------------------

func TestCovOwnerUIDFallback(t *testing.T) {
	if got := ownerUID(fakeFileInfo{sys: nil}); got != 0 {
		t.Fatalf("ownerUID(non-stat)=%d want 0", got)
	}
	if got := ownerUID(fakeFileInfo{sys: "not-a-stat_t"}); got != 0 {
		t.Fatalf("ownerUID(wrong-sys)=%d want 0", got)
	}
}

// -- detectBrokerPlugin remaining branches ------------------------

func TestCovDetectBrokerPluginAll(t *testing.T) {
	cases := map[string]BrokerPlugin{
		"[Bitfinex]":             PluginBitfinex,
		"bitfinex_api_key=x":     PluginBitfinex,
		"[Kraken]":               PluginKraken,
		"kraken_api_key=x":       PluginKraken,
		"[Coinbase]":             PluginCoinbase,
		"coinbase_api_key=x":     PluginCoinbase,
		"[Continuum]":            PluginCQG,
		"ibcontroller=1":         PluginIB,
		"dxfeed_credentials=y":   PluginDXFeed,
		"oanda_account=123":      PluginOanda,
		"[plugin]":               PluginCustom,
		"custom_plugin=whatever": PluginCustom,
	}
	for in, want := range cases {
		if got := detectBrokerPlugin([]byte(in)); got != want {
			t.Fatalf("detectBrokerPlugin(%q)=%q want %q", in, got, want)
		}
	}
}

// -- peakMessagesPerSecond ----------------------------------------

func TestCovPeakMessagesPerSecond(t *testing.T) {
	body := []byte(`2026-06-16 09:30:01 MarketDataUpdate ES
2026-06-16 09:30:01 QuoteUpdate ES
2026-06-16 09:30:01 TradeUpdate ES
2026-06-16 09:30:02 OrderUpdate ES
2026-06-16 09:30:02 DOMUpdate ES
line without marker or timestamp
2026-06-16 09:30:03 no-marker-here
HeartBeat without timestamp
`)
	if got := peakMessagesPerSecond(body); got != 3 {
		t.Fatalf("peak=%d want 3", got)
	}
	if got := peakMessagesPerSecond(nil); got != 0 {
		t.Fatalf("empty peak=%d want 0", got)
	}
	if got := peakMessagesPerSecond([]byte("just plain text\n")); got != 0 {
		t.Fatalf("no-marker peak=%d want 0", got)
	}
}

// -- Parse* wrappers ----------------------------------------------

func TestCovParseCredentialsAndWorkspace(t *testing.T) {
	body := []byte("quantower_password=secret123\n")
	if f := ParseQuantowerCredentials(body); !f.HasPassword {
		t.Fatal("credentials must flag password")
	}
	if f := ParseQuantowerWorkspace(body); !f.HasPassword {
		t.Fatal("workspace must flag password")
	}
	if f := ParseQuantowerAlgoBuilder(body); !f.HasPassword {
		t.Fatal("algo-builder must flag password")
	}
}

func TestCovParseSymbols(t *testing.T) {
	body := []byte(`{"symbols":[{"symbol":"DLR"},{"symbol":"ES"},{"symbol":"AAPL"},{"symbol":"BTC/USDT"}]}`)
	f := ParseQuantowerSymbols(body)
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
	if f.DistinctSymbols < 4 {
		t.Fatalf("distinct=%d want >=4", f.DistinctSymbols)
	}
	if f := ParseQuantowerSymbols(nil); f.DistinctSymbols != 0 {
		t.Fatalf("empty symbols distinct=%d want 0", f.DistinctSymbols)
	}
}

func TestCovParseConnectionConfig(t *testing.T) {
	body := []byte(`[Binance]
binance_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
tws_port=7497
`)
	f := ParseQuantowerConnectionConfig(body)
	if !f.HasPassword {
		t.Fatal("plugin section + plugin credential must force HasPassword")
	}
	if f.BrokerPlugin != PluginBinance {
		t.Fatalf("plugin=%q want binance", f.BrokerPlugin)
	}
}

func TestCovParseMultiStrategyLauncher(t *testing.T) {
	body := []byte(`public class A : Strategy {}
public class B : Strategy {}
quantower_account=ACME-9
`)
	f := ParseQuantowerMultiStrategyLauncher(body)
	if f.StrategyCount != 2 {
		t.Fatalf("strategies=%d want 2", f.StrategyCount)
	}
	if f.QuantowerAccountID == "" {
		t.Fatal("account must extract")
	}
}

func TestCovParseTradeLog(t *testing.T) {
	body := []byte(`quantower_account=ACME-777
2026-06-16 09:30:01 TradeUpdate
2026-06-16 09:30:01 QuoteUpdate
symbol=ES
symbol=BTC/USDT
cliente_cuit=30-71234567-8
`)
	f := ParseQuantowerTradeLog(body)
	if f.QuantowerAccountID != "ACME-777" {
		t.Fatalf("account=%q want ACME-777", f.QuantowerAccountID)
	}
	if f.PeakMsgPerSec != 2 {
		t.Fatalf("peak=%d want 2", f.PeakMsgPerSec)
	}
	if f.CMESymbolsCount < 1 {
		t.Fatalf("cme=%d", f.CMESymbolsCount)
	}
	if f.CryptoSymbolsCount < 1 {
		t.Fatalf("crypto=%d", f.CryptoSymbolsCount)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit must extract")
	}
	if f := ParseQuantowerTradeLog(nil); f.PeakMsgPerSec != 0 {
		t.Fatalf("empty trade-log peak=%d want 0", f.PeakMsgPerSec)
	}
}

// -- classifyProduct / classifyAccount remaining branches ---------

func TestCovClassifyProductSingleVenue(t *testing.T) {
	if got := classifyProduct(Row{HasCMEFutures: true}); got != ProductCMEFutures {
		t.Fatalf("cme -> cme-futures, got %q", got)
	}
	if got := classifyProduct(Row{HasUSEquity: true}); got != ProductUSEquity {
		t.Fatalf("us -> us-equity, got %q", got)
	}
}

func TestCovClassifyAccountPasswordFallback(t *testing.T) {
	if got := classifyAccount(Row{HasPasswordInConfig: true}); got != AccountAlgotrader {
		t.Fatalf("password -> algotrader, got %q", got)
	}
	if got := classifyAccount(Row{HasBrokerPluginCredentials: true}); got != AccountAlgotrader {
		t.Fatalf("plugin creds -> algotrader, got %q", got)
	}
}

// -- SortRows period tie-break ------------------------------------

func TestCovSortRowsPeriodTieBreak(t *testing.T) {
	in := []Row{
		{FilePath: "a", ArtifactKind: KindTradeLog, PeriodYYYYMM: "202507"},
		{FilePath: "a", ArtifactKind: KindTradeLog, PeriodYYYYMM: "202506"},
	}
	SortRows(in)
	if in[0].PeriodYYYYMM != "202506" {
		t.Fatalf("period tie-break first=%q want 202506", in[0].PeriodYYYYMM)
	}
}

// -- mergeFields (direct) covering every kind + field branch ------

func TestCovMergeFieldsConfig(t *testing.T) {
	c := &fileCollector{}
	body := []byte(`# Quantower config
quantower_username=alice@example.com
quantower_password=secret123
api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
api_secret=zYxWvUtSrQpOnMlKjIhGfEdCbA0123
quantower_account=ACME-001
[Binance]
binance_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
paper_trading=true
symbol=DLR
symbol=ES
symbol=AAPL
symbol=BTC/USDT
cliente_cuit=27-11111111-4
`)
	row := Row{ArtifactKind: KindConfig, BrokerPlugin: PluginUnknown}
	c.mergeFields(&row, body)
	if !row.HasPasswordInConfig {
		t.Fatal("password field must set")
	}
	if row.APIKeyHash == "" || row.APISecretHash == "" || row.UsernameHash == "" {
		t.Fatalf("hashes must set: %+v", row)
	}
	if row.QuantowerAccountID == "" {
		t.Fatal("account id must set")
	}
	if !row.HasPaperTradingMode {
		t.Fatal("paper-trading must set")
	}
	if row.BrokerPlugin != PluginBinance {
		t.Fatalf("plugin=%q want binance", row.BrokerPlugin)
	}
	if row.MATbaSymbolsCount < 1 || row.CMESymbolsCount < 1 ||
		row.USEquitySymbolsCount < 1 || row.CryptoSymbolsCount < 1 {
		t.Fatalf("symbol counts must set: %+v", row)
	}
	if row.DistinctSymbolsCount < 1 {
		t.Fatalf("distinct=%d", row.DistinctSymbolsCount)
	}
	if row.ClienteCuitPrefix != "27" || row.ClienteCuitSuffix4 != "1114" {
		t.Fatalf("cliente cuit=%q/%q", row.ClienteCuitPrefix, row.ClienteCuitSuffix4)
	}
}

func TestCovMergeFieldsKinds(t *testing.T) {
	c := &fileCollector{}

	// DOM config -> HasDOMArmed.
	dom := Row{ArtifactKind: KindDOMConfig}
	c.mergeFields(&dom, []byte("dom_armed=true\n"))
	if !dom.HasDOMArmed {
		t.Fatal("dom-config must set armed")
	}

	// Algo SDK script -> strategy count + USDT/ARS arbitrage.
	sdk := Row{ArtifactKind: KindAlgoSDKScript}
	c.mergeFields(&sdk, []byte(`public class S : Strategy {}
// brecha cambiaria usdt_ars
`))
	if sdk.StrategyCount < 1 {
		t.Fatalf("sdk strategies=%d", sdk.StrategyCount)
	}
	if !sdk.HasUSDTARSArbitrage {
		t.Fatal("sdk must flag USDT/ARS arb")
	}

	// Trade log -> peak msg/s.
	tl := Row{ArtifactKind: KindTradeLog}
	c.mergeFields(&tl, []byte(`2026-06-16 09:30:01 TradeUpdate
2026-06-16 09:30:01 QuoteUpdate
`))
	if tl.PeakMsgPerSec != 2 {
		t.Fatalf("trade-log peak=%d want 2", tl.PeakMsgPerSec)
	}

	// Workspace / Symbols / ConnectionConfig / AlgoBuilder / MultiStrategy
	// each route through mergeFields without panicking.
	for _, k := range []ArtifactKind{
		KindWorkspace, KindSymbols, KindConnectionConfig,
		KindAlgoBuilder, KindMultiStrategyLauncher, KindCredentials,
	} {
		r := Row{ArtifactKind: k}
		c.mergeFields(&r, []byte("symbol=ES\nquantower_account=ACME-2\n"))
	}

	// Installer / Other / Unknown -> early return, row untouched.
	for _, k := range []ArtifactKind{KindInstaller, KindOther, KindUnknown} {
		r := Row{ArtifactKind: k}
		c.mergeFields(&r, []byte("quantower_password=secret\napi_key=aBcDeFgHiJkLmNoPqRsTuVwX12345\n"))
		if r.HasPasswordInConfig || r.APIKeyHash != "" {
			t.Fatalf("kind %q must early-return untouched: %+v", k, r)
		}
	}
}

// -- consider (direct) covering dedup / stat error / read error ---

func TestCovConsiderDedup(t *testing.T) {
	c := &fileCollector{
		readFile: os.ReadFile, readDir: os.ReadDir,
		statFile: os.Stat, now: fixedClock,
	}
	out := []Row{{FilePath: "/already/seen.cfg"}}
	c.consider("/already/seen.cfg", "", &out)
	if len(out) != 1 {
		t.Fatalf("dedup must not append: %d", len(out))
	}
}

func TestCovConsiderStatError(t *testing.T) {
	c := &fileCollector{
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: func(string) (os.FileInfo, error) { return nil, errors.New("stat boom") },
		now:      fixedClock,
	}
	var out []Row
	c.consider("/whatever/quantower.cfg", "", &out)
	if len(out) != 0 {
		t.Fatalf("stat error must skip: %d", len(out))
	}
}

func TestCovConsiderReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "quantower.cfg")
	must(t, os.WriteFile(path, []byte("quantower_password=secret\n"), 0o644))

	c := &fileCollector{
		readFile: func(string) ([]byte, error) { return nil, errors.New("read boom") },
		readDir:  os.ReadDir,
		statFile: os.Stat,
		now:      fixedClock,
	}
	var out []Row
	c.consider(path, "", &out)
	if len(out) != 1 {
		t.Fatalf("row must still append on read error: %d", len(out))
	}
	if out[0].FileHash != "" {
		t.Fatalf("read error must leave hash empty: %q", out[0].FileHash)
	}
	if out[0].HasPasswordInConfig {
		t.Fatal("read error must skip field merge")
	}
}

func TestCovConsiderBinarySkipBody(t *testing.T) {
	dir := t.TempDir()
	// .dll is a candidate (quantower token) but body is skipped:
	// only the hash is taken, no field merge.
	dll := filepath.Join(dir, "quantower_strategy.dll")
	must(t, os.WriteFile(dll, []byte("quantower_password=secret\nMZbinary"), 0o644))

	c := &fileCollector{
		readFile: os.ReadFile, readDir: os.ReadDir,
		statFile: os.Stat, now: fixedClock,
	}
	var out []Row
	c.consider(dll, "", &out)
	if len(out) != 1 {
		t.Fatalf("dll must append: %d", len(out))
	}
	if out[0].ArtifactKind != KindAlgoSDKScript {
		t.Fatalf("dll kind=%q want algo-sdk-script", out[0].ArtifactKind)
	}
	if out[0].FileHash == "" {
		t.Fatal("dll must still be hashed")
	}
	if out[0].HasPasswordInConfig {
		t.Fatal("dll body must NOT be parsed for fields")
	}
}

// -- walk depth guard ---------------------------------------------

func TestCovWalkDepthGuard(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "quantower.cfg"),
		[]byte("quantower_account=ACME\n"), 0o644))

	c := &fileCollector{
		readFile: os.ReadFile, readDir: os.ReadDir,
		statFile: os.Stat, now: fixedClock,
	}
	var out []Row
	c.walk(dir, "", &out, MaxWalkDepth+1)
	if len(out) != 0 {
		t.Fatalf("depth over limit must collect nothing: %d", len(out))
	}
}

// -- Collect via install roots (non-env path) ---------------------

func TestCovCollectInstallRoot(t *testing.T) {
	root := t.TempDir()
	must(t, os.WriteFile(filepath.Join(root, "quantower.cfg"),
		[]byte("quantower_account=ACME-INSTALL\n"), 0o644))

	c := &fileCollector{
		installRoots: []string{root},
		usersBases:   nil,
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          fixedClock,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || got[0].ArtifactKind != KindConfig {
		t.Fatalf("install-root collect: %+v", got)
	}
	if !got[0].IsRecent {
		t.Fatal("freshly written file under fixed clock must be recent")
	}
}
