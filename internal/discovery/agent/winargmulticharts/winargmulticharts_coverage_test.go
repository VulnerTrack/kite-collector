package winargmulticharts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixedNow is the pinned clock shared by these coverage tests.
func fixedNow() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }

func newTestCollector(installRoots, usersBases []string) *fileCollector {
	return &fileCollector{
		installRoots: installRoots,
		usersBases:   usersBases,
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          fixedNow,
	}
}

// -- trivial constructors -----------------------------------------

func TestNewCollectorName(t *testing.T) {
	c := NewCollector()
	if got := c.Name(); got != "winargmulticharts" {
		t.Fatalf("Name()=%q want winargmulticharts", got)
	}
}

func TestDefaultPathSets(t *testing.T) {
	roots := DefaultInstallRoots()
	if len(roots) != 9 {
		t.Fatalf("install roots=%d want 9", len(roots))
	}
	bases := DefaultUsersBases()
	if len(bases) != 3 {
		t.Fatalf("users bases=%d want 3", len(bases))
	}
	if len(UserMultiChartsDirs()) == 0 {
		t.Fatal("user dirs empty")
	}
}

// -- documented numeric constants ---------------------------------

func TestConstants(t *testing.T) {
	if MaxRows != 16384 {
		t.Fatalf("MaxRows=%d", MaxRows)
	}
	if MaxFileBytes != 16<<20 {
		t.Fatalf("MaxFileBytes=%d", MaxFileBytes)
	}
	if MaxWalkDepth != 6 {
		t.Fatalf("MaxWalkDepth=%d", MaxWalkDepth)
	}
	if RecentlyWindow != 90*24*time.Hour {
		t.Fatalf("RecentlyWindow=%v", RecentlyWindow)
	}
	if HighMessageRateThreshold != 1000 {
		t.Fatalf("HighMessageRateThreshold=%d", HighMessageRateThreshold)
	}
	if LargeQuoteManagerBytes != 1<<30 {
		t.Fatalf("LargeQuoteManagerBytes=%d", LargeQuoteManagerBytes)
	}
}

// -- classifiers --------------------------------------------------

func TestIsCandidateExtCoverage(t *testing.T) {
	yes := []string{
		"x.pla", "x.ela", "x.wsp", "x.pls",
		"x.cs", "x.dll", "x.cfg", "x.ini", "x.json",
		"x.xml", "x.txt", "x.log", "x.csv",
		"x.db", "x.sqlite", "x.mdf",
		"x.msi", "x.exe", "x.pkg", "x.dmg",
		"X.PLA", "REPORT.CSV",
	}
	no := []string{"x.pdf", "x.docx", "x", "x.bin", ""}
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

func TestIsCredentialKindBogus(t *testing.T) {
	// Exercises the terminal `return false` for a non-enum value.
	if IsCredentialKind(ArtifactKind("bogus-kind")) {
		t.Fatal("non-enum kind must not be credential kind")
	}
	if IsCredentialKind(KindQuoteManagerDB) {
		t.Fatal("quotemanager db is not credential kind")
	}
	if !IsCredentialKind(KindConfig) {
		t.Fatal("config is credential kind")
	}
}

func TestArtifactKindFromNameCoverage(t *testing.T) {
	cases := map[string]ArtifactKind{
		"setup.msi":                    KindOther,
		"randomtool.exe":               KindOther,
		"multicharts_installer.msi":    KindInstaller,
		"helper.cs":                    KindOther,
		"mc_strategy.cs":               KindNetScript,
		"random.dll":                   KindOther,
		"ibcontroller.dll":             KindBrokerPlugin,
		"market.db":                    KindOther,
		"quotemanager.sqlite":          KindQuoteManagerDB,
		"multicharts_credentials.json": KindCredentials,
		"portfolio_trader_config.json": KindPortfolioTraderConfig,
		"dom_config.json":              KindDOMConfig,
		"backtest_report.csv":          KindBacktestReport,
		"trade_log_202506.csv":         KindTradeLog,
		"brokerprofiles_ib.cfg":        KindConfig,
		"multicharts.json":             KindConfig,
		"random.bin":                   KindOther,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestHashSecretEmpty(t *testing.T) {
	if HashSecret("") != "" {
		t.Fatal("empty secret must hash to empty string")
	}
	if HashSecret("   ") != "" {
		t.Fatal("whitespace-only secret must hash to empty string")
	}
}

func TestSortRowsPeriodTiebreak(t *testing.T) {
	in := []Row{
		{FilePath: "a", ArtifactKind: KindTradeLog, PeriodYYYYMM: "202506"},
		{FilePath: "a", ArtifactKind: KindTradeLog, PeriodYYYYMM: "202505"},
	}
	SortRows(in)
	if in[0].PeriodYYYYMM != "202505" {
		t.Fatalf("first period=%q want 202505", in[0].PeriodYYYYMM)
	}
}

// -- Parse* exact-value tests -------------------------------------

func TestParseMCCredentialsValues(t *testing.T) {
	body := []byte(`[MultiCharts]
mc_username=bob@example.com
mc_password=hunter2xyz
mc_api_key=ZZZZ1111YYYY2222XXXX3333
[Rithmic]
rithmic_user=bob
rithmic_server=Rithmic 01
symbol=DLR
symbol=ES
cliente_cuit=30-71234567-8
`)
	f := ParseMCCredentials(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey != "ZZZZ1111YYYY2222XXXX3333" {
		t.Fatalf("apikey=%q", f.APIKey)
	}
	if f.Username != "bob@example.com" {
		t.Fatalf("username=%q", f.Username)
	}
	if !f.HasBrokerPluginCreds {
		t.Fatal("plugin creds must flag")
	}
	if f.BrokerPlugin != PluginRithmic {
		t.Fatalf("plugin=%q want rithmic", f.BrokerPlugin)
	}
	if f.MATbaSymbolsCount != 1 {
		t.Fatalf("matba=%d want 1", f.MATbaSymbolsCount)
	}
	if f.CMESymbolsCount != 1 {
		t.Fatalf("cme=%d want 1", f.CMESymbolsCount)
	}
	if f.ClienteCuitRaw != "30-71234567-8" {
		t.Fatalf("cuit=%q", f.ClienteCuitRaw)
	}
}

func TestParseMCPLAStrategyValues(t *testing.T) {
	body := []byte(`PLA-BINARY-HEADER
<sym>DLR</sym>
<sym>ES</sym>
cliente_cuit=27-11111111-4
`)
	f := ParseMCPLAStrategy(body)
	if f.MATbaSymbolsCount != 1 {
		t.Fatalf("matba=%d want 1", f.MATbaSymbolsCount)
	}
	if f.CMESymbolsCount != 1 {
		t.Fatalf("cme=%d want 1", f.CMESymbolsCount)
	}
	if f.DistinctSymbols != 2 {
		t.Fatalf("distinct=%d want 2", f.DistinctSymbols)
	}
	if f.ClienteCuitRaw != "27-11111111-4" {
		t.Fatalf("cuit=%q", f.ClienteCuitRaw)
	}
	// PLA must not leak credential fields.
	if f.HasPassword || f.APIKey != "" {
		t.Fatalf("pla must not carry creds: %+v", f)
	}
	if empty := ParseMCPLAStrategy(nil); empty.DistinctSymbols != 0 {
		t.Fatalf("empty pla non-zero: %+v", empty)
	}
}

func TestParseMCELAStrategyValues(t *testing.T) {
	body := []byte(`ELA-EXPORT
<symbol>MTR-USD</symbol>
`)
	f := ParseMCELAStrategy(body)
	if f.MATbaSymbolsCount != 1 {
		t.Fatalf("matba=%d want 1", f.MATbaSymbolsCount)
	}
	if f.DistinctSymbols != 1 {
		t.Fatalf("distinct=%d want 1", f.DistinctSymbols)
	}
}

func TestParseMCNetScriptValues(t *testing.T) {
	body := []byte(`using PowerLanguage;
// broker password="topSecret123"
string apiKey = "mc_api_key=ABCD1234EFGH5678IJKL";
InsertSymbol("ES");
InsertSymbol("DLR");
// cliente_cuit=27-11111111-4
`)
	f := ParseMCNetScript(body)
	if !f.HasPassword {
		t.Fatal("inline password must flag")
	}
	if f.APIKey == "" {
		t.Fatalf("api key must extract: %+v", f)
	}
	if f.CMESymbolsCount != 1 {
		t.Fatalf("cme=%d want 1", f.CMESymbolsCount)
	}
	if f.MATbaSymbolsCount != 1 {
		t.Fatalf("matba=%d want 1", f.MATbaSymbolsCount)
	}
	if f.ClienteCuitRaw != "27-11111111-4" {
		t.Fatalf("cuit=%q", f.ClienteCuitRaw)
	}
	if empty := ParseMCNetScript(nil); empty.APIKey != "" {
		t.Fatalf("empty net-script non-zero: %+v", empty)
	}
}

func TestParseMCPortfolioTraderConfigValues(t *testing.T) {
	body := []byte(`[PortfolioTrader]
mc_account=PT-ACME-01
autoExecution=true
<symbol>DLR</symbol>
<symbol>ES</symbol>
<symbol>MTR-USD</symbol>
`)
	f := ParseMCPortfolioTraderConfig(body)
	if !f.HasPortfolioTrader {
		t.Fatal("portfolio trader must flag")
	}
	if !f.HasSendOrderStrategy {
		t.Fatal("autoExecution must flag send-order")
	}
	if f.PortfolioSymbolCount != 3 {
		t.Fatalf("portfolio symbols=%d want 3", f.PortfolioSymbolCount)
	}
	if f.MCAccountID != "PT-ACME-01" {
		t.Fatalf("account=%q", f.MCAccountID)
	}
}

func TestParseMCBacktestReportValues(t *testing.T) {
	body := []byte(`Date,Symbol,Qty,Px
2026-06-15,DLR/JUN26,5,1234.5
2026-06-15,ES/JUN26,2,5400.25
`)
	f := ParseMCBacktestReport(body)
	if f.MATbaSymbolsCount != 1 {
		t.Fatalf("matba=%d want 1", f.MATbaSymbolsCount)
	}
	if f.CMESymbolsCount != 1 {
		t.Fatalf("cme=%d want 1", f.CMESymbolsCount)
	}
}

// -- detectBrokerPlugin: every body branch ------------------------

func TestDetectBrokerPluginAllBranches(t *testing.T) {
	cases := []struct {
		body string
		want BrokerPlugin
	}{
		{"vendor=matbarofex bridge", PluginMATbaRofex},
		{"[MatbaRofex]\nuser=x", PluginMATbaRofex},
		{"[Rithmic]\nrithmic_user=x", PluginRithmic},
		{"rithmic_server=Rithmic 01", PluginRithmic},
		{"[CQG]\ncqg_user=x", PluginCQG},
		{"cqg_continuum=on", PluginCQG},
		{"[IQFeed]\niqfeed_user=x", PluginIQFeed},
		{"iqfeed_product=MC", PluginIQFeed},
		{"[InteractiveData]\nfeed=on", PluginInteractiveData},
		{"interactive_data=on", PluginInteractiveData},
		{"[TT]\nhost=x", PluginTT},
		{"tradingtechnologies=on", PluginTT},
		{"[IB]\nib_port=7496", PluginIB},
		{"ibcontroller=on", PluginIB},
		{"[TWS]\ntws_port=7497", PluginIB},
		{"tws_port=7497", PluginIB},
		{"[Plugin]\ncustom=on", PluginCustom},
		{"nothing to see here", PluginUnknown},
		{"", PluginUnknown},
	}
	for _, c := range cases {
		if got := detectBrokerPlugin([]byte(c.body)); got != c.want {
			t.Fatalf("detectBrokerPlugin(%q)=%q want %q", c.body, got, c.want)
		}
	}
}

// -- peakMessagesPerSecond ----------------------------------------

func TestPeakMessagesPerSecond(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 MarketDataUpdate px=1
2026-06-15 09:30:01 QuoteUpdate px=2
2026-06-15 09:30:01 DOMUpdate px=3
2026-06-15 09:30:02 HeartBeat
no-timestamp MarketDepthUpdate here
2026-06-15 09:30:05 plain line without marker
`)
	if got := peakMessagesPerSecond(body); got != 3 {
		t.Fatalf("peak=%d want 3", got)
	}
	if got := peakMessagesPerSecond(nil); got != 0 {
		t.Fatalf("empty peak=%d want 0", got)
	}
	if got := peakMessagesPerSecond([]byte("just some text\nno markers\n")); got != 0 {
		t.Fatalf("no-marker peak=%d want 0", got)
	}
}

// -- mergeFields: exercise every scalar branch --------------------

func TestMergeFieldsAllBranches(t *testing.T) {
	c := newTestCollector(nil, nil)

	// Config body drives password/apikey/username/account/plugin
	// creds/broker plugin/symbols/cuit and the body-CUIT fallback.
	cfg := Row{ArtifactKind: KindConfig, BrokerPlugin: PluginUnknown}
	c.mergeFields(&cfg, []byte(`[MultiCharts]
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
`), "multicharts.cfg")
	if !cfg.HasPasswordInConfig || cfg.APIKeyHash == "" || cfg.UsernameHash == "" {
		t.Fatalf("config secrets not merged: %+v", cfg)
	}
	if cfg.MCAccountID != "ACME-FUTURES-001" {
		t.Fatalf("account=%q", cfg.MCAccountID)
	}
	if !cfg.HasBrokerPluginCredentials || cfg.BrokerPlugin != PluginRithmic {
		t.Fatalf("plugin creds not merged: %+v", cfg)
	}
	if cfg.MATbaSymbolsCount != 1 || cfg.CMESymbolsCount != 1 || cfg.DistinctSymbolsCount != 2 {
		t.Fatalf("symbols not merged: %+v", cfg)
	}
	if cfg.ClienteCuitPrefix != "27" || cfg.ClienteCuitSuffix4 != "1114" {
		t.Fatalf("body cuit not merged: %+v", cfg)
	}

	// Workspace -> send-order.
	wsp := Row{ArtifactKind: KindWorkspace, BrokerPlugin: PluginUnknown}
	c.mergeFields(&wsp, []byte(`SendOrders="true"`), "x.wsp")
	if !wsp.HasSendOrderStrategy {
		t.Fatalf("send-order not merged: %+v", wsp)
	}

	// Portfolio -> portfolio trader + symbol count.
	pls := Row{ArtifactKind: KindPortfolio, BrokerPlugin: PluginUnknown}
	c.mergeFields(&pls, []byte(`<sym>DLR</sym>
<sym>ES</sym>`), "x.pls")
	if !pls.HasPortfolioTrader || pls.PortfolioSymbolCount != 2 {
		t.Fatalf("portfolio not merged: %+v", pls)
	}

	// DOM config -> DOM armed.
	dom := Row{ArtifactKind: KindDOMConfig, BrokerPlugin: PluginUnknown}
	c.mergeFields(&dom, []byte(`DOMTrading=true
OrderBarArmed=1`), "dom_config.json")
	if !dom.HasDOMArmed {
		t.Fatalf("dom armed not merged: %+v", dom)
	}

	// Trade log -> fill count + peak msg rate.
	tl := Row{ArtifactKind: KindTradeLog, BrokerPlugin: PluginUnknown}
	c.mergeFields(&tl, []byte(`2026-06-15 09:30:01 OrderFilled QuoteUpdate symbol=DLR qty=1
2026-06-15 09:30:01 OrderFilled MarketDataUpdate symbol=ES qty=1
`), "trade_log_202506.csv")
	if tl.FillCount == 0 || tl.PeakMsgPerSec == 0 {
		t.Fatalf("trade-log not merged: %+v", tl)
	}

	// Non-parsed kinds hit the early return.
	other := Row{ArtifactKind: KindOther, BrokerPlugin: PluginUnknown}
	c.mergeFields(&other, []byte(`irrelevant`), "x.other")
	if other.HasPasswordInConfig {
		t.Fatalf("other kind must not merge: %+v", other)
	}
}

// -- ownerUID fallback --------------------------------------------

type fakeFileInfo struct{ sys any }

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return 0 }
func (f fakeFileInfo) ModTime() time.Time { return fixedNow() }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return f.sys }

func TestOwnerUIDFallback(t *testing.T) {
	if got := ownerUID(fakeFileInfo{sys: nil}); got != 0 {
		t.Fatalf("ownerUID fallback=%d want 0", got)
	}
}

// -- consider edge cases ------------------------------------------

func TestConsiderDuplicateSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multicharts.cfg")
	must(t, os.WriteFile(path, []byte(`[MultiCharts]`), 0o644))

	c := newTestCollector(nil, nil)
	out := []Row{{FilePath: path, ArtifactKind: KindConfig}}
	c.consider(path, "", &out)
	if len(out) != 1 {
		t.Fatalf("duplicate must be skipped, got %d", len(out))
	}
}

func TestConsiderStatError(t *testing.T) {
	c := newTestCollector(nil, nil)
	c.statFile = func(string) (os.FileInfo, error) { return nil, errors.New("boom") }
	var out []Row
	c.consider("/nope/multicharts.cfg", "", &out)
	if len(out) != 0 {
		t.Fatalf("stat error must append nothing, got %d", len(out))
	}
}

func TestConsiderReadFileError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multicharts.cfg")
	must(t, os.WriteFile(path, []byte(`[MultiCharts]
broker_password=secret
`), 0o644))

	c := newTestCollector(nil, nil)
	c.readFile = func(string) ([]byte, error) { return nil, errors.New("io error") }
	var out []Row
	c.consider(path, "", &out)
	if len(out) != 1 {
		t.Fatalf("row still recorded on read error, got %d", len(out))
	}
	if out[0].FileHash != "" {
		t.Fatalf("hash must stay empty on read error: %q", out[0].FileHash)
	}
	if out[0].HasPasswordInConfig {
		t.Fatal("fields must not merge when body unreadable")
	}
}

// -- walk depth guard ---------------------------------------------

func TestWalkDepthGuard(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "multicharts.cfg"), []byte(`[MultiCharts]`), 0o644))
	c := newTestCollector(nil, nil)
	var out []Row
	// depth already beyond MaxWalkDepth -> immediate return, nothing collected.
	c.walk(dir, "", &out, MaxWalkDepth+1)
	if len(out) != 0 {
		t.Fatalf("depth guard must collect nothing, got %d", len(out))
	}
}

// -- collector end-to-end over an install root --------------------

func TestCollectorInstallRootManyKinds(t *testing.T) {
	root := t.TempDir()

	write := func(name string, body []byte) string {
		p := filepath.Join(root, name)
		must(t, os.WriteFile(p, body, 0o644))
		return p
	}

	cfg := write("multicharts.cfg", []byte(`[MultiCharts]
mc_username=alice@example.com
broker_password=secret123
mc_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
mc_account=ACME-FUTURES-001
[Rithmic]
rithmic_user=alice
rithmic_server=Rithmic 01
cliente_cuit=27-11111111-4
`))
	cred := write("multicharts_credentials.json", []byte(`{"mc_api_key":"AAAA1111BBBB2222CCCC3333","mc_username":"alice@example.com"}`))
	pla := write("strat.pla", []byte("PLA-BIN\n<sym>DLR</sym>\n"))
	ela := write("export.ela", []byte("ELA\n<symbol>ES</symbol>\n"))
	cs := write("mc_strategy.cs", []byte(`InsertSymbol("DLR");
InsertSymbol("ES");
`))
	pt := write("portfolio_trader_config.json", []byte(`autoExecution=true
<symbol>DLR</symbol>
<symbol>ES</symbol>
`))
	dom := write("dom_config.json", []byte(`DOMTrading=true
OrderBarArmed=1
`))
	bt := write("backtest_report.csv", []byte("Date,Symbol\n2026-06-15,DLR\n2026-06-15,ES\n"))
	tl := write("trade_log_202506.csv", []byte(`2026-06-15 09:30:01 OrderFilled MarketDataUpdate symbol=DLR
2026-06-15 09:30:01 OrderFilled QuoteUpdate symbol=ES
`))
	dll := write("multicharts_rithmic.dll", []byte("MZ binary rithmic plugin"))
	qm := write("quotemanager.db", []byte("SQLite format 3\x00 quotemanager"))
	msi := write("multicharts_installer.msi", []byte("MSI installer binary"))
	// Non-candidate extension is ignored by walk.
	write("readme.pdf", []byte("pdf"))

	c := newTestCollector([]string{root}, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	byPath := map[string]Row{}
	for _, r := range got {
		byPath[r.FilePath] = r
	}

	// The .pdf must not appear.
	if _, ok := byPath[filepath.Join(root, "readme.pdf")]; ok {
		t.Fatal("non-candidate .pdf must be skipped")
	}

	// Every artifact kind is present with the expected classification.
	checks := []struct {
		path string
		kind ArtifactKind
	}{
		{cfg, KindConfig},
		{cred, KindCredentials},
		{pla, KindPLAStrategy},
		{ela, KindELAStrategy},
		{cs, KindNetScript},
		{pt, KindPortfolioTraderConfig},
		{dom, KindDOMConfig},
		{bt, KindBacktestReport},
		{tl, KindTradeLog},
		{dll, KindBrokerPlugin},
		{qm, KindQuoteManagerDB},
		{msi, KindInstaller},
	}
	for _, ck := range checks {
		r, ok := byPath[ck.path]
		if !ok {
			t.Fatalf("missing artifact: %s", ck.path)
		}
		if r.ArtifactKind != ck.kind {
			t.Fatalf("%s kind=%q want %q", ck.path, r.ArtifactKind, ck.kind)
		}
	}

	// Config: creds + cuit + exposure risk (world-readable 0644).
	if r := byPath[cfg]; !r.HasPasswordInConfig || !r.HasClienteCuit ||
		r.BrokerPlugin != PluginRithmic || !r.IsCredentialExposureRisk {
		t.Fatalf("config row underclassified: %+v", r)
	}

	// PLA kind auto-flags encrypted strategy.
	if r := byPath[pla]; !r.HasPLAEncrypted {
		t.Fatalf("pla must flag encrypted: %+v", r)
	}

	// .cs kind auto-flags native strategy.
	if r := byPath[cs]; !r.HasCSNativeStrategy {
		t.Fatalf("cs must flag native strategy: %+v", r)
	}

	// DOM armed drives HFT classification.
	if r := byPath[dom]; !r.HasDOMArmed || r.AccountClass != AccountHFT ||
		r.ProductClass != ProductHFTExecution {
		t.Fatalf("dom row underclassified: %+v", r)
	}

	// QuoteManager DB: hash present (skip-body hash path), QM flagged.
	if r := byPath[qm]; !r.HasQuoteManagerDB || r.FileHash == "" {
		t.Fatalf("quotemanager row underclassified: %+v", r)
	}

	// Installer: skip-body but still hashed, no parse.
	if r := byPath[msi]; r.FileHash == "" {
		t.Fatalf("installer must be hashed: %+v", r)
	}

	// DLL: skip-body, plugin identity sniffed from filename.
	if r := byPath[dll]; r.BrokerPlugin != PluginRithmic || r.FileHash == "" {
		t.Fatalf("dll row underclassified: %+v", r)
	}

	// Files are recent under the fixed clock (mod time == now).
	if r := byPath[cfg]; !r.IsRecent {
		t.Fatalf("cfg should be recent: %+v", r)
	}
}
