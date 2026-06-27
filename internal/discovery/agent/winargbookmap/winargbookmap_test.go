package winargbookmap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "bookmap-config"},
		{string(KindCredentials), "bookmap-credentials"},
		{string(KindWorkspace), "bookmap-workspace"},
		{string(KindBTRRecording), "bookmap-btr-recording"},
		{string(KindIndicatorSDK), "bookmap-indicator-sdk"},
		{string(KindMarketplacePlugin), "bookmap-marketplace-plugin"},
		{string(KindConnectionConfig), "bookmap-connection-config"},
		{string(KindSessionLog), "bookmap-session-log"},
		{string(KindMBOCache), "bookmap-mbo-cache"},
		{string(KindInstaller), "bookmap-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountHFT), "hft"},
		{string(AccountScalper), "scalper"},
		{string(AccountPropTrader), "prop-trader"},
		{string(AccountOrderFlowResearcher), "order-flow-researcher"},
		{string(AccountAlgotrader), "algotrader"},
		{string(AccountAPI), "api"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(ProductCMEFutures), "cme-futures"},
		{string(ProductMATbaRofex), "matba-rofex"},
		{string(ProductUSEquity), "us-equity"},
		{string(ProductCrypto), "crypto"},
		{string(ProductMultiVenue), "multi-venue"},
		{string(ProductHFTExecution), "hft-execution"},
		{string(ProductOther), "other"},
		{string(ProductUnknown), "unknown"},
		{string(PluginIB), "ib"},
		{string(PluginRithmic), "rithmic"},
		{string(PluginCQG), "cqg"},
		{string(PluginTT), "tt"},
		{string(PluginDAS), "das"},
		{string(PluginKraken), "kraken"},
		{string(PluginBinance), "binance"},
		{string(PluginBitfinex), "bitfinex"},
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
		"bookmap.cfg",
		"bookmap_credentials.json",
		"my_workspace.bookmap",
		"recording_20260615.btr",
		"my_indicator.indicator",
		"bookmap_plugin.java",
		"speed_of_tape_cfg.json",
		"order_flow_analytics.json",
		"mbo_data_es.bin",
		"connection_config_ib.json",
		"bookmap_installer.msi",
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
		"bookmap.cfg":               KindConfig,
		"bookmap_credentials.json":  KindCredentials,
		"bookmap_api_token.json":    KindCredentials,
		"my_workspace.bookmap":      KindWorkspace,
		"recording_20260615.btr":    KindBTRRecording,
		"my_indicator.indicator":    KindIndicatorSDK,
		"bookmap_plugin.java":       KindIndicatorSDK,
		"marketplace_plugin.jar":    KindMarketplacePlugin,
		"connection_config_ib.json": KindConnectionConfig,
		"mbo_data_es.bin":           KindMBOCache,
		"bookmap_session.log":       KindSessionLog,
		"bookmap_installer.msi":     KindInstaller,
		"":                          KindUnknown,
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
	if PeriodFromFilename("bookmap_session_202506.log") != "202506" {
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

func TestIsCryptoSymbol(t *testing.T) {
	yes := []string{"BTC", "ETH", "USDT/ARS", "USDT"}
	no := []string{"", "AAPL", "DLR", "ES"}
	for _, v := range yes {
		if !IsCryptoSymbol(v) {
			t.Fatalf("expected crypto: %q", v)
		}
	}
	for _, v := range no {
		if IsCryptoSymbol(v) {
			t.Fatalf("expected NOT crypto: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindWorkspace,
		KindBTRRecording, KindIndicatorSDK, KindMarketplacePlugin,
		KindConnectionConfig, KindSessionLog, KindMBOCache,
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

func TestAnnotateBTRAuto(t *testing.T) {
	r := Row{ArtifactKind: KindBTRRecording, FileSize: 100 << 20}
	AnnotateSecurity(&r)
	if !r.HasBTRRecording {
		t.Fatal("BTR kind must auto-flag")
	}
	if !r.HasL3OrderbookData {
		t.Fatal("BTR implies L3 data")
	}
	if r.HasLargeBTRRecording {
		t.Fatal("100 MB must NOT flag large")
	}
}

func TestAnnotateLargeBTR(t *testing.T) {
	r := Row{
		ArtifactKind: KindBTRRecording,
		FileSize:     LargeBTRBytes + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasLargeBTRRecording {
		t.Fatal("> 5 GiB BTR must flag large")
	}
}

func TestAnnotateIndicatorAuto(t *testing.T) {
	r := Row{ArtifactKind: KindIndicatorSDK}
	AnnotateSecurity(&r)
	if !r.HasIndicatorSDK {
		t.Fatal("indicator kind must auto-flag")
	}
}

func TestAnnotateMarketplaceAuto(t *testing.T) {
	r := Row{ArtifactKind: KindMarketplacePlugin}
	AnnotateSecurity(&r)
	if !r.HasMarketplacePlugin {
		t.Fatal("marketplace kind must auto-flag")
	}
}

func TestAnnotateMBOAuto(t *testing.T) {
	r := Row{ArtifactKind: KindMBOCache}
	AnnotateSecurity(&r)
	if !r.HasMBOSubscription {
		t.Fatal("MBO cache kind must auto-flag")
	}
	if !r.HasL3OrderbookData {
		t.Fatal("MBO implies L3")
	}
}

func TestAnnotateCrossVenue(t *testing.T) {
	r := Row{
		ArtifactKind:       KindWorkspace,
		MATbaSymbolsCount:  1,
		CMESymbolsCount:    1,
		CryptoSymbolsCount: 1,
	}
	AnnotateSecurity(&r)
	if !r.HasMATbaRofexRouting {
		t.Fatal("MATba count must flag")
	}
	if !r.HasCMEFutures {
		t.Fatal("CME count must flag")
	}
	if !r.HasCryptoData {
		t.Fatal("crypto count must flag")
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

func TestParseBookmapConfig(t *testing.T) {
	body := []byte(`# Bookmap config
bookmap_username=alice@example.com
bookmap_password=secret123
broker_password=AnotherSecret
api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
bookmap_account=ACME-001
[Rithmic]
rithmic_user=alice
rithmic_server=Rithmic 01
speed_of_tape_armed=true
iceberg_auto_trade=enabled
mbo_subscription=true
market_by_order=premium
symbol=DLR
symbol=ES
symbol=BTC/USDT
cliente_cuit=27-11111111-4
`)
	f := ParseBookmapConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.BookmapAccountID == "" {
		t.Fatalf("account=%q", f.BookmapAccountID)
	}
	if f.BrokerPlugin != PluginRithmic {
		t.Fatalf("plugin=%q want rithmic", f.BrokerPlugin)
	}
	if !f.HasSpeedOfTapeArmed {
		t.Fatal("speed of tape must flag")
	}
	if !f.HasMBOSubscription {
		t.Fatal("MBO must flag")
	}
	if f.MATbaSymbolsCount < 1 {
		t.Fatalf("matba=%d", f.MATbaSymbolsCount)
	}
	if f.CMESymbolsCount < 1 {
		t.Fatalf("cme=%d", f.CMESymbolsCount)
	}
	if f.CryptoSymbolsCount < 1 {
		t.Fatalf("crypto=%d", f.CryptoSymbolsCount)
	}
}

func TestParseBookmapIndicatorSDK(t *testing.T) {
	body := []byte(`package velox.api.layer1.simplified;
import com.bookmap.api.simple.CustomIndicator;

public class MyIndicator implements CustomIndicator {
    @Override
    public void onBookUpdate() {
        // detect spoofing pattern
    }
}
api_key="aBcDeFgHiJkLmNoPqRsTuVwX12345"
`)
	f := ParseBookmapIndicatorSDK(body)
	if f.IndicatorCount < 1 {
		t.Fatalf("indicators=%d", f.IndicatorCount)
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
}

func TestParseBookmapEmpty(t *testing.T) {
	f := ParseBookmapConfig(nil)
	if f.HasPassword || f.APIKey != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestDetectBrokerPlugin(t *testing.T) {
	cases := map[string]BrokerPlugin{
		`[Rithmic]`:      PluginRithmic,
		`[CQG]`:          PluginCQG,
		`[TT]`:           PluginTT,
		`[DAS]`:          PluginDAS,
		`[Kraken]`:       PluginKraken,
		`[Binance]`:      PluginBinance,
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
	if got := classifyAccount(Row{HasSpeedOfTapeArmed: true}); got != AccountHFT {
		t.Fatalf("SoT -> hft, got %q", got)
	}
	if got := classifyAccount(Row{HasMBOSubscription: true}); got != AccountHFT {
		t.Fatalf("MBO -> hft, got %q", got)
	}
	if got := classifyAccount(Row{HasBTRRecording: true}); got != AccountOrderFlowResearcher {
		t.Fatalf("BTR -> researcher, got %q", got)
	}
	if got := classifyAccount(Row{HasIndicatorSDK: true}); got != AccountAlgotrader {
		t.Fatalf("indicator -> algotrader, got %q", got)
	}
	if got := classifyAccount(Row{HasCMEFutures: true}); got != AccountScalper {
		t.Fatalf("cme -> scalper, got %q", got)
	}
	if got := classifyAccount(Row{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyProduct(t *testing.T) {
	if got := classifyProduct(Row{HasSpeedOfTapeArmed: true}); got != ProductHFTExecution {
		t.Fatalf("SoT -> hft-execution, got %q", got)
	}
	if got := classifyProduct(Row{
		HasCMEFutures: true,
		HasCryptoData: true,
	}); got != ProductMultiVenue {
		t.Fatalf("multi -> multi-venue, got %q", got)
	}
	if got := classifyProduct(Row{HasMATbaRofexRouting: true}); got != ProductMATbaRofex {
		t.Fatalf("matba -> matba-rofex, got %q", got)
	}
	if got := classifyProduct(Row{HasCryptoData: true}); got != ProductCrypto {
		t.Fatalf("crypto -> crypto, got %q", got)
	}
	if got := classifyProduct(Row{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Bookmap")
	must(t, os.MkdirAll(dir, 0o755))

	cfgPath := filepath.Join(dir, "bookmap.cfg")
	must(t, os.WriteFile(cfgPath, []byte(`bookmap_username=alice@example.com
bookmap_password=secret123
api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
[Rithmic]
rithmic_user=alice
speed_of_tape_armed=true
mbo_subscription=true
symbol=ES
symbol=BTC/USDT
cliente_cuit=27-11111111-4
`), 0o644))

	indPath := filepath.Join(dir, "my_indicator.java")
	must(t, os.WriteFile(indPath, []byte(`package velox.api.layer1.simplified;
import com.bookmap.api.simple.CustomIndicator;
public class MyInd implements CustomIndicator {
    public void onBookUpdate() {}
}
`), 0o644))

	btrPath := filepath.Join(dir, "recording_20260615.btr")
	must(t, os.WriteFile(btrPath, make([]byte, 200), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Bookmap")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "bookmap.cfg"),
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
		t.Fatalf("want 3 (cfg+ind+btr), got %d: %+v", len(got), got)
	}

	var cfg, ind, btr Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case indPath:
			ind = r
		case btrPath:
			btr = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if cfg.BrokerPlugin != PluginRithmic {
		t.Fatalf("cfg plugin=%q want rithmic", cfg.BrokerPlugin)
	}
	if !cfg.HasSpeedOfTapeArmed {
		t.Fatalf("cfg must flag SoT: %+v", cfg)
	}
	if !cfg.HasMBOSubscription {
		t.Fatalf("cfg must flag MBO: %+v", cfg)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cliente = exposure: %+v", cfg)
	}

	if ind.ArtifactKind != KindIndicatorSDK {
		t.Fatalf("ind kind=%q", ind.ArtifactKind)
	}
	if !ind.HasIndicatorSDK {
		t.Fatalf("ind must auto-flag: %+v", ind)
	}

	if btr.ArtifactKind != KindBTRRecording {
		t.Fatalf("btr kind=%q", btr.ArtifactKind)
	}
	if !btr.HasBTRRecording {
		t.Fatalf("btr must auto-flag: %+v", btr)
	}
	if !btr.HasL3OrderbookData {
		t.Fatalf("btr must imply L3: %+v", btr)
	}
	if btr.AccountClass != AccountOrderFlowResearcher {
		t.Fatalf("btr account=%q want order-flow-researcher", btr.AccountClass)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-bm")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "bookmap.cfg"),
		[]byte(`bookmap_account=ACME`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "BOOKMAP_DIR" {
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
		installRoots: []string{"/nope-bm"},
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
		t.Fatalf("first=%+v want (a,bookmap-config)", in[0])
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
