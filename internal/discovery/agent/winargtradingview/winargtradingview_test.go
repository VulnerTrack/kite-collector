package winargtradingview

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindPineScript), "tv-pine-script"},
		{string(KindStrategyAlert), "tv-strategy-alert"},
		{string(KindWebhookConfig), "tv-webhook-config"},
		{string(KindWatchlist), "tv-watchlist"},
		{string(KindChartLayout), "tv-chart-layout"},
		{string(KindIndicator), "tv-indicator"},
		{string(KindBrokerLink), "tv-broker-link"},
		{string(KindConfig), "tv-config"},
		{string(KindCache), "tv-cache"},
		{string(KindInstaller), "tv-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(BrokerOANDA), "oanda"},
		{string(BrokerFXCM), "fxcm"},
		{string(BrokerCapitalCom), "capitalcom"},
		{string(BrokerEasyMarkets), "easymarkets"},
		{string(BrokerAlpaca), "alpaca"},
		{string(BrokerForexCom), "forexcom"},
		{string(BrokerSaxo), "saxo"},
		{string(BrokerTradier), "tradier"},
		{string(BrokerGemini), "gemini"},
		{string(BrokerBitstamp), "bitstamp"},
		{string(BrokerTradovate), "tradovate"},
		{string(BrokerPaperOnly), "paperonly"},
		{string(BrokerWebhookOther), "webhook-other"},
		{string(BrokerOther), "other"},
		{string(BrokerUnknown), "unknown"},
		{string(PineV3), "v3"},
		{string(PineV4), "v4"},
		{string(PineV5), "v5"},
		{string(PineV6), "v6"},
		{string(PineOther), "other"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"strategy.pine",
		"my_strategy.pinescript",
		"strategy_alert_GGAL.json",
		"webhook_GGAL.json",
		"watchlist_001.csv",
		"chart_layout_main.json",
		"indicator_RSI.pine",
		"broker_link_oanda.json",
		"tradingview.ini",
		"tv_config.json",
		"tv-cache.json",
		"tradingview_installer.exe",
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
		"strategy.pine":                KindPineScript,
		"my_strategy.pinescript":       KindPineScript,
		"indicator_RSI.pine":           KindIndicator,
		"strategy_alert_GGAL.json":     KindStrategyAlert,
		"webhook_GGAL.json":            KindWebhookConfig,
		"watchlist_001.csv":            KindWatchlist,
		"chart_layout_main.json":       KindChartLayout,
		"broker_link_oanda.json":       KindBrokerLink,
		"tradingview.ini":              KindConfig,
		"tradingview_v8_installer.msi": KindInstaller,
		"tv_cache.json":                KindCache,
		"":                             KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestLinkedBrokerFromBody(t *testing.T) {
	cases := map[string]LinkedBroker{
		`{"broker":"https://api-fxpractice.oanda.com"}`:    BrokerOANDA,
		`{"endpoint":"https://api.fxcm.com"}`:              BrokerFXCM,
		`{"endpoint":"https://api-capital.capital.com"}`:   BrokerCapitalCom,
		`{"endpoint":"https://api.easymarkets.com"}`:       BrokerEasyMarkets,
		`{"endpoint":"https://api.alpaca.markets"}`:        BrokerAlpaca,
		`{"endpoint":"https://api.forex.com"}`:             BrokerForexCom,
		`{"endpoint":"https://api.saxobank.com"}`:          BrokerSaxo,
		`{"endpoint":"https://api.tradier.com"}`:           BrokerTradier,
		`{"endpoint":"https://api.gemini.com"}`:            BrokerGemini,
		`{"endpoint":"https://api.bitstamp.net"}`:          BrokerBitstamp,
		`{"endpoint":"https://demo.tradovate.com"}`:        BrokerTradovate,
		`{"mode":"paper"}`:                                 BrokerPaperOnly,
		`{"webhook":"https://discord.com/api/webhooks/x"}`: BrokerWebhookOther,
		`{"endpoint":"https://unknown.com"}`:               BrokerUnknown,
		"":                                                 BrokerUnknown,
	}
	for in, want := range cases {
		if got := LinkedBrokerFromBody([]byte(in)); got != want {
			t.Fatalf("LinkedBrokerFromBody(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsLiveBroker(t *testing.T) {
	yes := []LinkedBroker{
		BrokerOANDA, BrokerFXCM, BrokerAlpaca, BrokerSaxo,
		BrokerTradovate, BrokerGemini,
	}
	no := []LinkedBroker{
		BrokerPaperOnly, BrokerWebhookOther, BrokerOther, BrokerUnknown,
	}
	for _, v := range yes {
		if !IsLiveBroker(v) {
			t.Fatalf("expected live: %q", v)
		}
	}
	for _, v := range no {
		if IsLiveBroker(v) {
			t.Fatalf("expected NOT live: %q", v)
		}
	}
}

func TestIsArgentineTicker(t *testing.T) {
	yes := []string{"GGAL", "YPFD", "AL30", "AL30D", "GD30", "LELIQ"}
	no := []string{"AAPL", "TSLA", "BTC", "", "FOO"}
	for _, v := range yes {
		if !IsArgentineTicker(v) {
			t.Fatalf("expected ARG ticker: %q", v)
		}
	}
	for _, v := range no {
		if IsArgentineTicker(v) {
			t.Fatalf("expected NOT ARG ticker: %q", v)
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
	if PeriodFromFilename("watchlist_202506.csv") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.csv") != "" {
		t.Fatal("non-period must be empty")
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotatePineStrategy(t *testing.T) {
	r := Row{
		ArtifactKind:         KindPineScript,
		ArgentineTickerCount: 3,
		FileMode:             0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasArgentinePineStrategy {
		t.Fatal("pine + ARG tickers must flag")
	}
}

func TestAnnotateWebhookExposure(t *testing.T) {
	r := Row{
		ArtifactKind:         KindWebhookConfig,
		HasWebhookWithSecret: true,
		ClienteCuitPrefix:    "27",
		ClienteCuitSuffix4:   "1114",
		FileMode:             0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + webhook secret + cliente = exposure")
	}
}

func TestAnnotateLiveBroker(t *testing.T) {
	r := Row{
		ArtifactKind: KindBrokerLink,
		LinkedBroker: BrokerOANDA,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasBrokerLinkedLive {
		t.Fatal("OANDA must flag live broker")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:         KindWebhookConfig,
		HasWebhookWithSecret: true,
		ClienteCuitPrefix:    "27",
		FileMode:             0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseTVPineScript --------------------------------------------

func TestParseTVPineScriptStrategy(t *testing.T) {
	body := []byte(`//@version=6
strategy("GGAL_momentum", overlay=true)
plot(close)
if (close > sma(close, 20))
    strategy.entry("long", strategy.long)
`)
	f := ParseTVPineScript(body)
	if !f.HasStrategyFn {
		t.Fatal("strategy() must flag")
	}
	if f.StrategyName != "GGAL_momentum" {
		t.Fatalf("name=%q", f.StrategyName)
	}
	if f.PineVersion != PineV6 {
		t.Fatalf("version=%q", f.PineVersion)
	}
	if _, ok := f.ArgentineTickers["GGAL"]; !ok {
		t.Fatalf("GGAL ticker missing: %+v", f.ArgentineTickers)
	}
}

func TestParseTVPineScriptIndicator(t *testing.T) {
	body := []byte(`//@version=5
indicator("MyRSI", overlay=false)
rsiVal = ta.rsi(close, 14)
plot(rsiVal)
`)
	f := ParseTVPineScript(body)
	if f.HasStrategyFn {
		t.Fatal("indicator must NOT flag strategy")
	}
	if f.StrategyName != "MyRSI" {
		t.Fatalf("name=%q", f.StrategyName)
	}
}

func TestParseTVPineScriptAPIKey(t *testing.T) {
	body := []byte(`//@version=6
//api_key = "abcdef1234567890ABCDEF"
strategy("X")
`)
	f := ParseTVPineScript(body)
	if f.APIKey == "" {
		t.Fatal("api key in pine comment must extract")
	}
}

// -- ParseTVWebhookConfig -----------------------------------------

func TestParseTVWebhookConfig(t *testing.T) {
	body := []byte(`{
  "alert_name": "GGAL_momentum_alert",
  "webhook_url": "https://api.example.com/webhook",
  "headers": {
    "Authorization": "Bearer aBcDeFgHiJkLmNoPqRsTuVwX"
  },
  "cliente_cuit": "27-11111111-4"
}`)
	f := ParseTVWebhookConfig(body)
	if f.WebhookURL == "" {
		t.Fatal("webhook url must extract")
	}
	if !f.HasWebhookSecret {
		t.Fatal("bearer must flag webhook secret")
	}
	if f.AlertCount < 1 {
		t.Fatalf("alert count=%d", f.AlertCount)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseTVWatchlist(t *testing.T) {
	body := []byte(`symbol,name
GGAL,Galicia
YPFD,YPF
AL30,Bonar 2030
AAPL,Apple
TSLA,Tesla
`)
	f := ParseTVWatchlist(body)
	if f.WatchlistTickers < 4 {
		t.Fatalf("watchlist=%d", f.WatchlistTickers)
	}
	if len(f.ArgentineTickers) < 3 {
		t.Fatalf("arg=%d want >=3", len(f.ArgentineTickers))
	}
}

func TestParseTVEmpty(t *testing.T) {
	f := ParseTVPineScript(nil)
	if f.HasStrategyFn || f.StrategyName != "" {
		t.Fatalf("empty must be zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "TradingView")
	must(t, os.MkdirAll(dir, 0o755))

	// Pine strategy with ARG tickers, world-readable.
	pinePath := filepath.Join(dir, "ggal_strategy.pine")
	must(t, os.WriteFile(pinePath, []byte(`//@version=6
strategy("GGAL_momentum", overlay=true)
// works on GGAL and YPFD
plot(close)
`), 0o644))

	// Webhook config with secret + cliente CUIT, readable.
	whPath := filepath.Join(dir, "webhook_GGAL.json")
	must(t, os.WriteFile(whPath, []byte(`{
  "alert_name": "GGAL_alert",
  "webhook_url": "https://api.example.com/webhook",
  "Authorization": "Bearer aBcDeFgHiJkLmNoPqRsTuVwX",
  "cliente_cuit": "27-11111111-4"
}`), 0o644))

	// Broker link to OANDA (live).
	blPath := filepath.Join(dir, "broker_link_oanda.json")
	must(t, os.WriteFile(blPath, []byte(`{
  "broker": "oanda",
  "endpoint": "https://api-fxpractice.oanda.com",
  "account": "999"
}`), 0o600))

	// Watchlist CSV.
	wlPath := filepath.Join(dir, "watchlist_001.csv")
	must(t, os.WriteFile(wlPath, []byte(`symbol,name
GGAL,Galicia
YPFD,YPF
AL30,Bonar 2030
AAPL,Apple
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "TradingView")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "strategy_skip.pine"),
		[]byte(`strategy("X")`), 0o644))

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
	if len(got) != 4 {
		t.Fatalf("want 4 (pine+wh+bl+wl), got %d: %+v", len(got), got)
	}

	var pine, wh, bl, wl Row
	for _, r := range got {
		switch r.FilePath {
		case pinePath:
			pine = r
		case whPath:
			wh = r
		case blPath:
			bl = r
		case wlPath:
			wl = r
		}
	}

	if pine.ArtifactKind != KindPineScript {
		t.Fatalf("pine kind=%q", pine.ArtifactKind)
	}
	if !pine.HasPineStrategy {
		t.Fatalf("pine must flag strategy: %+v", pine)
	}
	if !pine.HasArgentinePineStrategy {
		t.Fatalf("pine ARG strategy must flag: %+v", pine)
	}
	if pine.PineVersion != PineV6 {
		t.Fatalf("pine version=%q", pine.PineVersion)
	}

	if wh.ArtifactKind != KindWebhookConfig {
		t.Fatalf("wh kind=%q", wh.ArtifactKind)
	}
	if !wh.HasWebhookWithSecret {
		t.Fatalf("wh must flag secret: %+v", wh)
	}
	if !wh.HasAlertWithPII {
		t.Fatalf("wh must flag PII alert: %+v", wh)
	}
	if !wh.IsCredentialExposureRisk {
		t.Fatalf("readable + webhook secret + PII = exposure: %+v", wh)
	}

	if bl.ArtifactKind != KindBrokerLink {
		t.Fatalf("bl kind=%q", bl.ArtifactKind)
	}
	if bl.LinkedBroker != BrokerOANDA {
		t.Fatalf("bl broker=%q", bl.LinkedBroker)
	}
	if !bl.HasBrokerLinkedLive {
		t.Fatalf("OANDA must flag live: %+v", bl)
	}
	if bl.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", bl)
	}

	if wl.ArtifactKind != KindWatchlist {
		t.Fatalf("wl kind=%q", wl.ArtifactKind)
	}
	if wl.ArgentineTickerCount < 3 {
		t.Fatalf("wl ARG count=%d", wl.ArgentineTickerCount)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-tv")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "strategy.pine"),
		[]byte(`//@version=6
strategy("X")`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "TRADINGVIEW_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindPineScript {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-tv"},
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
		{FilePath: "z", ArtifactKind: KindPineScript},
		{FilePath: "a", ArtifactKind: KindWebhookConfig},
		{FilePath: "a", ArtifactKind: KindPineScript},
	}
	SortRows(in)
	// "tv-pine-script" sorts before "tv-webhook-config".
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindPineScript {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("abcdef")
	b := HashSecret("abcdef")
	c := HashSecret("ABCDEF")
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
