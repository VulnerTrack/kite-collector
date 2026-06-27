package winarghomebroker

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "homebroker-config"},
		{string(KindCredentials), "homebroker-credentials"},
		{string(KindWatchlist), "homebroker-watchlist"},
		{string(KindPositionsCache), "homebroker-positions-cache"},
		{string(KindOrdersCache), "homebroker-orders-cache"},
		{string(KindChartTemplate), "homebroker-chart-template"},
		{string(KindSignalRLog), "homebroker-signalr-log"},
		{string(KindSkin), "homebroker-skin"},
		{string(KindInstaller), "homebroker-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountRetail), "retail"},
		{string(AccountWealth), "wealth"},
		{string(AccountCorporate), "corporate"},
		{string(AccountAPIScraper), "api-scraper"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"homebroker_config.json",
		"hb_config.json",
		"hb-session.tok",
		"signalr.log",
		"watchlist.json",
		"positions.json",
		"decsis_skin.css",
		"adcap.chart",
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
		"homebroker_config.json":        KindConfig,
		"hb_config.json":                KindConfig,
		"homebroker_credentials.json":   KindCredentials,
		"hb_session.tok":                KindCredentials,
		"homebroker_watchlist.json":     KindWatchlist,
		"homebroker_positions.json":     KindPositionsCache,
		"homebroker_orders_202506.json": KindOrdersCache,
		"homebroker_signalr.log":        KindSignalRLog,
		"signalr.log":                   KindSignalRLog,
		"adcap.chart":                   KindChartTemplate,
		"adcap.skin":                    KindSkin,
		"decsis_skin.css":               KindSkin,
		"homebroker_setup.msi":          KindInstaller,
		"hb_setup.exe":                  KindInstaller,
		"":                              KindUnknown,
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
	if PeriodFromFilename("homebroker_orders_202506.json") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.json") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestDetectALYCBranding(t *testing.T) {
	cases := []struct {
		body, name, want string
	}{
		{`<config><broker>adcap</broker></config>`, "config.xml", "adcap"},
		{`{"branding":"bullmarket"}`, "config.json", "bullmarket"},
		{``, "tavelli.skin", "tavelli"},
		{`{"x":1}`, "random.json", ""},
		{``, "", ""},
	}
	for _, c := range cases {
		got := DetectALYCBranding([]byte(c.body), c.name)
		if got != c.want {
			t.Fatalf("DetectALYCBranding(%q,%q)=%q want %q",
				c.body, c.name, got, c.want)
		}
	}
}

func TestCancelRateBps(t *testing.T) {
	cases := []struct {
		o, c, f, want int64
	}{
		{0, 0, 0, 0},
		{10, 0, 90, 0},
		{10, 50, 40, 5000},
		{0, 75, 25, 7500},
		{100, 100, 0, 5000},
	}
	for _, c := range cases {
		got := CancelRateBps(c.o, c.c, c.f)
		if got != c.want {
			t.Fatalf("CancelRateBps(%d,%d,%d)=%d want %d",
				c.o, c.c, c.f, got, c.want)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindPositionsCache,
		KindOrdersCache, KindSignalRLog,
	}
	no := []ArtifactKind{
		KindWatchlist, KindChartTemplate, KindSkin,
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
		ArtifactKind:       KindCredentials,
		HasSignalRToken:    true,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + signalr + cliente = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:    KindCredentials,
		HasSignalRToken: true,
		FileMode:        0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateHighCancelRate(t *testing.T) {
	r := Row{
		ArtifactKind:  KindSignalRLog,
		CancelRateBps: 6000,
	}
	AnnotateSecurity(&r)
	if !r.HasHighCancelRate {
		t.Fatal("6000 bps must flag high cancel rate")
	}
}

func TestAnnotateBranding(t *testing.T) {
	r := Row{
		ArtifactKind: KindConfig,
		ALYCBranding: "adcap",
	}
	AnnotateSecurity(&r)
	if !r.HasALYCBranding {
		t.Fatal("branding must flag")
	}
}

func TestParseHBCredentialsJSON(t *testing.T) {
	body := []byte(`{
  "username": "alice@adcap.com.ar",
  "password": "secret123",
  "connection_token": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
  "cliente_cuit": "27-11111111-4",
  "broker": "adcap"
}`)
	f := ParseHBCredentials(body, "hb_credentials.json")
	if f.SignalRToken == "" {
		t.Fatal("signalr token must extract")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
	if f.ALYCBranding != "adcap" {
		t.Fatalf("branding=%q want adcap", f.ALYCBranding)
	}
}

func TestParseHBSignalRLog(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 hub.invoke SendOrder symbol=GGAL qty=100
2026-06-15 09:31:15 hub.invoke OrderFilled symbol=GGAL qty=100
2026-06-15 09:32:00 hub.invoke CancelOrder symbol=GGAL
2026-06-15 09:33:00 hub.invoke CancelOrder symbol=YPFD
2026-06-15 09:34:00 hub.invoke SendOrder symbol=YPFD qty=50
2026-06-15 09:35:00 hub.invoke CancelOrder symbol=YPFD
`)
	f := ParseHBSignalRLog(body, "signalr.log")
	if f.OrderEventCount < 2 {
		t.Fatalf("orders=%d", f.OrderEventCount)
	}
	if f.CancelEventCount < 3 {
		t.Fatalf("cancels=%d", f.CancelEventCount)
	}
	if f.FillEventCount < 1 {
		t.Fatalf("fills=%d", f.FillEventCount)
	}
	if f.SessionFirstSeen == "" || f.SessionLastSeen == "" {
		t.Fatalf("session=%+v", f)
	}
}

func TestParseHBWatchlist(t *testing.T) {
	body := []byte(`<watchlist>
<symbol>GGAL</symbol>
<symbol>YPFD</symbol>
<symbol>AL30</symbol>
</watchlist>`)
	f := ParseHBWatchlist(body, "watchlist.xml")
	if f.DistinctSymbols < 3 {
		t.Fatalf("distinct=%d", f.DistinctSymbols)
	}
}

func TestParseHBPositions(t *testing.T) {
	body := []byte(`{
"positions": [
{ "symbol": "GGAL", "lots": 100 },
{ "symbol": "YPFD", "lots": 50 }
],
"cliente_cuit": "27-11111111-4"
}`)
	f := ParseHBPositions(body, "positions.json")
	if f.DistinctSymbols < 2 {
		t.Fatalf("distinct=%d", f.DistinctSymbols)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseHBSkin(t *testing.T) {
	body := []byte(`/* HomeBroker skin */
.brand-logo { background-image: url("/static/maxinver-logo.png"); }
`)
	f := ParseHBSkin(body, "maxinver.skin")
	if f.ALYCBranding != "maxinver" {
		t.Fatalf("branding=%q want maxinver", f.ALYCBranding)
	}
}

func TestHasSignalRMarker(t *testing.T) {
	if !HasSignalRMarker([]byte(`hub.invoke("SendOrder")`)) {
		t.Fatal("hub.invoke must signal")
	}
	if HasSignalRMarker([]byte(`{"x":1}`)) {
		t.Fatal("random must not signal")
	}
}

func TestParseHBEmpty(t *testing.T) {
	f := ParseHBCredentials(nil, "")
	if f.SignalRToken != "" || f.HasPassword {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "HomeBroker")
	must(t, os.MkdirAll(filepath.Join(dir, "logs"), 0o755))

	cfgPath := filepath.Join(dir, "hb_config.json")
	must(t, os.WriteFile(cfgPath, []byte(`{
"username": "alice@adcap.com.ar",
"password": "secret123",
"connection_token": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
"broker": "adcap",
"cliente_cuit": "27-11111111-4"
}`), 0o644))

	sigPath := filepath.Join(dir, "logs", "signalr_202506.log")
	must(t, os.WriteFile(sigPath, []byte(`2026-06-15 09:30:01 hub.invoke SendOrder symbol=GGAL
2026-06-15 09:30:02 hub.invoke CancelOrder symbol=GGAL
2026-06-15 09:30:03 hub.invoke CancelOrder symbol=GGAL
2026-06-15 09:30:04 hub.invoke CancelOrder symbol=GGAL
`), 0o644))

	skinPath := filepath.Join(dir, "adcap.skin")
	must(t, os.WriteFile(skinPath, []byte(`/* adcap branding */
.brand { color: red; }`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "HomeBroker")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "hb_config.json"),
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
		t.Fatalf("want 3 (cfg+signalr+skin), got %d: %+v", len(got), got)
	}

	var cfg, sig, skin Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case sigPath:
			sig = r
		case skinPath:
			skin = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if !cfg.HasSignalRToken {
		t.Fatalf("cfg must flag signalr token: %+v", cfg)
	}
	if !cfg.HasALYCBranding || cfg.ALYCBranding != "adcap" {
		t.Fatalf("cfg branding=%q has=%t", cfg.ALYCBranding, cfg.HasALYCBranding)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cuit = exposure: %+v", cfg)
	}

	if sig.ArtifactKind != KindSignalRLog {
		t.Fatalf("sig kind=%q", sig.ArtifactKind)
	}
	if sig.CancelEventCount < 3 {
		t.Fatalf("sig cancels=%d", sig.CancelEventCount)
	}
	if !sig.HasHighCancelRate {
		t.Fatalf("3 cancels of 4 events must flag high cancel rate: bps=%d",
			sig.CancelRateBps)
	}

	if skin.ArtifactKind != KindSkin {
		t.Fatalf("skin kind=%q", skin.ArtifactKind)
	}
	if !skin.HasALYCBranding {
		t.Fatalf("skin must flag branding: %+v", skin)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-hb")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "hb_config.json"),
		[]byte(`{"connection_token":"abcdefghijklmnopqrst"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "HOMEBROKER_DIR" {
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
		installRoots: []string{"/nope-hb"},
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
		{FilePath: "a", ArtifactKind: KindSignalRLog},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v", in[0])
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
