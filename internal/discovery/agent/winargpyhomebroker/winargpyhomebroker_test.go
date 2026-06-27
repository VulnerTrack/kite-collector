package winargpyhomebroker

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "pyhomebroker-config"},
		{string(KindCredentials), "pyhomebroker-credentials"},
		{string(KindSession), "pyhomebroker-session"},
		{string(KindOrdersCache), "pyhomebroker-orders-cache"},
		{string(KindPortfolioCache), "pyhomebroker-portfolio-cache"},
		{string(KindMarketDataCache), "pyhomebroker-marketdata-cache"},
		{string(KindTradeLog), "pyhomebroker-trade-log"},
		{string(KindStrategyScript), "pyhomebroker-strategy-script"},
		{string(KindInstaller), "pyhomebroker-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(BrokerCohen), "cohen"},
		{string(BrokerBullMarket), "bullmarket"},
		{string(BrokerAllaria), "allaria"},
		{string(BrokerAdcap), "adcap"},
		{string(BrokerEcoValores), "eco-valores"},
		{string(BrokerIOLLegacy), "iol-legacy"},
		{string(BrokerProyecciones), "proyecciones"},
		{string(BrokerMercadoBursatil), "mercado-bursatil"},
		{string(BrokerSenseDigital), "sense-digital"},
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
		"pyhomebroker.ini",
		"phb_config.toml",
		"credentials.json",
		"cohen_user.session",
		"bullmarket.cookies",
		"orders_20260615.json",
		"portfolio_20260615.json",
		"marketdata_20260615.json",
		"market_data_snap.json",
		"trades_20260615.log",
		"strategy_pyhomebroker.py",
		"my_phb_algo.ipynb",
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
		"pyhomebroker.ini":           KindConfig,
		"phb_config.toml":            KindConfig,
		"credentials.json":           KindCredentials,
		"cohen_user.session":         KindSession,
		"bullmarket.cookies":         KindSession,
		"session_data.json":          KindSession,
		"orders_20260615.json":       KindOrdersCache,
		"orders_20260615.csv":        KindOrdersCache,
		"portfolio_20260615.json":    KindPortfolioCache,
		"marketdata_20260615.json":   KindMarketDataCache,
		"market_data_snap.json":      KindMarketDataCache,
		"trades_20260615.log":        KindTradeLog,
		"strategy_pyhomebroker.py":   KindStrategyScript,
		"my_phb_algo.ipynb":          KindStrategyScript,
		"pyhomebroker_installer.msi": KindInstaller,
		"":                           KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBrokerFromBody(t *testing.T) {
	cases := map[string]Broker{
		`{"endpoint":"https://www.cohen.com.ar/api"}`:           BrokerCohen,
		`{"endpoint":"https://www.bullmarketbrokers.com/"}`:     BrokerBullMarket,
		`{"endpoint":"https://allaria.com.ar/"}`:                BrokerAllaria,
		`{"endpoint":"https://adcap.com.ar/"}`:                  BrokerAdcap,
		`{"endpoint":"https://www.ecovalores.com.ar/"}`:         BrokerEcoValores,
		`{"endpoint":"https://api.invertironline.com/"}`:        BrokerIOLLegacy,
		`{"endpoint":"https://proyeccionesbursatiles.com.ar/"}`: BrokerProyecciones,
		`{"endpoint":"https://www.mercadobursatil.com.ar/"}`:    BrokerMercadoBursatil,
		`{"endpoint":"https://sensedigital.com.ar/"}`:           BrokerSenseDigital,
		`{"endpoint":"https://random.com.ar/"}`:                 BrokerUnknown,
		``:                                                      BrokerUnknown,
	}
	for in, want := range cases {
		if got := BrokerFromBody([]byte(in)); got != want {
			t.Fatalf("BrokerFromBody(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBrokerFromPath(t *testing.T) {
	cases := map[string]Broker{
		`C:\Users\alice\.pyhomebroker\sessions\cohen_user1.session`: BrokerCohen,
		`/home/alice/.pyhomebroker/bullmarket_user.session`:         BrokerBullMarket,
		`/home/alice/.pyhomebroker/allaria.cookies`:                 BrokerAllaria,
		`/home/alice/.pyhomebroker/adcap_orders.json`:               BrokerAdcap,
		`/home/alice/.pyhomebroker/eco-valores_portfolio.json`:      BrokerEcoValores,
		`/home/alice/.pyhomebroker/iol_orders.json`:                 BrokerIOLLegacy,
		`/home/alice/.pyhomebroker/proyecciones_orders.json`:        BrokerProyecciones,
		`/home/alice/.pyhomebroker/mercado_bursatil.session`:        BrokerMercadoBursatil,
		`/home/alice/.pyhomebroker/sense_digital_orders.json`:       BrokerSenseDigital,
		`/home/alice/.pyhomebroker/random.json`:                     BrokerUnknown,
		"":                                                          BrokerUnknown,
	}
	for in, want := range cases {
		if got := BrokerFromPath(in); got != want {
			t.Fatalf("BrokerFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"cliente 27-11111111-4", "27", "1114"},
		{"operador 20-12345678-9", "20", "6789"},
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
	if PeriodFromFilename("orders_202506.json") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.json") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{KindCredentials, KindSession, KindConfig}
	no := []ArtifactKind{
		KindOrdersCache, KindPortfolioCache, KindMarketDataCache,
		KindTradeLog, KindStrategyScript, KindInstaller,
		KindOther, KindUnknown,
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

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateCookieExposure(t *testing.T) {
	r := Row{
		ArtifactKind:       KindSession,
		Broker:             BrokerCohen,
		CookieCount:        5,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasCookieJar {
		t.Fatal("cookie count > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + cookies + cliente = exposure: %+v", r)
	}
}

func TestAnnotateCredsExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindCredentials,
		Broker:              BrokerBullMarket,
		HasUsernamePassword: true,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + creds = exposure: %+v", r)
	}
}

func TestAnnotateHighFrequencyPolling(t *testing.T) {
	r := Row{
		ArtifactKind:      KindOrdersCache,
		PollsPerMinuteMax: 120,
		FileMode:          0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsHighFrequencyPolling {
		t.Fatal("120 polls/min must flag HFP")
	}
}

func TestAnnotatePortfolioExport(t *testing.T) {
	r := Row{
		ArtifactKind:           KindPortfolioCache,
		PortfolioPositionCount: 10,
		FileMode:               0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasPortfolioExport {
		t.Fatal("position count > 0 must flag portfolio")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind: KindSession,
		CookieCount:  5,
		FileMode:     0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParsePHBConfig -----------------------------------------------

func TestParsePHBConfigINI(t *testing.T) {
	body := []byte(`[pyhomebroker]
broker = cohen
username = trader_alice
password = secret123
twofa_secret = JBSWY3DPEHPK3PXPJBSWY3DPEHPK
cliente_cuit = 27-11111111-4
`)
	f := ParsePHBConfig(body)
	if !f.HasUsername {
		t.Fatal("username must flag")
	}
	if f.Username != "trader_alice" {
		t.Fatalf("username=%q", f.Username)
	}
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if !f.Has2FA {
		t.Fatal("2fa must flag")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParsePHBConfigEmpty(t *testing.T) {
	f := ParsePHBConfig(nil)
	if f.HasUsername || f.HasPassword || f.Has2FA {
		t.Fatal("empty must not flag")
	}
}

// -- ParsePHBSession ----------------------------------------------

func TestParsePHBSession(t *testing.T) {
	body := []byte(`[
  {"name":"ASP.NET_SessionId","value":"AbCdEfGhIjKlMnOpQrStUvWxYz123456","domain":"cohen.com.ar"},
  {"name":"auth_token","value":"FzZyXwVuTsRqPoNmLkJiHgFeDcBa789012","domain":"cohen.com.ar"},
  {"name":"X-CSRF-Token","value":"012345abcdef67890123456789abcdef","domain":"cohen.com.ar"}
]`)
	f := ParsePHBSession(body)
	if !f.HasCookies {
		t.Fatal("cookies must flag")
	}
	if f.CookieCount < 3 {
		t.Fatalf("cookie count=%d want >=3", f.CookieCount)
	}
	if f.SessionCookieFingerprint == "" {
		t.Fatal("cookie fingerprint must populate")
	}
}

func TestParsePHBSessionEmpty(t *testing.T) {
	f := ParsePHBSession(nil)
	if f.HasCookies || f.CookieCount > 0 {
		t.Fatal("empty must not flag")
	}
}

// -- ParsePHBOrdersCache ------------------------------------------

func TestParsePHBOrdersCache(t *testing.T) {
	body := []byte(`2026-06-15 10:00:00 GET / poll order_id="A1" symbol="GGAL"
2026-06-15 10:00:00 GET / poll order_id="A2" symbol="YPFD"
2026-06-15 10:00:00 GET / poll order_id="A3" symbol="PAMP"
2026-06-15 10:01:00 GET / poll order_id="A4" symbol="AL30"
2026-06-15 10:01:00 GET / poll order_id="A5" symbol="GD30"
`)
	f := ParsePHBOrdersCache(body)
	if f.OrderCount < 5 {
		t.Fatalf("order count=%d want >=5", f.OrderCount)
	}
	if f.PollsPerMinMax != 3 {
		t.Fatalf("peak per minute=%d want 3", f.PollsPerMinMax)
	}
}

func TestParsePHBOrdersCacheHighFreq(t *testing.T) {
	var body []byte
	for i := 0; i < 120; i++ {
		body = append(body, []byte("2026-06-15 10:00:00 GET / poll order_id=\"X\" symbol=\"GGAL\"\n")...)
	}
	f := ParsePHBOrdersCache(body)
	if f.PollsPerMinMax != 120 {
		t.Fatalf("peak=%d want 120", f.PollsPerMinMax)
	}
}

// -- ParsePHBPortfolio --------------------------------------------

func TestParsePHBPortfolio(t *testing.T) {
	body := []byte(`{
  "positions": [
    {"symbol":"GGAL","valor_mercado":"5000000.00"},
    {"symbol":"YPFD","valor_mercado":"3000000.00"},
    {"symbol":"AL30","valor_mercado":"1000000.00"}
  ]
}`)
	f := ParsePHBPortfolio(body)
	if f.PortfolioCount < 1 {
		t.Fatalf("position count=%d", f.PortfolioCount)
	}
	if f.MaxPositionCents != 500_000_000 {
		t.Fatalf("max=%d want 500_000_000", f.MaxPositionCents)
	}
}

// -- ParsePHBMarketData -------------------------------------------

func TestParsePHBMarketData(t *testing.T) {
	body := []byte(`[
  {"symbol":"GGAL","last":1100},
  {"symbol":"YPFD","last":1200},
  {"symbol":"AL30","last":1300}
]`)
	f := ParsePHBMarketData(body)
	if f.InstrumentCount < 3 {
		t.Fatalf("instr=%d want >=3", f.InstrumentCount)
	}
}

// -- ParsePHBStrategy ---------------------------------------------

func TestParsePHBStrategy(t *testing.T) {
	body := []byte(`from pyhomebroker import HomeBroker
hb = HomeBroker("cohen")
hb.auth.login("user","pwd")
`)
	f := ParsePHBStrategy(body)
	if !f.HasStrategyImport {
		t.Fatal("from pyhomebroker import must flag")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", ".pyhomebroker")
	must(t, os.MkdirAll(filepath.Join(dir, "sessions"), 0o755))
	must(t, os.MkdirAll(filepath.Join(dir, "cache"), 0o755))

	// Credentials with username + password, world-readable.
	credsPath := filepath.Join(dir, "credentials.json")
	must(t, os.WriteFile(credsPath, []byte(`{
  "broker": "cohen",
  "username": "trader_alice",
  "password": "secret123",
  "cliente_cuit": "27-11111111-4"
}`), 0o644))

	// Session cookie jar for Cohen, world-readable.
	sessionPath := filepath.Join(dir, "sessions", "cohen_user.session")
	must(t, os.WriteFile(sessionPath, []byte(`[
  {"name":"ASP.NET_SessionId","value":"AbCdEfGhIjKlMnOpQrStUvWxYz123456","domain":"cohen.com.ar"},
  {"name":"auth_token","value":"FzZyXwVuTsRqPoNmLkJiHgFeDcBa789012","domain":"cohen.com.ar"}
]`), 0o644))

	// Orders cache with HFP signature.
	ordersPath := filepath.Join(dir, "cache", "orders_202506.json")
	var hfpBody []byte
	for i := 0; i < 120; i++ {
		hfpBody = append(hfpBody, []byte("2026-06-15 10:00:00 GET / poll order_id=\"X\" symbol=\"GGAL\"\n")...)
	}
	must(t, os.WriteFile(ordersPath, hfpBody, 0o600))

	// Strategy script.
	stratPath := filepath.Join(dir, "strategy_pyhomebroker.py")
	must(t, os.WriteFile(stratPath, []byte(`from pyhomebroker import HomeBroker
hb = HomeBroker("cohen")
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", ".pyhomebroker")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "credentials.json"),
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
	if len(got) != 4 {
		t.Fatalf("want 4 (creds+session+orders+strat), got %d: %+v", len(got), got)
	}

	var creds, session, orders, strat Row
	for _, r := range got {
		switch r.FilePath {
		case credsPath:
			creds = r
		case sessionPath:
			session = r
		case ordersPath:
			orders = r
		case stratPath:
			strat = r
		}
	}

	if creds.ArtifactKind != KindCredentials {
		t.Fatalf("creds kind=%q", creds.ArtifactKind)
	}
	if creds.Broker != BrokerCohen {
		t.Fatalf("creds broker=%q", creds.Broker)
	}
	if !creds.HasUsernamePassword {
		t.Fatalf("creds must flag user+pwd: %+v", creds)
	}
	if creds.UsernameHash == "" {
		t.Fatal("username hash must populate")
	}
	if !creds.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !creds.IsCredentialExposureRisk {
		t.Fatalf("readable + creds + cliente = exposure: %+v", creds)
	}

	if session.ArtifactKind != KindSession {
		t.Fatalf("session kind=%q", session.ArtifactKind)
	}
	if !session.HasCookieJar {
		t.Fatalf("session must flag cookies: %+v", session)
	}
	if session.CookieCount < 2 {
		t.Fatalf("cookie count=%d", session.CookieCount)
	}
	if session.SessionCookieHash == "" {
		t.Fatal("cookie hash must populate")
	}

	if orders.ArtifactKind != KindOrdersCache {
		t.Fatalf("orders kind=%q", orders.ArtifactKind)
	}
	if !orders.IsHighFrequencyPolling {
		t.Fatalf("120 polls/min must flag HFP: %+v", orders)
	}
	if orders.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", orders)
	}
	if orders.PeriodYYYYMM != "202506" {
		t.Fatalf("orders period=%q", orders.PeriodYYYYMM)
	}

	if strat.ArtifactKind != KindStrategyScript {
		t.Fatalf("strat kind=%q", strat.ArtifactKind)
	}
	if !strat.HasStrategyScript {
		t.Fatalf("strat must flag import: %+v", strat)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-phb")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "credentials.json"),
		[]byte(`{"broker":"cohen","username":"user1","password":"x"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "PYHOMEBROKER_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindCredentials {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-phb"},
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
		{FilePath: "z", ArtifactKind: KindCredentials},
		{FilePath: "a", ArtifactKind: KindSession},
		{FilePath: "a", ArtifactKind: KindCredentials},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindCredentials {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("user1")
	b := HashSecret("user1")
	c := HashSecret("USER1")
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
