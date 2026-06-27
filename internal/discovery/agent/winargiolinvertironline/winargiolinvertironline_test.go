package winargiolinvertironline

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindCredentialsJSON), "iol-credentials-json"},
		{string(KindPortfolioCache), "iol-portfolio-cache"},
		{string(KindOrdersCache), "iol-orders-cache"},
		{string(KindMarketDataCache), "iol-marketdata-cache"},
		{string(KindAccountExport), "iol-account-export"},
		{string(KindStrategyScript), "iol-strategy-script"},
		{string(KindTaxReport), "iol-tax-report"},
		{string(KindConfig), "iol-config"},
		{string(KindInstaller), "iol-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(EnvProduction), "production"},
		{string(EnvSandbox), "sandbox"},
		{string(EnvOther), "other"},
		{string(EnvUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"credentials.json",
		"iol_credentials.json",
		"portfolio_20260615.json",
		"orders_20260615.json",
		"marketdata_20260615.json",
		"iol_account_export.csv",
		"bienes_personales_2026.xlsx",
		"iol_config.xml",
		"strategy_pyiol.py",
		"my_iol_algo.ipynb",
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
		"credentials.json":            KindCredentialsJSON,
		"iol_credentials.json":        KindCredentialsJSON,
		"portfolio_20260615.json":     KindPortfolioCache,
		"orders_20260615.json":        KindOrdersCache,
		"marketdata_20260615.json":    KindMarketDataCache,
		"market_data_snap.json":       KindMarketDataCache,
		"iol_account_export.csv":      KindAccountExport,
		"bienes_personales_2026.xlsx": KindTaxReport,
		"iol_config.xml":              KindConfig,
		"strategy_pyiol.py":           KindStrategyScript,
		"my_iol_algo.ipynb":           KindStrategyScript,
		"iol_v8_installer.msi":        KindInstaller,
		"":                            KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEnvironmentFromBody(t *testing.T) {
	cases := map[string]Environment{
		`{"url":"https://api.invertironline.com"}`:  EnvProduction,
		`{"url":"https://demo.invertironline.com"}`: EnvSandbox,
		`{"env":"demo"}`:               EnvSandbox,
		`{"url":"https://random.com"}`: EnvUnknown,
		"":                             EnvUnknown,
	}
	for in, want := range cases {
		if got := EnvironmentFromBody([]byte(in)); got != want {
			t.Fatalf("EnvironmentFromBody(%q)=%q want %q", in, got, want)
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

func TestAccountSuffix4(t *testing.T) {
	cases := map[string]string{
		"cuenta=12345":          "2345",
		"comitente=7777":        "7777",
		"cuenta_comitente:9999": "9999",
		"no cuenta":             "",
	}
	for in, want := range cases {
		if got := AccountSuffix4(in); got != want {
			t.Fatalf("AccountSuffix4(%q)=%q want %q", in, got, want)
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
	yes := []ArtifactKind{KindCredentialsJSON, KindConfig}
	no := []ArtifactKind{
		KindPortfolioCache, KindOrdersCache, KindMarketDataCache,
		KindAccountExport, KindStrategyScript, KindTaxReport,
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

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateBearerExposure(t *testing.T) {
	r := Row{
		ArtifactKind:       KindCredentialsJSON,
		HasBearerToken:     true,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + bearer + cliente = exposure")
	}
}

func TestAnnotateHFP(t *testing.T) {
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

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:    KindCredentialsJSON,
		HasBearerToken:  true,
		HasRefreshToken: true,
		FileMode:        0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseIOLCredentials ------------------------------------------

func TestParseIOLCredentials(t *testing.T) {
	body := []byte(`{
  "endpoint": "https://api.invertironline.com",
  "access_token": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
  "refresh_token": "rt-abcdefghijklmnopqrstuvwxyz",
  "username": "trader_alice",
  "password": "secret123",
  "totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK",
  "cuenta_comitente": "1234567",
  "cliente_cuit": "27-11111111-4"
}`)
	f := ParseIOLCredentials(body)
	if f.BearerToken == "" {
		t.Fatal("bearer must extract")
	}
	if f.RefreshToken == "" {
		t.Fatal("refresh must extract")
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
	if f.AccountID != "1234567" {
		t.Fatalf("account=%q", f.AccountID)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

// -- ParseIOLOrdersCache ------------------------------------------

func TestParseIOLOrdersCache(t *testing.T) {
	body := []byte(`2026-06-15 10:00:00 GET / poll "order_id":"A1" "simbolo":"GGAL"
2026-06-15 10:00:00 GET / poll "order_id":"A2" "simbolo":"YPFD"
2026-06-15 10:00:00 GET / poll "order_id":"A3" "simbolo":"AL30"
2026-06-15 10:00:00 GET / poll "order_id":"A4" "simbolo":"AL30D"
2026-06-15 10:01:00 GET / poll "order_id":"A5" "simbolo":"PAMP"
`)
	f := ParseIOLOrdersCache(body)
	if f.OrderCount < 4 {
		t.Fatalf("orders=%d", f.OrderCount)
	}
	if f.PollsPerMinMax != 4 {
		t.Fatalf("peak=%d want 4", f.PollsPerMinMax)
	}
	if !f.HasMEPCCLArbitrage {
		t.Fatalf("AL30 + AL30D must flag MEP/CCL: %+v", f)
	}
}

func TestParseIOLOrdersCacheHFT(t *testing.T) {
	var body []byte
	for i := 0; i < 120; i++ {
		body = append(body, []byte("2026-06-15 10:00:00 GET / poll \"order_id\":\"X\"\n")...)
	}
	f := ParseIOLOrdersCache(body)
	if f.PollsPerMinMax != 120 {
		t.Fatalf("peak=%d want 120", f.PollsPerMinMax)
	}
}

// -- ParseIOLPortfolio --------------------------------------------

func TestParseIOLPortfolio(t *testing.T) {
	body := []byte(`{
  "positions": [
    {"simbolo":"GGAL","valor_mercado":"5000000.00"},
    {"simbolo":"AL30","valor_mercado":"3000000.00"},
    {"simbolo":"AL30D","valor_mercado":"1000000.00"}
  ],
  "cliente_cuit": "27-11111111-4"
}`)
	f := ParseIOLPortfolio(body)
	if f.PortfolioCount < 1 {
		t.Fatalf("positions=%d", f.PortfolioCount)
	}
	if f.MaxPositionCents != 500_000_000 {
		t.Fatalf("max=%d want 500_000_000", f.MaxPositionCents)
	}
	if !f.HasMEPCCLArbitrage {
		t.Fatalf("AL30+AL30D must flag MEP/CCL: %+v", f)
	}
}

// -- ParseIOLStrategy ---------------------------------------------

func TestParseIOLStrategy(t *testing.T) {
	body := []byte(`from pyiol import IOLClient
client = IOLClient(username="alice", password="secret123")
`)
	f := ParseIOLStrategy(body)
	if !f.HasStrategyImport {
		t.Fatal("pyiol import must flag")
	}
	if !f.HasPassword {
		t.Fatal("hardcoded password must flag")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", ".iol")
	must(t, os.MkdirAll(filepath.Join(dir, "cache"), 0o755))

	// Credentials.json with bearer + refresh + 2FA, readable.
	credsPath := filepath.Join(dir, "credentials.json")
	must(t, os.WriteFile(credsPath, []byte(`{
  "endpoint": "https://api.invertironline.com",
  "access_token": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
  "refresh_token": "rt-abcdefghijklmnopqrstuvwxyz",
  "username": "trader_alice",
  "totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK",
  "cliente_cuit": "27-11111111-4"
}`), 0o644))

	// Orders cache with HFP + MEP/CCL pattern.
	ordersPath := filepath.Join(dir, "cache", "orders_202506.json")
	var hfpBody []byte
	for i := 0; i < 120; i++ {
		hfpBody = append(hfpBody, []byte("2026-06-15 10:00:00 GET / poll \"order_id\":\"X\" \"simbolo\":\"AL30\"\n")...)
	}
	hfpBody = append(hfpBody, []byte("2026-06-15 10:01:00 GET / poll \"order_id\":\"Y\" \"simbolo\":\"AL30D\"\n")...)
	must(t, os.WriteFile(ordersPath, hfpBody, 0o600))

	// Portfolio snapshot, readable.
	portfolioPath := filepath.Join(dir, "cache", "portfolio_202506.json")
	must(t, os.WriteFile(portfolioPath, []byte(`{
  "positions": [
    {"simbolo":"GGAL","valor_mercado":"5000000.00"}
  ]
}`), 0o644))

	// Strategy script.
	stratPath := filepath.Join(dir, "strategy_pyiol.py")
	must(t, os.WriteFile(stratPath, []byte(`from pyiol import IOLClient
client = IOLClient()
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", ".iol")
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
		t.Fatalf("want 4 (creds+orders+portfolio+strat), got %d: %+v", len(got), got)
	}

	var creds, orders, portfolio, strat Row
	for _, r := range got {
		switch r.FilePath {
		case credsPath:
			creds = r
		case ordersPath:
			orders = r
		case portfolioPath:
			portfolio = r
		case stratPath:
			strat = r
		}
	}

	if creds.ArtifactKind != KindCredentialsJSON {
		t.Fatalf("creds kind=%q", creds.ArtifactKind)
	}
	if !creds.HasBearerToken {
		t.Fatalf("creds must flag bearer: %+v", creds)
	}
	if !creds.HasRefreshToken {
		t.Fatalf("creds must flag refresh: %+v", creds)
	}
	if !creds.Has2FAToken {
		t.Fatalf("creds must flag 2fa: %+v", creds)
	}
	if creds.Environment != EnvProduction {
		t.Fatalf("creds env=%q", creds.Environment)
	}
	if creds.BearerTokenHash == "" {
		t.Fatal("bearer hash must populate")
	}
	if !creds.IsCredentialExposureRisk {
		t.Fatalf("readable + bearer + cliente = exposure: %+v", creds)
	}

	if orders.ArtifactKind != KindOrdersCache {
		t.Fatalf("orders kind=%q", orders.ArtifactKind)
	}
	if !orders.IsHighFrequencyPolling {
		t.Fatalf("orders 120 polls/min must flag: %+v", orders)
	}
	if !orders.HasMEPCCLArbitrage {
		t.Fatalf("orders AL30+AL30D must flag MEP/CCL: %+v", orders)
	}
	if orders.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", orders)
	}

	if portfolio.ArtifactKind != KindPortfolioCache {
		t.Fatalf("portfolio kind=%q", portfolio.ArtifactKind)
	}
	if portfolio.MaxPositionARSCents != 500_000_000 {
		t.Fatalf("portfolio max=%d", portfolio.MaxPositionARSCents)
	}

	if strat.ArtifactKind != KindStrategyScript {
		t.Fatalf("strat kind=%q", strat.ArtifactKind)
	}
	if !strat.HasStrategyScript {
		t.Fatalf("strat must flag pyiol import: %+v", strat)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-iol")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "credentials.json"),
		[]byte(`{"endpoint":"https://api.invertironline.com","access_token":"abcdefghijklmnopqrst"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "IOL_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindCredentialsJSON {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-iol"},
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
		{FilePath: "z", ArtifactKind: KindCredentialsJSON},
		{FilePath: "a", ArtifactKind: KindOrdersCache},
		{FilePath: "a", ArtifactKind: KindCredentialsJSON},
	}
	SortRows(in)
	// "iol-credentials-json" sorts before "iol-orders-cache".
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindCredentialsJSON {
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
