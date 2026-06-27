package winargcocoscapital

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindCredentials), "cocos-credentials"},
		{string(KindPortfolioCache), "cocos-portfolio-cache"},
		{string(KindOrdersCache), "cocos-orders-cache"},
		{string(KindMarketDataCache), "cocos-marketdata-cache"},
		{string(KindFCISubscriptions), "cocos-fci-subscriptions"},
		{string(KindUSDTTradeLog), "cocos-usdt-trade-log"},
		{string(KindAccountExport), "cocos-account-export"},
		{string(KindStrategyScript), "cocos-strategy-script"},
		{string(KindTaxReport), "cocos-tax-report"},
		{string(KindConfig), "cocos-config"},
		{string(KindIndexedDB), "cocos-indexeddb"},
		{string(KindInstaller), "cocos-installer"},
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
		"cocos_credentials.json",
		"portfolio_20260615.json",
		"orders_20260615.json",
		"marketdata_20260615.json",
		"fci_subscriptions.json",
		"usdt_trades_20260615.json",
		"cocos_pay_log.json",
		"cocos_account_export.csv",
		"bienes_personales_2026.xlsx",
		"cocos_config.json",
		"strategy_cocos.py",
		"my_cocos_algo.ipynb",
		"cocos_indexeddb.sqlite",
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
		"credentials.json":            KindCredentials,
		"cocos_credentials.json":      KindCredentials,
		"portfolio_20260615.json":     KindPortfolioCache,
		"orders_20260615.json":        KindOrdersCache,
		"marketdata_20260615.json":    KindMarketDataCache,
		"market_data_snap.json":       KindMarketDataCache,
		"fci_subscriptions.json":      KindFCISubscriptions,
		"usdt_trades_20260615.json":   KindUSDTTradeLog,
		"cocos_pay_log.json":          KindUSDTTradeLog,
		"cocos_account_export.csv":    KindAccountExport,
		"bienes_personales_2026.xlsx": KindTaxReport,
		"cocos_config.xml":            KindConfig,
		"strategy_cocos.py":           KindStrategyScript,
		"my_cocos_algo.ipynb":         KindStrategyScript,
		"cocos_indexeddb.sqlite":      KindIndexedDB,
		"cocos_v8_installer.msi":      KindInstaller,
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
		`{"url":"https://api.cocos.capital"}`:     EnvProduction,
		`{"url":"https://sandbox.cocos.capital"}`: EnvSandbox,
		`{"env":"demo"}`:                          EnvSandbox,
		`{"url":"https://random.com"}`:            EnvUnknown,
		"":                                        EnvUnknown,
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

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("orders_202506.json") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.json") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{KindCredentials, KindConfig, KindIndexedDB}
	no := []ArtifactKind{
		KindPortfolioCache, KindOrdersCache, KindMarketDataCache,
		KindFCISubscriptions, KindUSDTTradeLog, KindAccountExport,
		KindStrategyScript, KindTaxReport,
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

func TestHasMEPCCLPattern(t *testing.T) {
	yes := [][]byte{
		[]byte(`{"symbol":"AL30"} {"symbol":"AL30D"}`),
		[]byte(`GD30 buy + GD30C sell`),
	}
	no := [][]byte{
		[]byte(`{"symbol":"AL30"}`),
		[]byte(`{"symbol":"AL30D"}`),
		[]byte(``),
	}
	for _, v := range yes {
		if !HasMEPCCLPattern(v) {
			t.Fatalf("expected MEP/CCL: %q", v)
		}
	}
	for _, v := range no {
		if HasMEPCCLPattern(v) {
			t.Fatalf("expected NOT MEP/CCL: %q", v)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateBearerExposure(t *testing.T) {
	r := Row{
		ArtifactKind:       KindCredentials,
		HasBearerToken:     true,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
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

func TestAnnotateUSDTHigh(t *testing.T) {
	r := Row{
		ArtifactKind:       KindUSDTTradeLog,
		USDTVolumeARSCents: 2_000_000_000, // 20 M ARS
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasUSDTActivity {
		t.Fatal("USDT volume must flag activity")
	}
	if !r.HasHighVolumeUSDT {
		t.Fatal("20 M ARS USDT must flag high volume")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:    KindCredentials,
		HasBearerToken:  true,
		HasRefreshToken: true,
		FileMode:        0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseCocosCredentials ----------------------------------------

func TestParseCocosCredentials(t *testing.T) {
	body := []byte(`{
  "endpoint": "https://api.cocos.capital",
  "access_token": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
  "refresh_token": "rt-abcdefghijklmnopqrstuvwxyz",
  "username": "alice@cocos.capital",
  "password": "secret123",
  "totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK",
  "cliente_cuit": "27-11111111-4"
}`)
	f := ParseCocosCredentials(body)
	if f.BearerToken == "" {
		t.Fatal("bearer must extract")
	}
	if f.RefreshToken == "" {
		t.Fatal("refresh must extract")
	}
	if f.Username == "" {
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

// -- ParseCocosOrdersCache ----------------------------------------

func TestParseCocosOrdersCacheMEPCCL(t *testing.T) {
	body := []byte(`2026-06-15 10:00:00 GET / poll "symbol":"AL30"
2026-06-15 10:00:00 GET / poll "symbol":"AL30D"
2026-06-15 10:00:00 GET / poll "symbol":"GGAL"
2026-06-15 10:01:00 GET / poll "symbol":"YPFD"
`)
	f := ParseCocosOrdersCache(body)
	if f.OrderCount < 4 {
		t.Fatalf("orders=%d want >=4", f.OrderCount)
	}
	if !f.HasMEPCCLArbitrage {
		t.Fatalf("AL30 + AL30D must flag MEP/CCL: %+v", f)
	}
	if f.PollsPerMinMax < 3 {
		t.Fatalf("peak=%d", f.PollsPerMinMax)
	}
}

// -- ParseCocosUSDTLog --------------------------------------------

func TestParseCocosUSDTLog(t *testing.T) {
	body := []byte(`2026-06-15 10:00:00 USDT_amount=5000000.00 BUY
2026-06-15 10:05:00 USDT_amount=3000000.00 SELL
2026-06-15 10:10:00 USDT_amount=2000000.00 BUY
`)
	f := ParseCocosUSDTLog(body)
	if f.USDTVolumeCents != 1_000_000_000 {
		t.Fatalf("usdt vol=%d want 1_000_000_000", f.USDTVolumeCents)
	}
}

// -- ParseCocosFCISubscriptions -----------------------------------

func TestParseCocosFCISubscriptions(t *testing.T) {
	body := []byte(`[
  {"fci_id":"COCOS_RV_AR","fci_name":"Cocos RV Argentina"},
  {"fci_id":"COCOS_RF_AR","fci_name":"Cocos RF Argentina"},
  {"fci_id":"COCOS_DLR","fci_name":"Cocos Dolar"}
]`)
	f := ParseCocosFCISubscriptions(body)
	if f.FCISubscriptionCount < 3 {
		t.Fatalf("fci count=%d want >=3", f.FCISubscriptionCount)
	}
}

// -- ParseCocosStrategy -------------------------------------------

func TestParseCocosStrategy(t *testing.T) {
	body := []byte(`from cocos_api import CocosClient
client = CocosClient(username="alice", password="secret123")
`)
	f := ParseCocosStrategy(body)
	if !f.HasStrategyImport {
		t.Fatal("cocos_api import must flag")
	}
	if !f.HasPassword {
		t.Fatal("hardcoded password must flag")
	}
}

func TestParseCocosEmpty(t *testing.T) {
	f := ParseCocosCredentials(nil)
	if f.BearerToken != "" || f.RefreshToken != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", ".cocos")
	must(t, os.MkdirAll(filepath.Join(dir, "cache"), 0o755))

	// Credentials.json with bearer + refresh + 2FA, readable.
	credsPath := filepath.Join(dir, "credentials.json")
	must(t, os.WriteFile(credsPath, []byte(`{
  "endpoint": "https://api.cocos.capital",
  "access_token": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
  "refresh_token": "rt-abcdefghijklmnopqrstuvwxyz",
  "username": "alice@cocos.capital",
  "totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK",
  "cliente_cuit": "27-11111111-4"
}`), 0o644))

	// USDT trade log with high volume.
	usdtPath := filepath.Join(dir, "cache", "usdt_trades_202506.json")
	must(t, os.WriteFile(usdtPath, []byte(`2026-06-15 10:00:00 USDT_amount=8000000.00 BUY
2026-06-15 10:05:00 USDT_amount=5000000.00 SELL
2026-06-15 10:10:00 USDT_amount=3000000.00 BUY
`), 0o644))

	// Orders cache with MEP/CCL pattern + HFP.
	ordersPath := filepath.Join(dir, "cache", "orders_202506.json")
	var hfpBody []byte
	for i := 0; i < 120; i++ {
		hfpBody = append(hfpBody, []byte("2026-06-15 10:00:00 GET / poll \"symbol\":\"AL30\"\n")...)
	}
	hfpBody = append(hfpBody, []byte("2026-06-15 10:01:00 GET / poll \"symbol\":\"AL30D\"\n")...)
	must(t, os.WriteFile(ordersPath, hfpBody, 0o600))

	// FCI subscriptions.
	fciPath := filepath.Join(dir, "cache", "fci_subscriptions.json")
	must(t, os.WriteFile(fciPath, []byte(`[
  {"fci_id":"COCOS_RV_AR"},
  {"fci_id":"COCOS_RF_AR"}
]`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", ".cocos")
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
		t.Fatalf("want 4 (creds+usdt+orders+fci), got %d: %+v", len(got), got)
	}

	var creds, usdt, orders, fci Row
	for _, r := range got {
		switch r.FilePath {
		case credsPath:
			creds = r
		case usdtPath:
			usdt = r
		case ordersPath:
			orders = r
		case fciPath:
			fci = r
		}
	}

	if creds.ArtifactKind != KindCredentials {
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
	if !creds.IsCredentialExposureRisk {
		t.Fatalf("readable + bearer + cliente = exposure: %+v", creds)
	}

	if usdt.ArtifactKind != KindUSDTTradeLog {
		t.Fatalf("usdt kind=%q", usdt.ArtifactKind)
	}
	if !usdt.HasHighVolumeUSDT {
		t.Fatalf("16 M ARS USDT must flag high vol: %+v", usdt)
	}
	if !usdt.HasUSDTActivity {
		t.Fatalf("must flag USDT activity: %+v", usdt)
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

	if fci.ArtifactKind != KindFCISubscriptions {
		t.Fatalf("fci kind=%q", fci.ArtifactKind)
	}
	if fci.FCISubscriptionCount < 2 {
		t.Fatalf("fci subs=%d", fci.FCISubscriptionCount)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-cocos")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "credentials.json"),
		[]byte(`{"endpoint":"https://api.cocos.capital","access_token":"abcdefghijklmnopqrst"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "COCOS_DIR" {
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
		installRoots: []string{"/nope-cocos"},
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
		{FilePath: "a", ArtifactKind: KindOrdersCache},
		{FilePath: "a", ArtifactKind: KindCredentials},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindCredentials {
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
