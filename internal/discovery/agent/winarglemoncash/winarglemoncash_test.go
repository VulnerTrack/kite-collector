package winarglemoncash

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedClock() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// -- enum strings pinned to host_arg_lemoncash CHECK constraints --

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "lemon-config"},
		{string(KindCredentials), "lemon-credentials"},
		{string(KindSDKScript), "lemon-sdk-script"},
		{string(KindTradeLog), "lemon-trade-log"},
		{string(KindEarnPositions), "lemon-earn-positions"},
		{string(KindKYCDump), "lemon-kyc-dump"},
		{string(KindCardTransactions), "lemon-card-transactions"},
		{string(KindArbitrageScript), "lemon-arbitrage-script"},
		{string(KindMarketplaceConfig), "lemon-marketplace-config"},
		{string(KindWebhookConfig), "lemon-webhook-config"},
		{string(KindInstaller), "lemon-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountConsumer), "consumer"},
		{string(AccountMerchant), "merchant"},
		{string(AccountDeveloper), "developer"},
		{string(AccountComplianceOfficer), "compliance-officer"},
		{string(AccountAPI), "api"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(ProductCryptoWallet), "crypto-wallet"},
		{string(ProductCryptoCard), "crypto-card"},
		{string(ProductStablecoinRails), "stablecoin-rails"},
		{string(ProductYieldEarn), "yield-earn"},
		{string(ProductMarketplace), "marketplace"},
		{string(ProductMultiProduct), "multi-product"},
		{string(ProductOther), "other"},
		{string(ProductUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHighBalanceConst(t *testing.T) {
	if HighBalanceUSDCents != 1_000_000 {
		t.Fatalf("HighBalanceUSDCents=%d", HighBalanceUSDCents)
	}
}

func TestHashers(t *testing.T) {
	if len(HashContents([]byte("x"))) != 64 {
		t.Fatal("HashContents must be 64-hex")
	}
	// HashSecret normalizes (lowercase+trim) and returns "" for empties.
	if HashSecret("") != "" || HashSecret("   ") != "" {
		t.Fatal("empty/blank secret must hash to empty string")
	}
	if HashSecret(" ABC ") != HashSecret("abc") {
		t.Fatal("HashSecret must normalize case + whitespace")
	}
	if HashSecret("token") == "token" {
		t.Fatal("must never return raw secret")
	}
}

func TestDefaultPathSets(t *testing.T) {
	if len(DefaultInstallRoots()) == 0 || len(UserLemonDirs()) == 0 {
		t.Fatal("path sets empty")
	}
	if len(DefaultUsersBases()) != 3 {
		t.Fatalf("users bases=%d", len(DefaultUsersBases()))
	}
}

func TestIsCandidateExt(t *testing.T) {
	yes := []string{
		".env", "config.env", "x.json", "x.ini", "x.cfg",
		"x.conf", "x.yaml", "x.yml", "x.csv", "x.tsv", "x.log", "x.txt",
		"x.py", "x.ipynb", "x.js", "x.ts", "x.msi", "x.exe", "x.pkg", "x.dmg",
	}
	no := []string{"x.md", "x.png", "x"}
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

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		".env", "app.env", "lemon.json", "lemoncash.cfg",
		"earn_positions.csv", "kyc_dump.json", "crypto_card.csv",
		"lemon_card.log", "arbitrage.py", "stablecoin.py",
		"usdt_ars.py", "credentials.json",
	}
	no := []string{"", "random.json", "notes.txt", "invoice.csv"}
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
		"":                        KindUnknown,
		"lemon_setup.exe":         KindInstaller,
		"lemon_installer.dmg":     KindInstaller,
		"randomsetup.pkg":         KindOther,
		".env":                    KindCredentials,
		"credentials.json":        KindCredentials,
		"token.json":              KindCredentials,
		"tokens.json":             KindCredentials,
		"api_token.yaml":          KindCredentials,
		"kyc_dump.json":           KindKYCDump,
		"crypto_card.csv":         KindCardTransactions,
		"lemon_card.json":         KindCardTransactions,
		"card_transactions.csv":   KindCardTransactions,
		"earn_positions.csv":      KindEarnPositions,
		"yield_positions.json":    KindEarnPositions,
		"usdt_ars_arb.py":         KindArbitrageScript,
		"arbitrage.ipynb":         KindArbitrageScript,
		"usdt_ars_snapshot.csv":   KindOther, // arbitrage token but non-script ext
		"trade_log.csv":           KindTradeLog,
		"wallet_log.csv":          KindTradeLog,
		"marketplace_config.json": KindMarketplaceConfig,
		"webhook_config.yaml":     KindWebhookConfig,
		"lemon_sdk.py":            KindSDKScript,
		"lemon.json":              KindConfig,
		"lemon.txt":               KindOther, // lemon token but non-config ext
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	p, s := CuitFingerprint("cuit 30-11223344-5 x")
	if p != "30" || s != "3445" {
		t.Fatalf("fingerprint=(%q,%q) want (30,3445)", p, s)
	}
	if p, _ := CuitFingerprint("11-22334455-6"); p != "" {
		t.Fatal("invalid prefix 11 must be rejected")
	}
	if len(CuitEntityPrefixes()) != 7 || !IsValidCuitEntityPrefix("34") {
		t.Fatal("cuit prefix set")
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if got := PeriodFromFilename("trade_log_202601.csv"); got != "202601" {
		t.Fatalf("period=%q", got)
	}
	if got := PeriodFromFilename("trade_log.csv"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindSDKScript,
		KindTradeLog, KindEarnPositions, KindKYCDump, KindCardTransactions,
		KindArbitrageScript, KindMarketplaceConfig, KindWebhookConfig,
	}
	no := []ArtifactKind{KindInstaller, KindOther, KindUnknown}
	for _, k := range yes {
		if !IsCredentialKind(k) {
			t.Fatalf("expected credential kind: %q", k)
		}
	}
	for _, k := range no {
		if IsCredentialKind(k) {
			t.Fatalf("expected NOT credential kind: %q", k)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateSecurityExposure(t *testing.T) {
	r := Row{
		FileMode:              0o644,
		ArtifactKind:          KindKYCDump,
		ClienteCuitPrefix:     "20",
		ClienteDNIHash:        "sha256hash",
		PIISignalCount:        2,
		CryptoBalanceUSDCents: HighBalanceUSDCents,
		TradeRecordCount:      3,
		EarnPositionCount:     1,
		CardTxCount:           2,
	}
	AnnotateSecurity(&r)
	if !r.IsWorldReadable || !r.IsGroupReadable {
		t.Fatal("0o644 should be world+group readable")
	}
	if !r.HasClienteCuit || !r.HasClienteDNI || !r.HasKYCDump {
		t.Fatalf("cuit/dni/kyc flags: %+v", r)
	}
	if !r.HasTradeLog || !r.HasEarnPositions || !r.HasCardTransactions {
		t.Fatalf("trade/earn/card flags: %+v", r)
	}
	if !r.HasHighBalance || !r.HasPIIBundle {
		t.Fatalf("balance/pii flags: %+v", r)
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + credSignal + credential kind = exposure: %+v", r)
	}
}

func TestAnnotateSecurityArbitrageAndWebhook(t *testing.T) {
	r := Row{FileMode: 0o644, ArtifactKind: KindArbitrageScript}
	AnnotateSecurity(&r)
	if !r.HasUSDTARSArbitrage {
		t.Fatal("arbitrage script must flag USDT/ARS arbitrage")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable arbitrage script = exposure")
	}
	w := Row{FileMode: 0o644, ArtifactKind: KindWebhookConfig}
	AnnotateSecurity(&w)
	if !w.HasMarketplaceWebhook {
		t.Fatal("webhook config must flag marketplace webhook")
	}
	m := Row{FileMode: 0o644, ArtifactKind: KindMarketplaceConfig}
	AnnotateSecurity(&m)
	if !m.HasMarketplaceWebhook {
		t.Fatal("marketplace config must flag marketplace webhook")
	}
}

func TestAnnotateSecurityLockedDown(t *testing.T) {
	r := Row{FileMode: 0o600, ArtifactKind: KindKYCDump, ClienteCuitPrefix: "20"}
	AnnotateSecurity(&r)
	if r.IsWorldReadable || r.IsGroupReadable {
		t.Fatal("0o600 not readable")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateSecurityHighBalanceBoundary(t *testing.T) {
	below := Row{CryptoBalanceUSDCents: HighBalanceUSDCents - 1}
	AnnotateSecurity(&below)
	if below.HasHighBalance {
		t.Fatal("below threshold must NOT flag high balance")
	}
	at := Row{CryptoBalanceUSDCents: HighBalanceUSDCents}
	AnnotateSecurity(&at)
	if !at.HasHighBalance {
		t.Fatal("at threshold must flag high balance")
	}
	// PII bundle needs >= 2 signals.
	one := Row{PIISignalCount: 1}
	AnnotateSecurity(&one)
	if one.HasPIIBundle {
		t.Fatal("1 signal must NOT flag pii bundle")
	}
}

// -- parser -------------------------------------------------------

func TestParseLemonConfigFull(t *testing.T) {
	body := []byte(strings.Join([]string{
		"password = hunter2secretpw",
		"access_token = ACCESSTOKENabcdefghijklmnop012345",
		"refresh_token = REFRESHTOKENabcdefghijklmnop012345",
		"webhook_secret = WEBHOOKSECRET1234567890",
		"client_id = lemonclient123456",
		"user_id = lemonuser12",
		"username = alice@example.com",
		"cliente_cuit: 27-11112222-3",
		"dni: 12345678",
		"name: Alicia",
	}, "\n"))
	f := ParseLemonConfig(body)
	if !f.HasPassword {
		t.Fatal("password must be detected")
	}
	if !f.HasAccessToken || f.AccessToken != "ACCESSTOKENabcdefghijklmnop012345" {
		t.Fatalf("access token=%q", f.AccessToken)
	}
	if !f.HasRefreshToken || f.RefreshToken != "REFRESHTOKENabcdefghijklmnop012345" {
		t.Fatalf("refresh token=%q", f.RefreshToken)
	}
	if !f.HasWebhookSecret || f.WebhookSecret == "" {
		t.Fatalf("webhook secret=%q", f.WebhookSecret)
	}
	if !f.HasSDKCredentials || f.LemonAppID != "lemonclient123456" {
		t.Fatalf("app id=%q sdk=%v", f.LemonAppID, f.HasSDKCredentials)
	}
	if f.LemonUserID != "lemonuser12" {
		t.Fatalf("user id=%q", f.LemonUserID)
	}
	if f.Username != "alice@example.com" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.ClienteCuitRaw != "27-11112222-3" || f.ClienteDNI != "12345678" {
		t.Fatalf("cuit=%q dni=%q", f.ClienteCuitRaw, f.ClienteDNI)
	}
	if f.PIISignalCount != 3 {
		t.Fatalf("pii signals=%d want 3 (cuit+dni+name)", f.PIISignalCount)
	}
}

func TestParseLemonConfigEmpty(t *testing.T) {
	if f := ParseLemonConfig(nil); f.HasPassword || f.PIISignalCount != 0 {
		t.Fatalf("empty config non-zero: %+v", f)
	}
	// ParseLemonCredentials delegates to ParseLemonConfig.
	if f := ParseLemonCredentials([]byte("password=abc")); !f.HasPassword {
		t.Fatal("credentials delegate must detect password")
	}
}

func TestParseLemonSDKScript(t *testing.T) {
	body := []byte(strings.Join([]string{
		"import lemon",
		"access_token = ACCESSTOKENabcdefghijklmnop012345",
		"# brecha_cambiaria arbitrage strategy",
	}, "\n"))
	f := ParseLemonSDKScript(body)
	if !f.HasSDKCredentials {
		t.Fatal("import lemon + token = sdk credentials")
	}
	if !f.HasUSDTARSArbitrage {
		t.Fatal("brecha_cambiaria must flag arbitrage")
	}
}

func TestParseLemonTradeLog(t *testing.T) {
	body := []byte(strings.Join([]string{
		"trade_id=1",
		"asset: BTC",
		"balance_usd: 5000",
		"trade_id=2",
		"asset: ETH",
		"balance_usd: 3000",
	}, "\n"))
	f := ParseLemonTradeLog(body)
	if f.TradeRecordCount != 2 {
		t.Fatalf("trade records=%d want 2", f.TradeRecordCount)
	}
	if f.CryptoBalanceUSDCents != 800000 {
		t.Fatalf("balance cents=%d want 800000", f.CryptoBalanceUSDCents)
	}
	if f.DistinctAssetsCount != 2 {
		t.Fatalf("distinct assets=%d want 2", f.DistinctAssetsCount)
	}
	if f := ParseLemonTradeLog(nil); f.TradeRecordCount != 0 {
		t.Fatal("empty trade log must be zero")
	}
}

func TestParseLemonEarnPositions(t *testing.T) {
	body := []byte("earn_position=1\napy=0.05\nstake_id=abc\n")
	f := ParseLemonEarnPositions(body)
	if f.EarnPositionCount != 3 {
		t.Fatalf("earn positions=%d want 3", f.EarnPositionCount)
	}
	if f := ParseLemonEarnPositions(nil); f.EarnPositionCount != 0 {
		t.Fatal("empty earn must be zero")
	}
}

func TestParseLemonKYCDump(t *testing.T) {
	body := []byte(strings.Join([]string{
		"kyc_level: 2",
		"dni_front: s3://bucket/x.jpg",
		"cliente_cuit: 27-11112222-3",
		"dni: 12345678",
	}, "\n"))
	f := ParseLemonKYCDump(body)
	if !f.HasKYCMarkers {
		t.Fatal("kyc_level must flag kyc markers")
	}
	if f.ClienteCuitRaw != "27-11112222-3" || f.ClienteDNI != "12345678" {
		t.Fatalf("cuit=%q dni=%q", f.ClienteCuitRaw, f.ClienteDNI)
	}
	if f.PIISignalCount != 2 {
		t.Fatalf("pii signals=%d want 2", f.PIISignalCount)
	}
	if f := ParseLemonKYCDump(nil); f.HasKYCMarkers {
		t.Fatal("empty kyc must be zero")
	}
}

func TestParseLemonCardTransactions(t *testing.T) {
	body := []byte("card_tx_id=1\nmerchant_name=Store\ncard_tx_id=2\n")
	f := ParseLemonCardTransactions(body)
	if f.CardTxCount != 3 {
		t.Fatalf("card tx=%d want 3", f.CardTxCount)
	}
	if f := ParseLemonCardTransactions(nil); f.CardTxCount != 0 {
		t.Fatal("empty card txns must be zero")
	}
}

func TestParseLemonArbitrageScript(t *testing.T) {
	// Even without brecha markers, arbitrage script forces the flag.
	f := ParseLemonArbitrageScript([]byte("print('hi')\n"))
	if !f.HasUSDTARSArbitrage {
		t.Fatal("arbitrage script must force USDT/ARS flag")
	}
}

func TestParseLemonMarketplaceAndWebhookConfig(t *testing.T) {
	body := []byte("webhook_secret = WEBHOOKSECRET1234567890\n")
	m := ParseLemonMarketplaceConfig(body)
	if !m.HasWebhookSecret || m.WebhookSecret == "" {
		t.Fatalf("marketplace webhook secret: %+v", m)
	}
	w := ParseLemonWebhookConfig(body)
	if !w.HasWebhookSecret || w.WebhookSecret == "" {
		t.Fatalf("webhook secret: %+v", w)
	}
}

func TestSumUSDBalancesDecimalForms(t *testing.T) {
	// The balance regex captures a single separator group, so European
	// "1.234,56" is read as "1.234" (thousands dot dropped → 1234) and
	// plain "10" as 10 → total 1244 → 124400 cents.
	body := []byte("balance_usd: 1.234,56\nusd_amount = 10\n")
	if got := sumUSDBalances(body); got != 124400 {
		t.Fatalf("sum cents=%d want 124400", got)
	}
	// A comma-decimal value keeps its fractional part (12,50 → 1250c).
	if got := sumUSDBalances([]byte("balance_usd: 12,50")); got != 1250 {
		t.Fatalf("sum cents=%d want 1250", got)
	}
	if sumUSDBalances([]byte("balance_usd: notanumber")) != 0 {
		t.Fatal("non-numeric balance must contribute 0")
	}
}

func TestCountDistinctAssetsDedup(t *testing.T) {
	body := []byte("asset: BTC\ncurrency: btc\ncoin: ETH\n")
	if got := countDistinctAssets(body); got != 2 {
		t.Fatalf("distinct assets=%d want 2 (BTC/ETH, case-folded)", got)
	}
}

func TestPiiBundleSignalCount(t *testing.T) {
	if n := piiBundleSignalCount([]byte("name: Bob"), "", ""); n != 1 {
		t.Fatalf("name only=%d want 1", n)
	}
	if n := piiBundleSignalCount([]byte("nothing"), "27-1-1", "123"); n != 2 {
		t.Fatalf("cuit+dni=%d want 2", n)
	}
	if n := piiBundleSignalCount([]byte("nothing here"), "", ""); n != 0 {
		t.Fatalf("no signals=%d want 0", n)
	}
}

// -- classifiers --------------------------------------------------

func TestClassifyAccount(t *testing.T) {
	cases := []struct {
		row  Row
		want AccountClass
	}{
		{Row{FilePath: "/x/compliance_report.json"}, AccountComplianceOfficer},
		{Row{FilePath: "/x/a.json", HasKYCDump: true}, AccountComplianceOfficer},
		{Row{FilePath: "/x/marketplace.json"}, AccountMerchant},
		{Row{FilePath: "/x/a.json", HasMarketplaceWebhook: true}, AccountMerchant},
		{Row{FilePath: "/x/a.py", ArtifactKind: KindSDKScript}, AccountDeveloper},
		{Row{FilePath: "/x/a.py", ArtifactKind: KindArbitrageScript}, AccountDeveloper},
		{Row{FilePath: "/x/a.json", HasSDKCredentials: true}, AccountDeveloper},
		{Row{FilePath: "/x/a.csv", HasTradeLog: true}, AccountConsumer},
		{Row{FilePath: "/x/a.csv", HasEarnPositions: true}, AccountConsumer},
		{Row{FilePath: "/x/a.csv", HasCardTransactions: true}, AccountConsumer},
		{Row{FilePath: "/x/a.json", HasOAuthAccessToken: true}, AccountAPI},
		{Row{FilePath: "/x/a.json", HasOAuthRefreshToken: true}, AccountAPI},
		{Row{FilePath: "/x/a.json", HasPasswordInConfig: true}, AccountConsumer},
		{Row{FilePath: "/x/a.json"}, AccountUnknown},
	}
	for _, c := range cases {
		if got := classifyAccount(c.row); got != c.want {
			t.Fatalf("classifyAccount(%+v)=%q want %q", c.row, got, c.want)
		}
	}
}

func TestClassifyProduct(t *testing.T) {
	cases := []struct {
		row  Row
		want ProductClass
	}{
		{Row{HasCardTransactions: true, HasEarnPositions: true}, ProductMultiProduct},
		{Row{HasCardTransactions: true}, ProductCryptoCard},
		{Row{HasEarnPositions: true}, ProductYieldEarn},
		{Row{HasUSDTARSArbitrage: true}, ProductStablecoinRails},
		{Row{HasMarketplaceWebhook: true}, ProductMarketplace},
		{Row{HasTradeLog: true}, ProductCryptoWallet},
		{Row{}, ProductUnknown},
	}
	for _, c := range cases {
		if got := classifyProduct(c.row); got != c.want {
			t.Fatalf("classifyProduct(%+v)=%q want %q", c.row, got, c.want)
		}
	}
}

func TestSortRowsDeterministic(t *testing.T) {
	in := []Row{
		{FilePath: "z", ArtifactKind: KindConfig},
		{FilePath: "a", ArtifactKind: KindKYCDump},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].FilePath != "z" {
		t.Fatalf("last=%+v", in[2])
	}
}

func TestIsSystemPseudoProfile(t *testing.T) {
	for _, n := range []string{"Public", "default", "ALL USERS", "Shared"} {
		if !isSystemPseudoProfile(n) {
			t.Fatalf("expected pseudo: %q", n)
		}
	}
	if isSystemPseudoProfile("bob") {
		t.Fatal("bob is real")
	}
}

// -- collector end-to-end -----------------------------------------

func newTestCollector(installRoots, usersBases []string, getenv func(string) string) *fileCollector {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	return &fileCollector{
		installRoots: installRoots,
		usersBases:   usersBases,
		getenv:       getenv,
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          fixedClock,
	}
}

func TestNewCollectorName(t *testing.T) {
	if NewCollector().Name() != "winarglemoncash" {
		t.Fatal("collector name")
	}
}

func TestCollectorWalksInstallTree(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Lemon")
	must(t, os.MkdirAll(root, 0o755))

	cfgPath := filepath.Join(root, "lemon_config.json")
	must(t, os.WriteFile(cfgPath, []byte(
		`{"access_token":"ACCESSTOKENabcdefghijklmnop012345","cliente_cuit":"27-11112222-3"}`), 0o644))

	kycPath := filepath.Join(root, "kyc_dump.json")
	must(t, os.WriteFile(kycPath, []byte("kyc_level: 2\ncliente_cuit: 20-33334444-5\ndni: 87654321\nname: Bob\n"), 0o644))

	envPath := filepath.Join(root, ".env")
	must(t, os.WriteFile(envPath, []byte(
		"LEMON_PASSWORD=hunter2secretpw\nLEMON_REFRESH_TOKEN=REFRESHTOKENabcdefghijklmnop012345\n"), 0o644))

	exePath := filepath.Join(root, "lemon_setup.exe")
	must(t, os.WriteFile(exePath, []byte("MZ fake"), 0o644))

	// Ignored: wrong extension.
	must(t, os.WriteFile(filepath.Join(root, "readme.md"), []byte("noise"), 0o644))

	c := newTestCollector([]string{root}, nil, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 rows, got %d: %v", len(got), paths(got))
	}

	byPath := map[string]Row{}
	for _, r := range got {
		byPath[r.FilePath] = r
	}

	cfg := byPath[cfgPath]
	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasOAuthAccessToken || cfg.AccessTokenHash == "" {
		t.Fatalf("cfg must flag access token: %+v", cfg)
	}
	if cfg.ClienteCuitPrefix != "27" || cfg.ClienteCuitSuffix4 != "2223" {
		t.Fatalf("cfg cuit=(%q,%q)", cfg.ClienteCuitPrefix, cfg.ClienteCuitSuffix4)
	}
	if cfg.AccountClass != AccountAPI {
		t.Fatalf("cfg account=%q want api", cfg.AccountClass)
	}
	if !cfg.IsRecent {
		t.Fatal("cfg should be recent")
	}

	kyc := byPath[kycPath]
	if kyc.ArtifactKind != KindKYCDump || !kyc.HasKYCDump {
		t.Fatalf("kyc kind/flag: %+v", kyc)
	}
	if kyc.AccountClass != AccountComplianceOfficer {
		t.Fatalf("kyc account=%q want compliance-officer", kyc.AccountClass)
	}
	if kyc.ClienteDNIHash == "" {
		t.Fatal("kyc must hash the DNI")
	}
	if !kyc.HasPIIBundle {
		t.Fatalf("kyc cuit+dni+name = pii bundle: %+v", kyc)
	}
	if !kyc.IsCredentialExposureRisk {
		t.Fatalf("readable kyc with pii = exposure: %+v", kyc)
	}

	env := byPath[envPath]
	if env.ArtifactKind != KindCredentials {
		t.Fatalf(".env kind=%q", env.ArtifactKind)
	}
	if !env.HasPasswordInConfig || !env.HasOAuthRefreshToken {
		t.Fatalf(".env flags: %+v", env)
	}
	if env.RefreshTokenHash == "" {
		t.Fatal(".env must hash refresh token")
	}
	if !env.IsCredentialExposureRisk {
		t.Fatalf("readable .env with creds = exposure: %+v", env)
	}

	exe := byPath[exePath]
	if exe.ArtifactKind != KindInstaller {
		t.Fatalf("exe kind=%q", exe.ArtifactKind)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-lemon")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "lemon.json"),
		[]byte(`{"user_id":"lemonuser99"}`), 0o644))

	c := newTestCollector(nil, nil, func(k string) string {
		if k == "LEMON_DIR" {
			return envDir
		}
		return ""
	})
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || got[0].ArtifactKind != KindConfig {
		t.Fatalf("env override: %v", got)
	}
}

func TestCollectorWalksUserProfiles(t *testing.T) {
	tmp := t.TempDir()
	base := filepath.Join(tmp, "home")

	aliceDir := filepath.Join(base, "alice", ".lemon")
	must(t, os.MkdirAll(aliceDir, 0o755))
	// Name must carry a lemon-family token to pass IsCandidateName.
	alicePath := filepath.Join(aliceDir, "lemon_trade_log.csv")
	must(t, os.WriteFile(alicePath, []byte("trade_id=1\ntrade_id=2\n"), 0o644))

	// Pseudo-profile skipped.
	pubDir := filepath.Join(base, "Public", ".lemon")
	must(t, os.MkdirAll(pubDir, 0o755))
	must(t, os.WriteFile(filepath.Join(pubDir, "lemon.json"), []byte("{}"), 0o644))

	c := newTestCollector(nil, []string{base}, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || got[0].FilePath != alicePath {
		t.Fatalf("want alice trade log only, got %v", paths(got))
	}
	if got[0].UserProfile != "alice" {
		t.Fatalf("user profile=%q", got[0].UserProfile)
	}
	if got[0].ArtifactKind != KindTradeLog || !got[0].HasTradeLog {
		t.Fatalf("trade log flags: %+v", got[0])
	}
	if got[0].ProductClass != ProductCryptoWallet {
		t.Fatalf("product=%q want crypto-wallet", got[0].ProductClass)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := newTestCollector([]string{"/nope-lemon"}, []string{"/nope-users"}, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestCollectorStress(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Lemon")
	must(t, os.MkdirAll(root, 0o755))
	var sb strings.Builder
	for i := 0; i < 4000; i++ {
		fmt.Fprintf(&sb, "trade_id=%d\n", i)
	}
	must(t, os.WriteFile(filepath.Join(root, "lemon_trade_log.csv"),
		[]byte(sb.String()), 0o644))

	c := newTestCollector([]string{root}, nil, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 row, got %d", len(got))
	}
	if got[0].TradeRecordCount != 4000 {
		t.Fatalf("trade records=%d want 4000", got[0].TradeRecordCount)
	}
}

func paths(rs []Row) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.FilePath
	}
	return out
}
