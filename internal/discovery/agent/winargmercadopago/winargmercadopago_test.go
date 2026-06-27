package winargmercadopago

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "mp-config"},
		{string(KindCredentials), "mp-credentials"},
		{string(KindSDKScript), "mp-sdk-script"},
		{string(KindWebhookConfig), "mp-webhook-config"},
		{string(KindRendimientosExport), "mp-rendimientos-export"},
		{string(KindInversionesExport), "mp-inversiones-export"},
		{string(KindTradeLog), "mp-trade-log"},
		{string(KindMarketplaceConfig), "mp-marketplace-config"},
		{string(KindAuditLog), "mp-audit-log"},
		{string(KindInstaller), "mp-installer"},
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
		{string(ProductRendimientosFCI), "rendimientos-fci"},
		{string(ProductInversionesEquity), "inversiones-equity"},
		{string(ProductInversionesBonds), "inversiones-bonds"},
		{string(ProductInversionesCEDEAR), "inversiones-cedears"},
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

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"mp_config.json",
		"mercadopago_credentials.env",
		".env",
		"mp_sdk_script.py",
		"mp_webhook_handler.py",
		"mp_rendimientos_202506.csv",
		"mp_inversiones_202506.csv",
		"mp_audit_202506.log",
		"mp_trade_log.csv",
		"marketplace_autoinvest.json",
		"mercadopago_installer.msi",
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
		"mp_config.json":              KindConfig,
		"mercadopago.json":            KindConfig,
		"mercadopago_credentials.env": KindCredentials,
		".env":                        KindCredentials,
		"mp_api_token.json":           KindCredentials,
		"mp_token.json":               KindCredentials,
		"mp_sdk_script.py":            KindSDKScript,
		"mercadopago_sdk.py":          KindSDKScript,
		"mp_webhook_handler.py":       KindWebhookConfig,
		"mp_webhook_config.json":      KindWebhookConfig,
		"mp_rendimientos_202506.csv":  KindRendimientosExport,
		"rendimientos_202506.csv":     KindRendimientosExport,
		"mp_inversiones_202506.csv":   KindInversionesExport,
		"inversiones_202506.csv":      KindInversionesExport,
		"mp_trade_log.csv":            KindTradeLog,
		"marketplace_autoinvest.json": KindMarketplaceConfig,
		"mp_audit_202506.log":         KindAuditLog,
		"mercadopago_installer.msi":   KindInstaller,
		"":                            KindUnknown,
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
	if PeriodFromFilename("mp_audit_202506.log") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.log") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindSDKScript, KindWebhookConfig,
		KindRendimientosExport, KindInversionesExport,
		KindTradeLog, KindMarketplaceConfig, KindAuditLog,
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
		ArtifactKind:        KindCredentials,
		HasOAuthAccessToken: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + token + cliente = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:        KindCredentials,
		HasOAuthAccessToken: true,
		FileMode:            0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateHighBalance(t *testing.T) {
	r := Row{
		ArtifactKind:    KindInversionesExport,
		BalanceUSDCents: HighBalanceUSDCents + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasHighBalance {
		t.Fatal("> 50 K USD must flag high balance")
	}
}

func TestAnnotateRendimientosAuto(t *testing.T) {
	r := Row{
		ArtifactKind:            KindRendimientosExport,
		RendimientosRecordCount: 5,
	}
	AnnotateSecurity(&r)
	if !r.HasRendimientosExport {
		t.Fatal("rendimientos kind must auto-flag")
	}
}

func TestAnnotateInversionesAuto(t *testing.T) {
	r := Row{ArtifactKind: KindInversionesExport}
	AnnotateSecurity(&r)
	if !r.HasInversionesExport {
		t.Fatal("inversiones kind must auto-flag")
	}
}

func TestAnnotateAuditAuto(t *testing.T) {
	r := Row{ArtifactKind: KindAuditLog, AuditEventCount: 3}
	AnnotateSecurity(&r)
	if !r.HasAuditLog {
		t.Fatal("audit kind must auto-flag")
	}
}

func TestAnnotateMarketplaceAuto(t *testing.T) {
	r := Row{ArtifactKind: KindMarketplaceConfig}
	AnnotateSecurity(&r)
	if !r.HasMarketplaceAutoinvest {
		t.Fatal("marketplace kind must auto-flag")
	}
}

func TestAnnotatePIIBundle(t *testing.T) {
	r := Row{
		ArtifactKind:   KindInversionesExport,
		PIISignalCount: 2,
	}
	AnnotateSecurity(&r)
	if !r.HasPIIBundle {
		t.Fatal("PII signal count >=2 must flag bundle")
	}
}

func TestParseMPCredentials(t *testing.T) {
	body := []byte(`MP_CLIENT_ID=1234567890123456
MP_CLIENT_SECRET=ABCdefGHIjklMNOpqrSTUvwxYZ012345
MP_ACCESS_TOKEN=APP_USR-1234567890-061015-aBcDeFgHiJkLmNoPqRsTuVwX-12345
MP_REFRESH_TOKEN=TG-aBcDeFgHiJkLmNoPqRsTuVwX-1234567890
MP_USER_ID=987654321
MP_WEBHOOK_SECRET=zYxWvUtSrQpOnMlKjIhGfEdCbA
cliente_cuit=27-11111111-4
dni=12345678
nombre=Alice Garcia
`)
	f := ParseMPCredentials(body)
	if !f.HasPassword {
		t.Fatal("MP_CLIENT_SECRET must flag password")
	}
	if !f.HasAccessToken {
		t.Fatal("MP_ACCESS_TOKEN must flag")
	}
	if !f.HasRefreshToken {
		t.Fatal("MP_REFRESH_TOKEN must flag")
	}
	if !f.HasWebhookSecret {
		t.Fatal("MP_WEBHOOK_SECRET must flag")
	}
	if f.MPAppID == "" {
		t.Fatalf("MP app id missing")
	}
	if f.MPUserID == "" {
		t.Fatalf("MP user id missing")
	}
	if !f.HasSDKCredentials {
		t.Fatal("SDK credentials must flag from client_id")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
	if f.ClienteDNI == "" {
		t.Fatal("cliente DNI missing")
	}
	if f.PIISignalCount < 3 {
		t.Fatalf("PII signal count=%d want >=3", f.PIISignalCount)
	}
}

func TestParseMPSDKScript(t *testing.T) {
	body := []byte(`import mercadopago
sdk = mercadopago.SDK("APP_USR-1234567890-061015-aBcDeFgHiJkLmNoPqRsTuVwX-12345")
MP_ACCESS_TOKEN = "APP_USR-1234567890-061015-aBcDeFgHiJkLmNoPqRsTuVwX-12345"
payment_data = {"transaction_amount": 100}
result = sdk.payment().create(payment_data)
`)
	f := ParseMPSDKScript(body)
	if !f.HasAccessToken {
		t.Fatal("access token must flag")
	}
	if !f.HasSDKCredentials {
		t.Fatal("import + token must flag SDK creds")
	}
}

func TestParseMPRendimientosExport(t *testing.T) {
	body := []byte(`user_id,cuotaparte,mercado_fondo,balance_usd
987654321,150.50,Mercado Fondo,balance_usd=2500.75
987654321,200.00,Mercado Fondo Plus,balance_usd=5000.00
987654321,500.00,money_market,balance_usd=10000
cliente_cuit=27-11111111-4
`)
	f := ParseMPRendimientosExport(body)
	if f.RendimientosRecordCount < 3 {
		t.Fatalf("rendimientos rows=%d want >=3", f.RendimientosRecordCount)
	}
	if f.BalanceUSDCents < 1750000 {
		t.Fatalf("balance=%d want >=1750000", f.BalanceUSDCents)
	}
}

func TestParseMPInversionesExport(t *testing.T) {
	body := []byte(`user_id,ticker,equity,bond,balance_usd
987654321,GGAL,accion,,balance_usd=5500
987654321,AAPLD,cedear,,balance_usd=3200
987654321,AL30,,bono,balance_usd=10000
cliente_cuit=27-11111111-4
dni=12345678
`)
	f := ParseMPInversionesExport(body)
	if f.InversionesRecordCount < 3 {
		t.Fatalf("inversiones rows=%d want >=3", f.InversionesRecordCount)
	}
	if f.BalanceUSDCents < 1870000 {
		t.Fatalf("balance=%d", f.BalanceUSDCents)
	}
	if f.PIISignalCount < 2 {
		t.Fatalf("PII signals=%d", f.PIISignalCount)
	}
}

func TestParseMPMarketplaceAutoinvest(t *testing.T) {
	body := []byte(`{
"merchant_id": "987654321",
"auto_invest": true,
"rendimientos_auto_fund": true,
"investment_strategy": "automatic"
}`)
	f := ParseMPMarketplaceConfig(body)
	if !f.HasAutoinvest {
		t.Fatal("autoinvest must flag")
	}
}

func TestParseMPWebhookConfig(t *testing.T) {
	body := []byte(`{
"webhook_url": "https://example.com/mp-webhook",
"webhook_secret": "zYxWvUtSrQpOnMlKjIhGfEdCbA",
"x-signature": "ts=1700000000,v1=abc123",
"events": ["payment", "merchant_order"]
}`)
	f := ParseMPWebhookConfig(body)
	if !f.HasWebhookSecret {
		t.Fatal("webhook secret must flag")
	}
	if f.WebhookSecret == "" {
		t.Fatal("webhook secret must extract")
	}
}

func TestParseMPAuditLog(t *testing.T) {
	body := []byte(`2026-06-15T09:30:01Z action=login user_id=987654321
2026-06-15T09:30:02Z action=oauth_refresh user_id=987654321
2026-06-15T09:30:03Z audit_event=position_change user_id=987654321
cliente_cuit=27-11111111-4
`)
	f := ParseMPAuditLog(body)
	if f.AuditEventCount < 3 {
		t.Fatalf("audit events=%d", f.AuditEventCount)
	}
	if f.MPUserID == "" {
		t.Fatalf("MP user id missing")
	}
}

func TestParseMPEmpty(t *testing.T) {
	f := ParseMPConfig(nil)
	if f.HasPassword || f.AccessToken != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestClassifyAccount(t *testing.T) {
	if got := classifyAccount(Row{
		FilePath:     "mp_audit.log",
		ArtifactKind: KindAuditLog,
	}); got != AccountComplianceOfficer {
		t.Fatalf("audit -> compliance, got %q", got)
	}
	if got := classifyAccount(Row{
		FilePath:                 "marketplace_autoinvest.json",
		HasMarketplaceAutoinvest: true,
	}); got != AccountMerchant {
		t.Fatalf("marketplace -> merchant, got %q", got)
	}
	if got := classifyAccount(Row{
		ArtifactKind:      KindSDKScript,
		HasSDKCredentials: true,
	}); got != AccountDeveloper {
		t.Fatalf("SDK -> developer, got %q", got)
	}
	if got := classifyAccount(Row{HasRendimientosExport: true}); got != AccountConsumer {
		t.Fatalf("rendimientos -> consumer, got %q", got)
	}
	if got := classifyAccount(Row{HasOAuthAccessToken: true}); got != AccountAPI {
		t.Fatalf("api token -> api, got %q", got)
	}
	if got := classifyAccount(Row{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyProduct(t *testing.T) {
	if got := classifyProduct(Row{
		HasRendimientosExport: true,
		HasInversionesExport:  true,
	}); got != ProductMultiProduct {
		t.Fatalf("both -> multi, got %q", got)
	}
	if got := classifyProduct(Row{HasRendimientosExport: true}); got != ProductRendimientosFCI {
		t.Fatalf("rend -> rendimientos-fci, got %q", got)
	}
	if got := classifyProduct(Row{HasInversionesExport: true}); got != ProductInversionesEquity {
		t.Fatalf("inv -> inversiones-equity, got %q", got)
	}
	if got := classifyProduct(Row{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", ".mercadopago")
	must(t, os.MkdirAll(dir, 0o755))

	credPath := filepath.Join(dir, "credentials.env")
	must(t, os.WriteFile(credPath, []byte(`MP_CLIENT_ID=1234567890123456
MP_CLIENT_SECRET=ABCdefGHIjklMNOpqrSTUvwxYZ012345
MP_ACCESS_TOKEN=APP_USR-1234567890-061015-aBcDeFgHiJkLmNoPqRsTuVwX-12345
MP_REFRESH_TOKEN=TG-aBcDeFgHiJkLmNoPqRsTuVwX-1234567890
cliente_cuit=27-11111111-4
`), 0o644))

	rendPath := filepath.Join(dir, "mp_rendimientos_202506.csv")
	must(t, os.WriteFile(rendPath, []byte(`user_id,cuotaparte,mercado_fondo,balance_usd
987654321,150.50,Mercado Fondo,balance_usd=2500.75
987654321,200.00,Mercado Fondo Plus,balance_usd=60000.00
cliente_cuit=27-11111111-4
`), 0o644))

	invPath := filepath.Join(dir, "mp_inversiones_202506.csv")
	must(t, os.WriteFile(invPath, []byte(`user_id,ticker,equity,balance_usd
987654321,GGAL,accion,balance_usd=5500
987654321,AAPLD,cedear,balance_usd=3200
cliente_cuit=27-11111111-4
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", ".mercadopago")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "credentials.env"),
		[]byte(`MP_CLIENT_ID=999`), 0o644))

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
		t.Fatalf("want 3 (cred+rend+inv), got %d: %+v", len(got), got)
	}

	var cred, rend, inv Row
	for _, r := range got {
		switch r.FilePath {
		case credPath:
			cred = r
		case rendPath:
			rend = r
		case invPath:
			inv = r
		}
	}

	if cred.ArtifactKind != KindCredentials {
		t.Fatalf("cred kind=%q", cred.ArtifactKind)
	}
	if !cred.HasOAuthAccessToken {
		t.Fatalf("cred must flag access token: %+v", cred)
	}
	if !cred.HasOAuthRefreshToken {
		t.Fatalf("cred must flag refresh token: %+v", cred)
	}
	if !cred.HasSDKCredentials {
		t.Fatalf("cred must flag SDK creds: %+v", cred)
	}
	if !cred.HasClienteCuit {
		t.Fatalf("cred must flag cliente cuit: %+v", cred)
	}
	if !cred.IsCredentialExposureRisk {
		t.Fatalf("readable + tokens + cliente = exposure: %+v", cred)
	}

	if rend.ArtifactKind != KindRendimientosExport {
		t.Fatalf("rend kind=%q", rend.ArtifactKind)
	}
	if !rend.HasRendimientosExport {
		t.Fatalf("rend must flag rendimientos: %+v", rend)
	}
	if rend.RendimientosRecordCount < 2 {
		t.Fatalf("rend rows=%d", rend.RendimientosRecordCount)
	}
	if !rend.HasHighBalance {
		t.Fatalf("rend > USD 50 K must flag high balance: %+v", rend)
	}

	if inv.ArtifactKind != KindInversionesExport {
		t.Fatalf("inv kind=%q", inv.ArtifactKind)
	}
	if !inv.HasInversionesExport {
		t.Fatalf("inv must flag inversiones: %+v", inv)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-mp")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "mercadopago.json"),
		[]byte(`{"mp_user_id": "987654321"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "MERCADOPAGO_DIR" {
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
		installRoots: []string{"/nope-mp"},
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
		{FilePath: "a", ArtifactKind: KindAuditLog},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	// At FilePath="a", `mp-audit-log` < `mp-config` alphabetically.
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindAuditLog {
		t.Fatalf("first=%+v want (a,mp-audit-log)", in[0])
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
