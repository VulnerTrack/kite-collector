package winargcohen

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindProfile), "cohen-profile"},
		{string(KindMobileOAuth), "cohen-mobile-oauth"},
		{string(KindFCISubscription), "cohen-fci-subscription"},
		{string(KindFCIRedemption), "cohen-fci-redemption"},
		{string(KindCuotaparteRecord), "cohen-cuotaparte-record"},
		{string(KindLiquidacionPDF), "cohen-liquidacion-pdf"},
		{string(KindResearchPDF), "cohen-research-pdf"},
		{string(KindSAGGMConfig), "cohen-saggm-config"},
		{string(KindFIXSession), "cohen-fix-session"},
		{string(AccountInstitutionalCliente), "institutional-cliente"},
		{string(AccountFCICuotapartista), "fci-cuotapartista"},
		{string(AccountFIXCounterparty), "fix-counterparty"},
		{string(ProductARFCI), "ar-fci"},
		{string(ProductCEDEAR), "cedear"},
		{string(ProductMEPDollar), "mep-dollar"},
		{string(BackofficeSAGGMGalileo), "saggm-galileo"},
		{string(BackofficeSAGGMMariva), "saggm-mariva"},
		{string(BackofficeSintesis), "sintesis"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"profile.cohen",
		"session.cnt",
		"oauth_token.json",
		"refresh_token.json",
		"suscripcion_15.json",
		"rescate_15.json",
		"cuotaparte_15.json",
		"liquidacion_20260615.pdf",
		"research_GGAL.pdf",
		"saggm_config.ini",
		"fix_session.cfg",
		"boleto_20260615.pdf",
		"estado_cuenta_202606.pdf",
		"cohen_profile.json",
		"cohen_mobile.json",
	}
	no := []string{"", "factura.xml", "random.bin", "report.pdf", "notes.txt"}
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
		"profile.cohen":            KindProfile,
		"session.cnt":              KindSessionToken,
		"oauth_token.json":         KindMobileOAuth,
		"refresh_token.json":       KindMobileOAuth,
		"cohen_mobile.json":        KindMobileOAuth,
		"suscripcion_15.json":      KindFCISubscription,
		"rescate_15.json":          KindFCIRedemption,
		"cuotaparte_15.json":       KindCuotaparteRecord,
		"liquidacion_20260615.pdf": KindLiquidacionPDF,
		"liquidacion_20260615.csv": KindLiquidacionPDF,
		"research_GGAL.pdf":        KindResearchPDF,
		"informe_GGAL.pdf":         KindResearchPDF,
		"saggm_config.ini":         KindSAGGMConfig,
		"fix_session.cfg":          KindFIXSession,
		"boleto_20260615.pdf":      KindTradeConfirmation,
		"estado_cuenta_202606.pdf": KindStatement,
		"cohen_setup.msi":          KindInstaller,
		"":                         KindUnknown,
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
	cases := map[string]string{
		"liquidacion_20260615.pdf": "202606",
		"estado_cuenta_202606.pdf": "202606",
		"profile.cohen":            "",
	}
	for in, want := range cases {
		if got := PeriodFromFilename(in); got != want {
			t.Fatalf("PeriodFromFilename(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAREquityStem(t *testing.T) {
	yes := []string{"GGAL", "YPFD", "PAMP", "ALUA", "AL30"}
	no := []string{"", "AAPL", "TSLA"}
	for _, v := range yes {
		if !IsAREquityStem(v) {
			t.Fatalf("expected AR equity: %q", v)
		}
	}
	for _, v := range no {
		if IsAREquityStem(v) {
			t.Fatalf("expected NOT AR equity: %q", v)
		}
	}
}

func TestCEDEARStem(t *testing.T) {
	yes := []string{"AAPL", "MSFT", "MELI"}
	no := []string{"", "GGAL", "ALUA"}
	for _, v := range yes {
		if !IsCEDEARStem(v) {
			t.Fatalf("expected CEDEAR: %q", v)
		}
	}
	for _, v := range no {
		if IsCEDEARStem(v) {
			t.Fatalf("expected NOT CEDEAR: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindProfile, KindSessionToken, KindMobileOAuth,
		KindFCISubscription, KindFCIRedemption, KindCuotaparteRecord,
		KindLiquidacionPDF, KindResearchPDF,
		KindSAGGMConfig, KindFIXSession,
		KindTradeConfirmation, KindStatement,
	}
	for _, k := range yes {
		if !IsCredentialKind(k) {
			t.Fatalf("expected cred kind: %q", k)
		}
	}
	for _, k := range []ArtifactKind{KindInstaller, KindOther, KindUnknown} {
		if IsCredentialKind(k) {
			t.Fatalf("expected NOT cred kind: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:         KindProfile,
		HasPasswordInProfile: true,
		ClienteCuitPrefix:    "27",
		ClienteCuitSuffix4:   "1114",
		FileMode:             0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + cliente = exposure")
	}
}

func TestAnnotateMobileOAuthAuto(t *testing.T) {
	r := Row{ArtifactKind: KindMobileOAuth}
	AnnotateSecurity(&r)
	if !r.HasOAuthRefreshToken {
		t.Fatal("mobile-oauth kind must flag OAuth")
	}
}

func TestAnnotateFCIAuto(t *testing.T) {
	r := Row{ArtifactKind: KindFCISubscription}
	AnnotateSecurity(&r)
	if !r.HasFCISubscription {
		t.Fatal("subscription kind must flag")
	}
	r2 := Row{ArtifactKind: KindFCIRedemption}
	AnnotateSecurity(&r2)
	if !r2.HasFCIRedemption {
		t.Fatal("redemption kind must flag")
	}
	r3 := Row{ArtifactKind: KindCuotaparteRecord}
	AnnotateSecurity(&r3)
	if !r3.HasCuotaparteRecord {
		t.Fatal("cuotaparte kind must flag")
	}
}

func TestAnnotateInstitutional(t *testing.T) {
	r := Row{
		ArtifactKind:    KindFCISubscription,
		CuotaparteCount: InstitutionalCuotaparteThreshold + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasInstitutionalClass {
		t.Fatal("> 1000 cuotapartes must flag institutional class")
	}
}

func TestAnnotateSAGGMAuto(t *testing.T) {
	r := Row{ArtifactKind: KindSAGGMConfig}
	AnnotateSecurity(&r)
	if !r.HasSAGGMBackoffice {
		t.Fatal("saggm kind must flag")
	}
}

func TestAnnotateFIXSessionAuto(t *testing.T) {
	r := Row{ArtifactKind: KindFIXSession}
	AnnotateSecurity(&r)
	if !r.HasFIXSession {
		t.Fatal("fix-session kind must flag")
	}
}

func TestParseCohenProfile(t *testing.T) {
	body := []byte(`{
  "username": "alice@example.com",
  "password": "secret123",
  "cuenta_comitente": "12345",
  "backoffice": "SAGGM Galileo",
  "especie": "GGAL",
  "especie2": "AAPL",
  "cliente_cuit": "27-11111111-4"
}`)
	f := ParseCohenProfile(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.CuentaComitente != "12345" {
		t.Fatalf("comitente=%q", f.CuentaComitente)
	}
	if f.BackofficeChannel != BackofficeSAGGMGalileo {
		t.Fatalf("backoffice=%q want saggm-galileo", f.BackofficeChannel)
	}
	if f.AREquitySymbolsCount < 1 {
		t.Fatalf("ar=%d", f.AREquitySymbolsCount)
	}
	if f.CEDEARSymbolsCount < 1 {
		t.Fatalf("cedear=%d", f.CEDEARSymbolsCount)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cuit must extract")
	}
}

func TestParseCohenMobileOAuth(t *testing.T) {
	body := []byte(`{
  "access_token": "Bearer-abcd1234567890aBcDeFgHiJ",
  "refresh_token": "rt-9876543210zYxWvUtSrQpO",
  "expires_in": 3600
}`)
	f := ParseCohenMobileOAuth(body)
	if !f.HasOAuth {
		t.Fatal("oauth must flag")
	}
	if f.OAuthToken == "" {
		t.Fatalf("token=%q", f.OAuthToken)
	}
}

func TestParseCohenFCISubscription(t *testing.T) {
	body := []byte(`{
  "tipo": "suscripcion",
  "cuenta_comitente": "12345",
  "fondo": "Cohen Renta Fija",
  "cuotapartes_suscriptas": "250",
  "cliente_cuit": "27-11111111-4"
}`)
	f := ParseCohenFCISubscription(body)
	if f.CuotaparteCount != 250 {
		t.Fatalf("cuotaparte=%d want 250", f.CuotaparteCount)
	}
	if f.CuentaComitente != "12345" {
		t.Fatalf("comitente=%q", f.CuentaComitente)
	}
}

func TestParseCohenLiquidacion(t *testing.T) {
	body := []byte(`Fecha,Cuenta,Especie,Cantidad,Precio,Importe
15/06/2026,12345,GGAL,100,4500.50,450050.00
16/06/2026,12345,YPFD,50,15000.75,750037.50
17/06/2026,12345,AAPL,10,180000.00,1800000.00
`)
	f := ParseCohenLiquidacion(body)
	if f.LiquidacionCount < 3 {
		t.Fatalf("liq count=%d", f.LiquidacionCount)
	}
	if f.AREquitySymbolsCount < 1 {
		t.Fatalf("ar=%d", f.AREquitySymbolsCount)
	}
	if f.CEDEARSymbolsCount < 1 {
		t.Fatalf("cedear=%d", f.CEDEARSymbolsCount)
	}
}

func TestParseCohenFIXSession(t *testing.T) {
	body := []byte(`[SESSION]
BeginString=FIX.4.4
SenderCompID=COHEN_ALYC
TargetCompID=MAE
fix_password=secret123
`)
	f := ParseCohenFIXSession(body)
	if f.FIXSenderCompID != "COHEN_ALYC" {
		t.Fatalf("sender=%q", f.FIXSenderCompID)
	}
	if !f.HasPassword {
		t.Fatal("fix password must flag")
	}
}

func TestDetectBackoffice(t *testing.T) {
	cases := map[string]BackofficeChannel{
		`backoffice=SAGGM Galileo`: BackofficeSAGGMGalileo,
		`backoffice=SAGGM Mariva`:  BackofficeSAGGMMariva,
		`backoffice=Cohen Direct`:  BackofficeCohenDirect,
		`backoffice=Sintesis`:      BackofficeSintesis,
		`# generic`:                BackofficeUnknown,
	}
	for in, want := range cases {
		got := detectBackoffice([]byte(in))
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyAccount(t *testing.T) {
	if got := classifyAccount(Row{HasSAGGMBackoffice: true}); got != AccountComplianceOfficer {
		t.Fatalf("saggm -> compliance, got %q", got)
	}
	if got := classifyAccount(Row{HasInstitutionalClass: true}); got != AccountInstitutionalCliente {
		t.Fatalf("institutional -> institutional-cliente, got %q", got)
	}
	if got := classifyAccount(Row{HasFCISubscription: true}); got != AccountFCICuotapartista {
		t.Fatalf("sub -> fci-cuotapartista, got %q", got)
	}
	if got := classifyAccount(Row{HasCuotaparteRecord: true}); got != AccountFCICuotapartista {
		t.Fatalf("cuotaparte -> fci-cuotapartista, got %q", got)
	}
	if got := classifyAccount(Row{HasFIXSession: true}); got != AccountFIXCounterparty {
		t.Fatalf("fix -> fix-counterparty, got %q", got)
	}
	if got := classifyAccount(Row{HasResearchPDF: true}); got != AccountEquityResearchSubscriber {
		t.Fatalf("research -> equity-research-subscriber, got %q", got)
	}
	if got := classifyAccount(Row{HasOAuthRefreshToken: true}); got != AccountRetailCliente {
		t.Fatalf("oauth -> retail-cliente, got %q", got)
	}
	if got := classifyAccount(Row{HasPasswordInProfile: true}); got != AccountRetailCliente {
		t.Fatalf("password -> retail-cliente, got %q", got)
	}
	if got := classifyAccount(Row{HasLiquidacionPDF: true}); got != AccountRetailCliente {
		t.Fatalf("liquidacion -> retail-cliente, got %q", got)
	}
	if got := classifyAccount(Row{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyProduct(t *testing.T) {
	if got := classifyProduct(Row{AREquitySymbolsCount: 1, CEDEARSymbolsCount: 1}); got != ProductMultiAsset {
		t.Fatalf("ar+cedear -> multi-asset, got %q", got)
	}
	if got := classifyProduct(Row{HasFCISubscription: true}); got != ProductARFCI {
		t.Fatalf("fci -> ar-fci, got %q", got)
	}
	if got := classifyProduct(Row{AREquitySymbolsCount: 1}); got != ProductAREquity {
		t.Fatalf("ar -> ar-equity, got %q", got)
	}
	if got := classifyProduct(Row{CEDEARSymbolsCount: 1}); got != ProductCEDEAR {
		t.Fatalf("cedear -> cedear, got %q", got)
	}
	if got := classifyProduct(Row{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	roaming := filepath.Join(usersBase, "alice", "AppData", "Roaming")
	cnt := filepath.Join(roaming, "Cohen NetTrader")
	mobile := filepath.Join(roaming, "Cohen Mobile")
	am := filepath.Join(roaming, "Cohen AM")
	cohenRoot := filepath.Join(roaming, "Cohen")
	must(t, os.MkdirAll(cnt, 0o755))
	must(t, os.MkdirAll(mobile, 0o755))
	must(t, os.MkdirAll(am, 0o755))
	must(t, os.MkdirAll(cohenRoot, 0o755))

	profilePath := filepath.Join(cnt, "profile.cohen")
	must(t, os.WriteFile(profilePath, []byte(`{
  "username": "alice@example.com",
  "password": "secret123",
  "cuenta_comitente": "12345",
  "backoffice": "SAGGM Galileo",
  "especie": "GGAL",
  "especie2": "AAPL",
  "cliente_cuit": "27-11111111-4"
}`), 0o644))

	oauthPath := filepath.Join(mobile, "oauth_token.json")
	must(t, os.WriteFile(oauthPath, []byte(`{
  "access_token": "Bearer-abcd1234567890aBcDeFgHiJ",
  "refresh_token": "rt-9876543210zYxWvUtSrQpO",
  "expires_in": 3600
}`), 0o644))

	subPath := filepath.Join(am, "suscripcion_15.json")
	must(t, os.WriteFile(subPath, []byte(`{
  "tipo": "suscripcion",
  "cuenta_comitente": "12345",
  "fondo": "Cohen Renta Fija",
  "cuotapartes_suscriptas": "250",
  "cliente_cuit": "27-11111111-4"
}`), 0o644))

	saggmPath := filepath.Join(cohenRoot, "saggm_config.ini")
	must(t, os.WriteFile(saggmPath, []byte(`[BACKOFFICE]
channel=SAGGM Galileo
backoffice_password=adminpass
`), 0o644))

	liqPath := filepath.Join(cohenRoot, "liquidacion_20260615.csv")
	must(t, os.WriteFile(liqPath, []byte(`Fecha,Cuenta,Especie,Cantidad,Precio,Importe
15/06/2026,12345,GGAL,100,4500.50,450050.00
16/06/2026,12345,YPFD,50,15000.75,750037.50
17/06/2026,12345,AAPL,10,180000.00,1800000.00
`), 0o644))

	must(t, os.WriteFile(filepath.Join(cnt, "random.txt"),
		[]byte(`nope`), 0o644))

	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming",
		"Cohen NetTrader")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "profile.cohen"),
		[]byte(`{}`), 0o644))

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
	if len(got) != 5 {
		t.Fatalf("want 5 (profile+oauth+sub+saggm+liq), got %d: %+v", len(got), got)
	}

	var prof, oauth, sub, saggm, liq Row
	for _, r := range got {
		switch r.FilePath {
		case profilePath:
			prof = r
		case oauthPath:
			oauth = r
		case subPath:
			sub = r
		case saggmPath:
			saggm = r
		case liqPath:
			liq = r
		}
	}

	if prof.ArtifactKind != KindProfile {
		t.Fatalf("prof kind=%q", prof.ArtifactKind)
	}
	if !prof.HasPasswordInProfile {
		t.Fatalf("prof must flag password: %+v", prof)
	}
	if prof.BackofficeChannel != BackofficeSAGGMGalileo {
		t.Fatalf("prof backoffice=%q", prof.BackofficeChannel)
	}
	if !prof.HasClienteCuit {
		t.Fatalf("prof must flag cliente cuit: %+v", prof)
	}
	if !prof.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cliente = exposure: %+v", prof)
	}

	if oauth.ArtifactKind != KindMobileOAuth {
		t.Fatalf("oauth kind=%q", oauth.ArtifactKind)
	}
	if !oauth.HasOAuthRefreshToken {
		t.Fatalf("oauth must flag: %+v", oauth)
	}
	if oauth.OAuthTokenHash == "" {
		t.Fatalf("oauth must have hash: %+v", oauth)
	}
	if oauth.AccountClass != AccountRetailCliente {
		t.Fatalf("oauth should classify as retail-cliente, got %q", oauth.AccountClass)
	}

	if sub.ArtifactKind != KindFCISubscription {
		t.Fatalf("sub kind=%q", sub.ArtifactKind)
	}
	if !sub.HasFCISubscription {
		t.Fatalf("sub must flag: %+v", sub)
	}
	if sub.CuotaparteCount != 250 {
		t.Fatalf("sub cuotaparte=%d", sub.CuotaparteCount)
	}
	if sub.AccountClass != AccountFCICuotapartista {
		t.Fatalf("sub should classify as fci-cuotapartista, got %q", sub.AccountClass)
	}

	if saggm.ArtifactKind != KindSAGGMConfig {
		t.Fatalf("saggm kind=%q", saggm.ArtifactKind)
	}
	if !saggm.HasSAGGMBackoffice {
		t.Fatalf("saggm must flag: %+v", saggm)
	}
	if saggm.AccountClass != AccountComplianceOfficer {
		t.Fatalf("saggm should classify as compliance, got %q", saggm.AccountClass)
	}

	if liq.ArtifactKind != KindLiquidacionPDF {
		t.Fatalf("liq kind=%q", liq.ArtifactKind)
	}
	if !liq.HasLiquidacionPDF {
		t.Fatalf("liq must auto-flag: %+v", liq)
	}
	if liq.LiquidacionCount < 3 {
		t.Fatalf("liq count=%d", liq.LiquidacionCount)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-cohen")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "profile.cohen"),
		[]byte(`{"password":"hello"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "COHEN_DIR" {
				return custom
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
	if len(got) != 1 {
		t.Fatalf("want 1 from env-override, got %d", len(got))
	}
	if !got[0].HasPasswordInProfile {
		t.Fatalf("env-override row must flag password")
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-cohen"},
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
	rs := []Row{
		{FilePath: "/b", ArtifactKind: KindProfile},
		{FilePath: "/a", ArtifactKind: KindLiquidacionPDF},
		{FilePath: "/a", ArtifactKind: KindProfile},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindLiquidacionPDF {
		t.Fatalf("sort drift: %+v", rs)
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("abc")
	b := HashSecret("ABC")
	if a != b {
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
