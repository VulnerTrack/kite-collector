package winargbalanz

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "balanz-config"},
		{string(KindCredentials), "balanz-credentials"},
		{string(KindPositionsCache), "balanz-positions-cache"},
		{string(KindOrdersCache), "balanz-orders-cache"},
		{string(KindCaucionCache), "balanz-caucion-cache"},
		{string(KindFCIBalanz), "balanz-fci-balanz"},
		{string(KindONCache), "balanz-on-cache"},
		{string(KindCEDEARCache), "balanz-cedear-cache"},
		{string(KindLetrasCache), "balanz-letras-cache"},
		{string(KindStrategyScript), "balanz-strategy-script"},
		{string(KindAccountExport), "balanz-account-export"},
		{string(KindInstaller), "balanz-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountRetail), "retail"},
		{string(AccountWealth), "wealth"},
		{string(AccountCorporate), "corporate"},
		{string(AccountAPI), "api"},
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
		"balanz_credentials.json",
		"pybalanz_config.yaml",
		"balanz_positions.json",
		"balanz_orders_202506.json",
		"caucion_cache.json",
		"cedear_cache.json",
		"lecap_positions.json",
		"boncer_holdings.json",
		"obligaciones_negociables_2026.csv",
		"fci_balanz_subs.json",
		"balanz_strategy.py",
		"balanz_installer.msi",
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
		"balanz_credentials.json":      KindCredentials,
		"balanz_settings.xml":          KindConfig,
		"pybalanz_config.yaml":         KindConfig,
		"balanz_positions.json":        KindPositionsCache,
		"balanz_orders_202506.json":    KindOrdersCache,
		"balanz_ordenes_202506.json":   KindOrdersCache,
		"caucion_cache.json":           KindCaucionCache,
		"cedear_cache.json":            KindCEDEARCache,
		"lecap_holdings.json":          KindLetrasCache,
		"boncer_holdings.json":         KindLetrasCache,
		"obligaciones_negociables.csv": KindONCache,
		"fci_balanz_subs.json":         KindFCIBalanz,
		"balanz_strategy.py":           KindStrategyScript,
		"balanz_strategy.ipynb":        KindStrategyScript,
		"balanz_extracto_202506.xlsx":  KindAccountExport,
		"balanz_movimientos_2026.csv":  KindAccountExport,
		"balanz_installer.msi":         KindInstaller,
		"":                             KindUnknown,
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
	if PeriodFromFilename("balanz_orders_202506.json") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.json") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsLetraTicker(t *testing.T) {
	yes := []string{
		"S29M6", "S31E6", "TX26", "TC27", "T2X5",
		"LECAP", "BONCER", "BONTE",
	}
	no := []string{"", "GGAL", "YPFD", "DLR"}
	for _, v := range yes {
		if !IsLetraTicker(v) {
			t.Fatalf("expected letra: %q", v)
		}
	}
	for _, v := range no {
		if IsLetraTicker(v) {
			t.Fatalf("expected NOT letra: %q", v)
		}
	}
}

func TestHasCaucionTicker(t *testing.T) {
	yes := [][]byte{
		[]byte(`{"symbol":"PESOS$1D"}`),
		[]byte(`caucion volume = 100000`),
		[]byte(`{"ticker":"DOLAR$7D"}`),
	}
	no := [][]byte{
		[]byte(`{"symbol":"GGAL"}`),
		[]byte(``),
	}
	for _, v := range yes {
		if !HasCaucionTicker(v) {
			t.Fatalf("expected caución: %q", v)
		}
	}
	for _, v := range no {
		if HasCaucionTicker(v) {
			t.Fatalf("expected NOT caución: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindCredentials, KindConfig, KindPositionsCache,
		KindOrdersCache, KindAccountExport,
	}
	no := []ArtifactKind{
		KindCaucionCache, KindFCIBalanz, KindONCache, KindCEDEARCache,
		KindLetrasCache, KindStrategyScript, KindInstaller,
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

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindCredentials,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + cliente = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:        KindCredentials,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateCaucionLetras(t *testing.T) {
	r := Row{
		ArtifactKind:          KindCaucionCache,
		CaucionVolumeARSCents: 500_000_000,
		LetrasPositionCount:   3,
	}
	AnnotateSecurity(&r)
	if !r.HasCaucionActivity {
		t.Fatal("caución volume must flag")
	}
	if !r.HasLetrasTesoro {
		t.Fatal("letras count must flag")
	}
}

func TestParseBalanzCredentials(t *testing.T) {
	body := []byte(`{
  "endpoint": "https://api.balanz.com",
  "access_token": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
  "username": "alice@balanz.com",
  "password": "secret123",
  "cliente_cuit": "27-11111111-4",
  "matricula": 210
}`)
	f := ParseBalanzCredentials(body)
	if f.BearerToken == "" {
		t.Fatal("bearer must extract")
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
	if f.BrokerMatricula != "210" {
		t.Fatalf("matricula=%q", f.BrokerMatricula)
	}
}

func TestParseBalanzPositions(t *testing.T) {
	body := []byte(`{
"positions": [
{ "symbol": "GGAL" },
{ "symbol": "YPFD" },
{ "symbol": "S29M6" },
{ "symbol": "TX26" }
],
"cedear": [
{ "symbol": "AAPL" }
],
"obligaciones_negociables": [
{ "symbol": "YPCUO" }
]
}`)
	f := ParseBalanzPositions(body)
	if f.PortfolioCount < 1 {
		t.Fatalf("portfolio=%d", f.PortfolioCount)
	}
	if f.DistinctSymbols < 5 {
		t.Fatalf("distinct=%d", f.DistinctSymbols)
	}
	if f.LetrasCount < 2 {
		t.Fatalf("letras=%d want >=2", f.LetrasCount)
	}
	if f.CEDEARCount < 1 {
		t.Fatalf("cedear=%d", f.CEDEARCount)
	}
	if f.ONCount < 1 {
		t.Fatalf("on=%d", f.ONCount)
	}
}

func TestParseBalanzCaucion(t *testing.T) {
	body := []byte(`[
{"symbol":"PESOS$1D","caucion_amount":"1500000.50"},
{"symbol":"PESOS$1D","caucion_amount":"2000000.00"},
{"symbol":"DOLAR$7D","caucion_amount":"500000.00"}
]`)
	f := ParseBalanzCaucion(body)
	if f.CaucionVolumeCents != 400_000_050 {
		t.Fatalf("caucion vol=%d want 400_000_050", f.CaucionVolumeCents)
	}
}

func TestParseBalanzCaucionPresenceOnly(t *testing.T) {
	body := []byte(`{"symbol":"PESOS$1D","extra":"data"}`)
	f := ParseBalanzCaucion(body)
	if f.CaucionVolumeCents == 0 {
		t.Fatal("must flag presence-only signal")
	}
}

func TestParseBalanzCEDEAR(t *testing.T) {
	body := []byte(`{"cedear":[
{"symbol":"AAPL"},{"symbol":"MSFT"},{"symbol":"GOOGL"}
]}`)
	f := ParseBalanzCEDEAR(body)
	if f.CEDEARCount < 3 {
		t.Fatalf("cedear=%d", f.CEDEARCount)
	}
}

func TestParseBalanzLetras(t *testing.T) {
	body := []byte(`{"letras":[
{"symbol":"S29M6"},{"symbol":"TX26"},{"symbol":"TC27"}
]}`)
	f := ParseBalanzLetras(body)
	if f.LetrasCount < 3 {
		t.Fatalf("letras=%d", f.LetrasCount)
	}
}

func TestParseBalanzFCI(t *testing.T) {
	body := []byte(`[
{"fci_id":"BALANZ_CAPITAL_AHORRO","fci_name":"Balanz Capital Ahorro"},
{"fci_id":"BALANZ_CAPITAL_RV","fci_name":"Balanz Capital Renta Variable"}
]`)
	f := ParseBalanzFCI(body)
	if f.FCISubscriptionCount < 2 {
		t.Fatalf("fci subs=%d", f.FCISubscriptionCount)
	}
}

func TestParseBalanzStrategy(t *testing.T) {
	body := []byte(`from pybalanz import BalanzClient
client = BalanzClient(username="alice", password="secret123")
`)
	f := ParseBalanzStrategy(body)
	if !f.IsAPI {
		t.Fatal("pybalanz import must flag")
	}
	if !f.HasPassword {
		t.Fatal("hardcoded password must flag")
	}
}

func TestParseBalanzEmpty(t *testing.T) {
	f := ParseBalanzCredentials(nil)
	if f.BearerToken != "" || f.HasPassword {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "Balanz")
	must(t, os.MkdirAll(filepath.Join(dir, "cache"), 0o755))

	credsPath := filepath.Join(dir, "balanz_credentials.json")
	must(t, os.WriteFile(credsPath, []byte(`{
  "endpoint": "https://api.balanz.com",
  "access_token": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
  "username": "alice@balanz.com",
  "cliente_cuit": "27-11111111-4",
  "matricula": 210
}`), 0o644))

	caucionPath := filepath.Join(dir, "cache", "caucion_cache_202506.json")
	must(t, os.WriteFile(caucionPath, []byte(`[
{"symbol":"PESOS$1D","caucion_amount":"5000000.00"},
{"symbol":"DOLAR$7D","caucion_amount":"3000000.00"}
]`), 0o644))

	cedearPath := filepath.Join(dir, "cache", "cedear_cache.json")
	must(t, os.WriteFile(cedearPath, []byte(`{"cedear":[
{"symbol":"AAPL"},{"symbol":"MSFT"}
]}`), 0o644))

	letrasPath := filepath.Join(dir, "cache", "lecap_holdings.json")
	must(t, os.WriteFile(letrasPath, []byte(`{"letras":[
{"symbol":"S29M6"},{"symbol":"TX26"}
]}`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "Balanz")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "balanz_credentials.json"),
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
		t.Fatalf("want 4, got %d: %+v", len(got), got)
	}

	var creds, caucion, cedear, letras Row
	for _, r := range got {
		switch r.FilePath {
		case credsPath:
			creds = r
		case caucionPath:
			caucion = r
		case cedearPath:
			cedear = r
		case letrasPath:
			letras = r
		}
	}

	if creds.ArtifactKind != KindCredentials {
		t.Fatalf("creds kind=%q", creds.ArtifactKind)
	}
	if !creds.HasBearerToken {
		t.Fatalf("creds must flag bearer: %+v", creds)
	}
	if !creds.HasClienteCuit {
		t.Fatalf("creds must flag cliente cuit: %+v", creds)
	}
	if !creds.IsCredentialExposureRisk {
		t.Fatalf("readable + bearer + cliente = exposure: %+v", creds)
	}
	if creds.BrokerMatricula != "210" {
		t.Fatalf("creds matricula=%q", creds.BrokerMatricula)
	}

	if caucion.ArtifactKind != KindCaucionCache {
		t.Fatalf("caucion kind=%q", caucion.ArtifactKind)
	}
	if !caucion.HasCaucionActivity {
		t.Fatalf("caucion must flag activity: %+v", caucion)
	}

	if cedear.ArtifactKind != KindCEDEARCache {
		t.Fatalf("cedear kind=%q", cedear.ArtifactKind)
	}
	if !cedear.HasCEDEARActivity {
		t.Fatalf("cedear must flag activity: %+v", cedear)
	}

	if letras.ArtifactKind != KindLetrasCache {
		t.Fatalf("letras kind=%q", letras.ArtifactKind)
	}
	if !letras.HasLetrasTesoro {
		t.Fatalf("letras must flag tesoro: %+v", letras)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-balanz")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "balanz_credentials.json"),
		[]byte(`{"endpoint":"https://api.balanz.com","access_token":"abcdefghijklmnopqrst"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "BALANZ_DIR" {
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
		installRoots: []string{"/nope-balanz"},
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
		{FilePath: "a", ArtifactKind: KindPositionsCache},
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
	if a != c {
		t.Fatal("hash must be case-insensitive (lowercased+trimmed)")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func TestClassifyAccount(t *testing.T) {
	if classifyAccount(KindCredentials, BalanzFields{IsDemo: true}) != AccountDemo {
		t.Fatal("demo")
	}
	if classifyAccount(KindStrategyScript, BalanzFields{}) != AccountAPI {
		t.Fatal("script -> api")
	}
	if classifyAccount(KindCredentials, BalanzFields{BearerToken: "x"}) != AccountAPI {
		t.Fatal("bearer -> api")
	}
	if classifyAccount(KindCredentials, BalanzFields{Username: "x"}) != AccountRetail {
		t.Fatal("username -> retail")
	}
	if classifyAccount(KindCredentials, BalanzFields{}) != AccountUnknown {
		t.Fatal("unknown")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
