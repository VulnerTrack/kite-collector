package winargprimary

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

// -- enum strings pinned to host_arg_primary_api CHECK constraints -

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindCredentialsJSON), "primary-credentials-json"},
		{string(KindPyRofexConfig), "primary-pyrofex-config"},
		{string(KindWSSubscriptions), "primary-ws-subscriptions"},
		{string(KindOrderAudit), "primary-order-audit"},
		{string(KindInstrumentCache), "primary-instrument-cache"},
		{string(KindStrategyScript), "primary-strategy-script"},
		{string(KindBacktestHistory), "primary-backtest-history"},
		{string(KindTokenCache), "primary-token-cache"},
		{string(KindInstaller), "primary-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(EnvRemarkets), "remarkets"},
		{string(EnvProduction), "production"},
		{string(EnvDemo), "demo"},
		{string(EnvOther), "other"},
		{string(EnvUnknown), "unknown"},
		{string(BrokerCocos), "cocos"},
		{string(BrokerIOL), "iol"},
		{string(BrokerBalanz), "balanz"},
		{string(BrokerPPI), "ppi"},
		{string(BrokerBullMarket), "bullmarket"},
		{string(BrokerAllaria), "allaria"},
		{string(BrokerComafi), "comafi"},
		{string(BrokerDirect), "direct"},
		{string(BrokerOther), "other"},
		{string(BrokerUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHighFrequencyConst(t *testing.T) {
	if HighFrequencyOrdersPerMinute != 100 {
		t.Fatalf("HighFrequencyOrdersPerMinute=%d", HighFrequencyOrdersPerMinute)
	}
}

func TestHashers(t *testing.T) {
	if len(HashContents([]byte("x"))) != 64 {
		t.Fatal("HashContents 64-hex")
	}
	if HashSecret("token") == "token" || len(HashSecret("token")) != 64 {
		t.Fatal("HashSecret must hash")
	}
}

func TestDefaultPathSets(t *testing.T) {
	if len(DefaultInstallRoots()) == 0 || len(UserPrimaryDirs()) == 0 {
		t.Fatal("path sets empty")
	}
	if len(DefaultUsersBases()) != 3 {
		t.Fatalf("users bases=%d", len(DefaultUsersBases()))
	}
}

func TestIsCandidateExt(t *testing.T) {
	yes := []string{
		"x.json", "x.ini", "x.cfg", "x.conf", "x.yaml",
		"x.yml", "x.toml", "x.py", "x.ipynb", "x.log", "x.txt",
		"x.csv", "x.tsv", "x.parquet", "x.msi", "x.exe",
		"refresh_token", "access_token", "primary_token",
	}
	no := []string{"x.md", "randomfile", "x.png"}
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
		"refresh_token", "access_token", "primary_token",
		"strategy_pyrofex.py", "backtest_primary.ipynb",
		"credentials.json", "instruments.json", "ws_state.json",
		"orders_2025.csv", "rofex_config.ini", "pyrofex.yaml",
	}
	no := []string{"", "myscript.py", "notebook.ipynb", "random.json"}
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
		"":                         KindUnknown,
		"refresh_token":            KindTokenCache,
		"access_token":             KindTokenCache,
		"primary_token":            KindTokenCache,
		"primary_setup.msi":        KindInstaller,
		"randomsetup.exe":          KindOther,
		"strategy_pyrofex.py":      KindStrategyScript,
		"analysis.ipynb":           KindStrategyScript,
		"backtest_history.parquet": KindBacktestHistory,
		"data.parquet":             KindOther,
		"credentials.json":         KindCredentialsJSON,
		"pyrofex.ini":              KindPyRofexConfig,
		"primary.yaml":             KindPyRofexConfig,
		"ws_state.json":            KindWSSubscriptions,
		"orders.log":               KindOrderAudit,
		"orders_2025.csv":          KindOrderAudit,
		"instruments.json":         KindInstrumentCache,
		"backtest_2025.txt":        KindBacktestHistory,
		"history.txt":              KindBacktestHistory,
		"notes.txt":                KindOther,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEnvironmentFromBody(t *testing.T) {
	cases := map[string]Environment{
		"host=api.remarkets.primary.com.ar": EnvRemarkets,
		"host=demo.primary.com.ar":          EnvDemo,
		"host=api.primary.com.ar":           EnvProduction,
		"host=example.com":                  EnvUnknown,
		"":                                  EnvUnknown,
	}
	for in, want := range cases {
		if got := EnvironmentFromBody([]byte(in)); got != want {
			t.Fatalf("EnvironmentFromBody(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBrokerRouteFromBody(t *testing.T) {
	cases := map[string]BrokerRoute{
		"url=cocos.capital":      BrokerCocos,
		"url=invertironline":     BrokerIOL,
		"url=balanz.com":         BrokerBalanz,
		"url=portfoliopersonal":  BrokerPPI,
		"url=bullmarket":         BrokerBullMarket,
		"url=allaria":            BrokerAllaria,
		"url=comafi.com.ar":      BrokerComafi,
		"url=api.primary.com.ar": BrokerDirect,
		"url=example.com":        BrokerUnknown,
		"":                       BrokerUnknown,
	}
	for in, want := range cases {
		if got := BrokerRouteFromBody([]byte(in)); got != want {
			t.Fatalf("BrokerRouteFromBody(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	p, s := CuitFingerprint("cuit 24-99887766-1 x")
	if p != "24" || s != "7661" {
		t.Fatalf("fingerprint=(%q,%q) want (24,7661)", p, s)
	}
	if p, _ := CuitFingerprint("11-22334455-6"); p != "" {
		t.Fatal("invalid prefix must be rejected")
	}
	if len(CuitEntityPrefixes()) != 7 || IsValidCuitEntityPrefix("00") {
		t.Fatal("cuit prefix set")
	}
}

func TestAccountSuffix4(t *testing.T) {
	cases := map[string]string{
		"cuenta: 12345678":  "5678",
		"account = 1234":    "1234",
		"account=12":        "", // fewer than 4 digits
		"comitente: 987654": "7654",
		"no account here":   "",
	}
	for in, want := range cases {
		if got := AccountSuffix4(in); got != want {
			t.Fatalf("AccountSuffix4(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if got := PeriodFromFilename("orders_202503.log"); got != "202503" {
		t.Fatalf("period=%q", got)
	}
	if got := PeriodFromFilename("orders.log"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{KindCredentialsJSON, KindPyRofexConfig, KindTokenCache}
	no := []ArtifactKind{
		KindWSSubscriptions, KindOrderAudit, KindInstrumentCache,
		KindStrategyScript, KindBacktestHistory, KindInstaller, KindOther, KindUnknown,
	}
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
		ClienteCuitPrefix:     "20",
		HasBearerToken:        true,
		HasProductionEndpoint: true,
		OrderPerMinuteMax:     150,
	}
	AnnotateSecurity(&r)
	if !r.IsWorldReadable || !r.IsGroupReadable {
		t.Fatal("0o644 world+group readable")
	}
	if !r.HasClienteCuit {
		t.Fatal("cuit prefix must set HasClienteCuit")
	}
	if !r.IsHighFrequency {
		t.Fatal("150 orders/min must flag HFT")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + bearer + production = exposure: %+v", r)
	}
}

func TestAnnotateSecurityNoProductionNoExposure(t *testing.T) {
	r := Row{FileMode: 0o644, HasBearerToken: true, HasProductionEndpoint: false}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("no production endpoint must NOT flag exposure")
	}
}

func TestAnnotateSecurityHFTBoundary(t *testing.T) {
	below := Row{OrderPerMinuteMax: HighFrequencyOrdersPerMinute - 1}
	AnnotateSecurity(&below)
	if below.IsHighFrequency {
		t.Fatal("below threshold must NOT flag HFT")
	}
	at := Row{OrderPerMinuteMax: HighFrequencyOrdersPerMinute}
	AnnotateSecurity(&at)
	if !at.IsHighFrequency {
		t.Fatal("at threshold must flag HFT")
	}
}

func TestAnnotateSecurityLockedDown(t *testing.T) {
	r := Row{FileMode: 0o600, HasBearerToken: true, HasProductionEndpoint: true}
	AnnotateSecurity(&r)
	if r.IsWorldReadable || r.IsGroupReadable {
		t.Fatal("0o600 not readable")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- parser -------------------------------------------------------

func TestParsePrimaryConfigINI(t *testing.T) {
	body := []byte(strings.Join([]string{
		"access_token = BEARERTOKENabcdefghij01234567",
		"refresh_token = REFRESHTOKENabcdefghij01234567",
		"password = secretpw",
		"cuenta_comitente = 987654",
		"cuit = 20-12345678-9",
	}, "\n"))
	f := ParsePrimaryConfig(body)
	if f.BearerToken != "BEARERTOKENabcdefghij01234567" {
		t.Fatalf("bearer=%q", f.BearerToken)
	}
	if f.RefreshToken != "REFRESHTOKENabcdefghij01234567" {
		t.Fatalf("refresh=%q", f.RefreshToken)
	}
	if !f.HasPassword {
		t.Fatal("password must be detected")
	}
	if f.AccountID != "987654" {
		t.Fatalf("account id=%q", f.AccountID)
	}
	if f.ClienteCuitRaw != "20123456789" {
		t.Fatalf("cuit raw=%q", f.ClienteCuitRaw)
	}
}

func TestParsePrimaryConfigBearerPrefix(t *testing.T) {
	// Exercises the "Bearer <token>" alternative (capture group 5).
	f := ParsePrimaryConfig([]byte("auth_token: Bearer ABCDEFGHIJ0123456789xy"))
	if f.BearerToken != "ABCDEFGHIJ0123456789xy" {
		t.Fatalf("bearer=%q", f.BearerToken)
	}
}

func TestParsePrimaryConfigEmpty(t *testing.T) {
	if f := ParsePrimaryConfig(nil); f.BearerToken != "" || f.HasPassword {
		t.Fatalf("empty config non-zero: %+v", f)
	}
}

func TestParsePrimaryTokenCache(t *testing.T) {
	f := ParsePrimaryTokenCache([]byte("  REFRESHTOKENabcdefghij01234567  \n"))
	if f.RefreshToken != "REFRESHTOKENabcdefghij01234567" {
		t.Fatalf("token=%q", f.RefreshToken)
	}
	// Short bodies (< 20 chars) are not treated as tokens.
	if f := ParsePrimaryTokenCache([]byte("short")); f.RefreshToken != "" {
		t.Fatalf("short token=%q", f.RefreshToken)
	}
}

func TestParsePrimaryOrderAudit(t *testing.T) {
	body := []byte(strings.Join([]string{
		"2025-03-10 11:30 new_order notional=1000,00",
		"2025-03-10 11:30 new_order notional=2000,50",
		"2025-03-10 11:31 new_order notional=500,00",
	}, "\n"))
	f := ParsePrimaryOrderAudit(body)
	if f.OrderCount != 3 {
		t.Fatalf("order count=%d want 3", f.OrderCount)
	}
	if f.OrderPerMinMax != 2 {
		t.Fatalf("peak orders/min=%d want 2", f.OrderPerMinMax)
	}
	if f.SessionFirstSeen != "2025-03-10 11:30" {
		t.Fatalf("first seen=%q", f.SessionFirstSeen)
	}
	if f.SessionLastSeen != "2025-03-10 11:31" {
		t.Fatalf("last seen=%q", f.SessionLastSeen)
	}
	if f.MaxNotionalCents != 200050 {
		t.Fatalf("max notional=%d want 200050", f.MaxNotionalCents)
	}
	if f := ParsePrimaryOrderAudit(nil); f.OrderCount != 0 {
		t.Fatal("empty order audit must be zero")
	}
}

func TestParsePrimaryWSState(t *testing.T) {
	f := ParsePrimaryWSState([]byte(`{"subscription":"md","topic":"AL30","subscribe":"x"}`))
	if f.WSSubCount != 3 {
		t.Fatalf("ws sub count=%d want 3", f.WSSubCount)
	}
	if f := ParsePrimaryWSState(nil); f.WSSubCount != 0 {
		t.Fatal("empty ws state must be zero")
	}
}

func TestParsePrimaryInstrumentCache(t *testing.T) {
	f := ParsePrimaryInstrumentCache([]byte(`{"symbol":"AL30","ticker":"GD30","instrument_id":"MERV"}`))
	if f.InstrumentCount != 3 {
		t.Fatalf("instrument count=%d want 3", f.InstrumentCount)
	}
	if f := ParsePrimaryInstrumentCache(nil); f.InstrumentCount != 0 {
		t.Fatal("empty instrument cache must be zero")
	}
}

func TestParsePrimaryStrategy(t *testing.T) {
	if f := ParsePrimaryStrategy([]byte("import pyRofex\nx = 1\n")); !f.HasStrategyImport {
		t.Fatal("import pyRofex must be detected")
	}
	if f := ParsePrimaryStrategy([]byte("from pyrofex import x\n")); !f.HasStrategyImport {
		t.Fatal("lowercase pyrofex import must be detected")
	}
	if f := ParsePrimaryStrategy([]byte("import numpy\n")); f.HasStrategyImport {
		t.Fatal("non-pyrofex import must NOT flag")
	}
	if f := ParsePrimaryStrategy(nil); f.HasStrategyImport {
		t.Fatal("empty strategy must be zero")
	}
}

func TestDecimalToCents(t *testing.T) {
	cases := map[string]int64{
		"1.234,56": 123456,
		"1234.56":  123456,
		"1000":     100000,
		"":         0,
		"abc":      0,
		"0":        0,
		"-5":       0,
	}
	for in, want := range cases {
		if got := decimalToCents(in); got != want {
			t.Fatalf("decimalToCents(%q)=%d want %d", in, got, want)
		}
	}
}

func TestSortRowsDeterministic(t *testing.T) {
	in := []Row{
		{FilePath: "z", ArtifactKind: KindOrderAudit},
		{FilePath: "a", ArtifactKind: KindTokenCache},
		{FilePath: "a", ArtifactKind: KindCredentialsJSON},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindCredentialsJSON {
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
	if isSystemPseudoProfile("carol") {
		t.Fatal("carol is real")
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
	if NewCollector().Name() != "winargprimary" {
		t.Fatal("collector name")
	}
}

func TestCollectorWalksInstallTree(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Primary")
	must(t, os.MkdirAll(root, 0o755))

	credPath := filepath.Join(root, "credentials.json")
	must(t, os.WriteFile(credPath, []byte(
		`{"access_token":"BEARERTOKENabcdefghij01234567","endpoint":"https://api.primary.com.ar/v1"}`), 0o644))

	// Orders audit with > 100 orders in one minute → high-frequency.
	var ord strings.Builder
	for i := 0; i < 150; i++ {
		ord.WriteString("2025-03-10 11:30 new_order notional=100,00\n")
	}
	ordPath := filepath.Join(root, "orders_202503.log")
	must(t, os.WriteFile(ordPath, []byte(ord.String()), 0o644))

	tokPath := filepath.Join(root, "access_token")
	must(t, os.WriteFile(tokPath, []byte("REFRESHTOKENabcdefghij01234567"), 0o644))

	pyPath := filepath.Join(root, "strategy_pyrofex.py")
	must(t, os.WriteFile(pyPath, []byte("import pyRofex\nprint('hi')\n"), 0o644))

	// Parquet is skip-body (hash only); needs a candidate name.
	pqPath := filepath.Join(root, "backtest_history_primary.parquet")
	must(t, os.WriteFile(pqPath, []byte("PAR1binary"), 0o644))

	// Ignored: not a candidate name.
	must(t, os.WriteFile(filepath.Join(root, "readme.md"), []byte("noise"), 0o644))

	c := newTestCollector([]string{root}, nil, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("want 5 rows, got %d: %v", len(got), paths(got))
	}

	byPath := map[string]Row{}
	for _, r := range got {
		byPath[r.FilePath] = r
	}

	cred := byPath[credPath]
	if cred.ArtifactKind != KindCredentialsJSON {
		t.Fatalf("cred kind=%q", cred.ArtifactKind)
	}
	if !cred.HasBearerToken || cred.BearerTokenHash == "" {
		t.Fatalf("cred must flag bearer: %+v", cred)
	}
	if cred.Environment != EnvProduction || !cred.HasProductionEndpoint {
		t.Fatalf("cred env=%q production=%v", cred.Environment, cred.HasProductionEndpoint)
	}
	if cred.BrokerRoute != BrokerDirect {
		t.Fatalf("cred broker=%q want direct", cred.BrokerRoute)
	}
	if !cred.IsCredentialExposureRisk {
		t.Fatalf("readable + bearer + production = exposure: %+v", cred)
	}

	ordRow := byPath[ordPath]
	if ordRow.ArtifactKind != KindOrderAudit {
		t.Fatalf("orders kind=%q", ordRow.ArtifactKind)
	}
	if ordRow.OrderCount != 150 {
		t.Fatalf("order count=%d want 150", ordRow.OrderCount)
	}
	if ordRow.OrderPerMinuteMax != 150 || !ordRow.IsHighFrequency {
		t.Fatalf("orders/min=%d hft=%v", ordRow.OrderPerMinuteMax, ordRow.IsHighFrequency)
	}
	if ordRow.PeriodYYYYMM != "202503" {
		t.Fatalf("orders period=%q", ordRow.PeriodYYYYMM)
	}

	tok := byPath[tokPath]
	if tok.ArtifactKind != KindTokenCache || !tok.HasRefreshToken {
		t.Fatalf("token kind/flag: %+v", tok)
	}
	if tok.RefreshTokenHash == "" {
		t.Fatal("token cache must hash the refresh token")
	}

	py := byPath[pyPath]
	if py.ArtifactKind != KindStrategyScript || !py.HasStrategyScript {
		t.Fatalf("py kind/flag: %+v", py)
	}

	pq := byPath[pqPath]
	if pq.ArtifactKind != KindBacktestHistory {
		t.Fatalf("parquet kind=%q", pq.ArtifactKind)
	}
	if pq.FileHash == "" {
		t.Fatal("parquet skip-body path should still hash")
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-primary")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "pyrofex.ini"),
		[]byte("access_token = BEARERTOKENabcdefghij01234567\n"), 0o644))

	c := newTestCollector(nil, nil, func(k string) string {
		if k == "PRIMARY_DIR" {
			return envDir
		}
		return ""
	})
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || got[0].ArtifactKind != KindPyRofexConfig {
		t.Fatalf("env override: %v", got)
	}
	if !got[0].HasBearerToken {
		t.Fatalf("pyrofex config must flag bearer: %+v", got[0])
	}
}

func TestCollectorWalksUserProfiles(t *testing.T) {
	tmp := t.TempDir()
	base := filepath.Join(tmp, "home")

	aliceDir := filepath.Join(base, "alice", ".primary")
	must(t, os.MkdirAll(aliceDir, 0o755))
	alicePath := filepath.Join(aliceDir, "credentials.json")
	must(t, os.WriteFile(alicePath, []byte(
		`{"access_token":"BEARERTOKENabcdefghij01234567","host":"api.remarkets.primary.com.ar"}`), 0o644))

	pubDir := filepath.Join(base, "Public", ".primary")
	must(t, os.MkdirAll(pubDir, 0o755))
	must(t, os.WriteFile(filepath.Join(pubDir, "credentials.json"), []byte("{}"), 0o644))

	c := newTestCollector(nil, []string{base}, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || got[0].FilePath != alicePath {
		t.Fatalf("want alice cred only, got %v", paths(got))
	}
	if got[0].UserProfile != "alice" {
		t.Fatalf("user profile=%q", got[0].UserProfile)
	}
	if got[0].Environment != EnvRemarkets {
		t.Fatalf("alice env=%q want remarkets", got[0].Environment)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := newTestCollector([]string{"/nope-primary"}, []string{"/nope-users"}, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestPeakOrdersPerMinuteStress(t *testing.T) {
	var sb strings.Builder
	// 3000 orders spread across three minutes, 1000 each.
	for m := 30; m < 33; m++ {
		for i := 0; i < 1000; i++ {
			fmt.Fprintf(&sb, "2025-03-10 11:%02d new_order\n", m)
		}
	}
	f := ParsePrimaryOrderAudit([]byte(sb.String()))
	if f.OrderCount != 3000 {
		t.Fatalf("order count=%d want 3000", f.OrderCount)
	}
	if f.OrderPerMinMax != 1000 {
		t.Fatalf("peak orders/min=%d want 1000", f.OrderPerMinMax)
	}
}

func paths(rs []Row) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.FilePath
	}
	return out
}
