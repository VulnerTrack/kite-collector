package winargbloomberg

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "bbg-config"},
		{string(KindLicense), "bbg-license"},
		{string(KindCredentials), "bbg-credentials"},
		{string(KindSessionLog), "bbg-session-log"},
		{string(KindVaultCache), "bbg-vault-cache"},
		{string(KindBPipeConfig), "bbg-bpipe-config"},
		{string(KindBLPAPIScript), "bbg-blpapi-script"},
		{string(KindExcelAddin), "bbg-excel-addin"},
		{string(KindAIMConfig), "bbg-aim-config"},
		{string(KindAnywhereCert), "bbg-anywhere-cert"},
		{string(KindInstaller), "bbg-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(TierTerminal), "terminal"},
		{string(TierAnywhere), "anywhere"},
		{string(TierBPipe), "bpipe"},
		{string(TierAIM), "aim"},
		{string(TierDataLicense), "data-license"},
		{string(TierOther), "other"},
		{string(TierUnknown), "unknown"},
		{string(ProductMarketData), "market-data"},
		{string(ProductNews), "news"},
		{string(ProductExecutionMgmt), "execution-mgmt"},
		{string(ProductRisk), "risk"},
		{string(ProductPortfolioMgmt), "portfolio-mgmt"},
		{string(ProductFCIAIM), "fci-aim"},
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
		"BBT.cfg",
		"Bloomberg.lic",
		"bbg_credentials.json",
		"bbg_session.log",
		"bloomberg_anywhere.cert",
		"BPipe.cfg",
		"b-pipe_config.xml",
		"aim_portfolio.xml",
		"bbg_aim_config.json",
		"blpapi_script.py",
		"bloomberg_addin.xlam",
		"blp_strategy.py",
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
		"BBT.cfg":                 KindConfig,
		"bbg_settings.json":       KindConfig,
		"Bloomberg.lic":           KindLicense,
		"bbg_credentials.json":    KindCredentials,
		"bbg_session.log":         KindSessionLog,
		"bloomberg_session.txt":   KindSessionLog,
		"BPipe.cfg":               KindBPipeConfig,
		"b-pipe_config.xml":       KindBPipeConfig,
		"aim_portfolio.xml":       KindAIMConfig,
		"bbg_aim_config.json":     KindAIMConfig,
		"blpapi_script.py":        KindBLPAPIScript,
		"bloomberg_quant.ipynb":   KindBLPAPIScript,
		"bbg_strategy.java":       KindBLPAPIScript,
		"bloomberg_addin.xlam":    KindExcelAddin,
		"blp_workbook.xlsm":       KindExcelAddin,
		"vault_cache.json":        KindVaultCache,
		"bloomberg_anywhere.cert": KindAnywhereCert,
		"bbg_installer.msi":       KindInstaller,
		"":                        KindUnknown,
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
	if PeriodFromFilename("bbg_session_202506.log") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.log") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsArgentineBloombergTicker(t *testing.T) {
	yes := []string{
		"GGAL AR", "YPFD AR", "AL30 Govt", "GD30 Govt",
		"BOPREAL Govt", "TX26 Govt", "YPCUO Corp",
	}
	no := []string{"", "AAPL US", "MSFT US", "VALE BZ"}
	for _, v := range yes {
		if !IsArgentineBloombergTicker(v) {
			t.Fatalf("expected AR: %q", v)
		}
	}
	for _, v := range no {
		if IsArgentineBloombergTicker(v) {
			t.Fatalf("expected NOT AR: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindLicense, KindCredentials,
		KindSessionLog, KindVaultCache, KindBPipeConfig,
		KindBLPAPIScript, KindExcelAddin, KindAIMConfig,
		KindAnywhereCert,
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
		ArtifactKind:       KindConfig,
		HasSessionToken:    true,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + session token + cliente = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:    KindConfig,
		HasSessionToken: true,
		FileMode:        0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateLicense(t *testing.T) {
	r := Row{ArtifactKind: KindLicense}
	AnnotateSecurity(&r)
	if !r.HasLicenseFile {
		t.Fatal("license kind must auto-flag")
	}
}

func TestAnnotateBPipe(t *testing.T) {
	r := Row{ArtifactKind: KindBPipeConfig}
	AnnotateSecurity(&r)
	if !r.HasBPipeManagedFeed {
		t.Fatal("bpipe kind must auto-flag")
	}
}

func TestAnnotateAIM(t *testing.T) {
	r := Row{ArtifactKind: KindAIMConfig}
	AnnotateSecurity(&r)
	if !r.HasAIMFCIManager {
		t.Fatal("aim kind must auto-flag")
	}
}

func TestAnnotateBLPAPIScript(t *testing.T) {
	r := Row{ArtifactKind: KindBLPAPIScript}
	AnnotateSecurity(&r)
	if !r.HasBLPAPIScript {
		t.Fatal("blpapi-script kind must auto-flag")
	}
}

func TestAnnotateMultipleSessions(t *testing.T) {
	r := Row{
		ArtifactKind:      KindSessionLog,
		DistinctUserCount: 3,
	}
	AnnotateSecurity(&r)
	if !r.HasMultipleSessions {
		t.Fatal("3 distinct users must flag subscription-sharing")
	}
}

func TestAnnotateArgentineFocus(t *testing.T) {
	r := Row{
		ArtifactKind:          KindBLPAPIScript,
		DistinctARTickerCount: 5,
	}
	AnnotateSecurity(&r)
	if !r.HasArgentineFocus {
		t.Fatal("5 AR tickers must flag AR-focus")
	}
}

func TestParseBloombergConfig(t *testing.T) {
	body := []byte(`[BBT]
BLPUsername=alice@example.com
BLPPassword=secret123
bbg_session_token=aBcDeFgHiJkLmNoPqRsTuVwX12345
license_id=ABC123XYZ789
ticker_1=GGAL AR Equity
ticker_2=AL30 Govt
cliente_cuit=27-11111111-4
`)
	f := ParseBloombergConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.SessionToken == "" {
		t.Fatal("session token must extract")
	}
	if f.LicenseID == "" {
		t.Fatal("license id must extract")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.DistinctARTickers < 2 {
		t.Fatalf("AR tickers=%d want >=2", f.DistinctARTickers)
	}
	if !f.HasArgentineMarkers {
		t.Fatal("AR markers must flag")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseBloombergSessionLogMultiUser(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 login_user: alice@example.com
2026-06-15 10:00:00 bbg session opened
2026-06-15 11:00:00 login_user: bob@example.com
2026-06-15 12:00:00 login_user: carol@example.com
2026-06-15 13:00:00 login_user: alice@example.com
ticker request: GGAL AR Equity
ticker request: AL30 Govt
ticker request: GD30 Govt
ticker request: YPFD AR Equity
`)
	f := ParseBloombergSessionLog(body)
	if f.DistinctUsers != 3 {
		t.Fatalf("distinct users=%d want 3", f.DistinctUsers)
	}
	if f.DistinctARTickers < 4 {
		t.Fatalf("AR tickers=%d want >=4", f.DistinctARTickers)
	}
}

func TestParseBloombergBLPAPIScript(t *testing.T) {
	body := []byte(`import blpapi
session = blpapi.Session()
session.start()
ticker = "GGAL AR Equity"
password = "hardcoded123"
`)
	f := ParseBloombergBLPAPIScript(body)
	if !f.HasBLPAPIImport {
		t.Fatal("blpapi import must flag")
	}
	if !f.HasPassword {
		t.Fatal("hardcoded password must flag")
	}
	if !f.HasArgentineMarkers {
		t.Fatal("GGAL AR must flag AR")
	}
}

func TestParseBloombergExcelAddin(t *testing.T) {
	body := []byte(`<sheet>
<cell formula="=BDP(\"GGAL AR Equity\", \"PX_LAST\")"/>
<cell formula="=BDH(\"AL30 Govt\", \"PX_LAST\", \"20260101\", \"20260615\")"/>
<cell formula="=BDS(\"BMA AR Equity\", \"DVD_HIST\")"/>
</sheet>`)
	f := ParseBloombergExcelAddin(body)
	if !f.HasExcelBLPFormula {
		t.Fatal("BDP/BDH must flag")
	}
	if f.DistinctARTickers < 3 {
		t.Fatalf("AR tickers=%d want >=3", f.DistinctARTickers)
	}
}

func TestParseBloombergLicense(t *testing.T) {
	body := []byte(`[License]
license_id=ACME-CORP-12345
customer_id=ABC123XYZ
BLPUsername=alice@example.com
`)
	f := ParseBloombergLicense(body)
	if f.LicenseID == "" {
		t.Fatal("license id must extract")
	}
}

func TestParseBloombergEmpty(t *testing.T) {
	f := ParseBloombergConfig(nil)
	if f.HasPassword || f.SessionToken != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "Bloomberg")
	must(t, os.MkdirAll(filepath.Join(dir, "AIM"), 0o755))

	cfgPath := filepath.Join(dir, "BBT.cfg")
	must(t, os.WriteFile(cfgPath, []byte(`[BBT]
BLPUsername=alice@example.com
BLPPassword=secret123
bbg_session_token=aBcDeFgHiJkLmNoPqRsTuVwX12345
ticker_1=GGAL AR Equity
ticker_2=AL30 Govt
ticker_3=YPFD AR Equity
ticker_4=BMA AR Equity
cliente_cuit=27-11111111-4
`), 0o644))

	licPath := filepath.Join(dir, "Bloomberg.lic")
	must(t, os.WriteFile(licPath, []byte(`license_id=ACME-CORP-12345
BLPUsername=alice@example.com
`), 0o644))

	aimPath := filepath.Join(dir, "AIM", "aim_portfolio.xml")
	must(t, os.WriteFile(aimPath, []byte(`<portfolio name="FCI Argentino Cobertura">
<position ticker="AL30 Govt" weight="0.3"/>
<position ticker="GD30 Govt" weight="0.2"/>
</portfolio>`), 0o644))

	stratPath := filepath.Join(usersBase, "alice", "projects", "blpapi", "blpapi_strategy.py")
	must(t, os.MkdirAll(filepath.Dir(stratPath), 0o755))
	must(t, os.WriteFile(stratPath, []byte(`import blpapi
session = blpapi.Session()
ticker = "GGAL AR Equity"
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "Bloomberg")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "BBT.cfg"),
		[]byte(`x`), 0o644))

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
		t.Fatalf("want 4 (cfg+lic+aim+strat), got %d: %+v", len(got), got)
	}

	var cfg, lic, aim, strat Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case licPath:
			lic = r
		case aimPath:
			aim = r
		case stratPath:
			strat = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if !cfg.HasSessionToken {
		t.Fatalf("cfg must flag session: %+v", cfg)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.HasArgentineFocus {
		t.Fatalf("cfg must flag AR focus: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + session + cuit = exposure: %+v", cfg)
	}

	if lic.ArtifactKind != KindLicense {
		t.Fatalf("lic kind=%q", lic.ArtifactKind)
	}
	if !lic.HasLicenseFile {
		t.Fatalf("lic must flag: %+v", lic)
	}
	if lic.SubscriptionTier != TierTerminal {
		t.Fatalf("lic tier=%q want terminal", lic.SubscriptionTier)
	}

	if aim.ArtifactKind != KindAIMConfig {
		t.Fatalf("aim kind=%q", aim.ArtifactKind)
	}
	if !aim.HasAIMFCIManager {
		t.Fatalf("aim must flag: %+v", aim)
	}
	if aim.SubscriptionTier != TierAIM {
		t.Fatalf("aim tier=%q want aim", aim.SubscriptionTier)
	}
	if aim.ProductClass != ProductFCIAIM {
		t.Fatalf("aim product=%q want fci-aim", aim.ProductClass)
	}

	if strat.ArtifactKind != KindBLPAPIScript {
		t.Fatalf("strat kind=%q", strat.ArtifactKind)
	}
	if !strat.HasBLPAPIScript {
		t.Fatalf("strat must flag: %+v", strat)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-bbg")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "BBT.cfg"),
		[]byte(`BLPUsername=alice@example.com`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "BLOOMBERG_DIR" {
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
		installRoots: []string{"/nope-bbg"},
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
		{FilePath: "a", ArtifactKind: KindLicense},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	// At "a": "bbg-config" < "bbg-license" alphabetically.
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,bbg-config)", in[0])
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
