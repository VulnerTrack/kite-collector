package winargrefinitiv

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "eikon-config"},
		{string(KindCredentials), "eikon-credentials"},
		{string(KindLicense), "eikon-license"},
		{string(KindSessionLog), "eikon-session-log"},
		{string(KindLSEGWorkspaceCfg), "lseg-workspace-config"},
		{string(KindDatastreamConfig), "datastream-config"},
		{string(KindWorldCheckConfig), "world-check-config"},
		{string(KindPythonSDK), "eikon-python-sdk"},
		{string(KindExcelAddin), "eikon-excel-addin"},
		{string(KindInstaller), "refinitiv-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(TierEikon), "eikon"},
		{string(TierEikonPlus), "eikon-plus"},
		{string(TierLSEGWorkspace), "lseg-workspace"},
		{string(TierDatastream), "datastream"},
		{string(TierWorldCheck), "world-check"},
		{string(TierDataLicense), "data-license"},
		{string(TierOther), "other"},
		{string(TierUnknown), "unknown"},
		{string(ProductMarketData), "market-data"},
		{string(ProductNewsMachineReadable), "news-machine-readable"},
		{string(ProductRisk), "risk"},
		{string(ProductPortfolioMgmt), "portfolio-mgmt"},
		{string(ProductAMLKYCWorldCheck), "aml-kyc-world-check"},
		{string(ProductHistoricalData), "historical-data"},
		{string(ProductFCIPortfolio), "fci-portfolio"},
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
		"eikon_config.xml",
		"eikon.lic",
		"refinitiv_credentials.json",
		"eikon_session.log",
		"lseg_workspace.cfg",
		"datastream_config.xml",
		"world_check_config.json",
		"refinitiv_data_script.py",
		"eikon_addin.xlam",
		"refinitiv_installer.msi",
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
		"eikon_config.xml":         KindConfig,
		"refinitiv_settings.json":  KindConfig,
		"eikon.lic":                KindLicense,
		"eikon_credentials.json":   KindCredentials,
		"eikon_session.log":        KindSessionLog,
		"refinitiv_session.txt":    KindSessionLog,
		"lseg_workspace.cfg":       KindLSEGWorkspaceCfg,
		"datastream_config.xml":    KindDatastreamConfig,
		"dws.json":                 KindDatastreamConfig,
		"world_check_config.json":  KindWorldCheckConfig,
		"refinitiv_data_script.py": KindPythonSDK,
		"eikon_quant.ipynb":        KindPythonSDK,
		"eikon_addin.xlam":         KindExcelAddin,
		"refinitiv_addin.xlsm":     KindExcelAddin,
		"refinitiv_installer.msi":  KindInstaller,
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
	if PeriodFromFilename("eikon_session_202506.log") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.log") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsArgentineRefinitivTicker(t *testing.T) {
	yes := []string{
		"GGAL.BA", "YPFD.BA", "BMA.BA",
		"ARAL30=", "ARGD30=", "ARBOPREAL=", "ARTX26=",
	}
	no := []string{"", "AAPL.OQ", "MSFT.OQ", "VALE.BZ"}
	for _, v := range yes {
		if !IsArgentineRefinitivTicker(v) {
			t.Fatalf("expected AR: %q", v)
		}
	}
	for _, v := range no {
		if IsArgentineRefinitivTicker(v) {
			t.Fatalf("expected NOT AR: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindLicense, KindSessionLog,
		KindLSEGWorkspaceCfg, KindDatastreamConfig,
		KindWorldCheckConfig, KindPythonSDK, KindExcelAddin,
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
		t.Fatal("readable + session + cliente = exposure")
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

func TestAnnotateDatastream(t *testing.T) {
	r := Row{ArtifactKind: KindDatastreamConfig}
	AnnotateSecurity(&r)
	if !r.HasDatastreamSubscription {
		t.Fatal("datastream kind must auto-flag")
	}
}

func TestAnnotateWorldCheck(t *testing.T) {
	r := Row{ArtifactKind: KindWorldCheckConfig}
	AnnotateSecurity(&r)
	if !r.HasWorldCheckScreening {
		t.Fatal("world-check kind must auto-flag")
	}
}

func TestAnnotateLSEGRebrand(t *testing.T) {
	r := Row{ArtifactKind: KindLSEGWorkspaceCfg}
	AnnotateSecurity(&r)
	if !r.HasLSEGWorkspaceRebrand {
		t.Fatal("LSEG kind must auto-flag")
	}
}

func TestAnnotateExcelAndPython(t *testing.T) {
	r := Row{ArtifactKind: KindExcelAddin}
	AnnotateSecurity(&r)
	if !r.HasExcelEikonAddin {
		t.Fatal("excel kind must auto-flag")
	}
	r2 := Row{ArtifactKind: KindPythonSDK}
	AnnotateSecurity(&r2)
	if !r2.HasPythonSDK {
		t.Fatal("python kind must auto-flag")
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
		ArtifactKind:          KindPythonSDK,
		DistinctARTickerCount: 5,
	}
	AnnotateSecurity(&r)
	if !r.HasArgentineFocus {
		t.Fatal("5 AR tickers must flag AR-focus")
	}
}

func TestParseRefinitivConfig(t *testing.T) {
	body := []byte(`[Eikon]
eikon_username=alice@example.com
eikon_password=secret123
eikon_token=aBcDeFgHiJkLmNoPqRsTuVwX12345
license_id=REF-CORP-2024-001
ticker_1=GGAL.BA
ticker_2=ARAL30=
ticker_3=YPFD.BA
cliente_cuit=27-11111111-4
`)
	f := ParseRefinitivConfig(body)
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

func TestParseRefinitivSessionLogMultiUser(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 login_user: alice@example.com
2026-06-15 10:00:00 eikon session opened
2026-06-15 11:00:00 login_user: bob@example.com
2026-06-15 12:00:00 login_user: carol@example.com
2026-06-15 13:00:00 login_user: alice@example.com
ric_request: GGAL.BA
ric_request: ARAL30=
ric_request: ARGD30=
ric_request: YPFD.BA
`)
	f := ParseRefinitivSessionLog(body)
	if f.DistinctUsers != 3 {
		t.Fatalf("distinct users=%d want 3", f.DistinctUsers)
	}
	if f.DistinctARTickers < 4 {
		t.Fatalf("AR tickers=%d want >=4", f.DistinctARTickers)
	}
}

func TestParseRefinitivPythonSDK(t *testing.T) {
	body := []byte(`import refinitiv.data as rd
session = rd.session.platform.Definition(app_key="aBcDeFgHiJkLmNoPqRsTuVwX12345").get_session()
ticker = "GGAL.BA"
password = "hardcoded123"
`)
	f := ParseRefinitivPythonSDK(body)
	if !f.HasPythonSDKImport {
		t.Fatal("refinitiv import must flag")
	}
	if !f.HasPassword {
		t.Fatal("hardcoded password must flag")
	}
	if !f.HasArgentineMarkers {
		t.Fatal("GGAL.BA must flag AR")
	}
}

func TestParseRefinitivExcelAddin(t *testing.T) {
	body := []byte(`<sheet>
<cell formula="=TR(\"GGAL.BA\", \"PX_LAST\")"/>
<cell formula="=RData(\"ARAL30=\", \"PX_LAST\")"/>
<cell formula="=RHistory(\"BMA.BA\", \"TR.PriceClose\", \"20260101\", \"20260615\")"/>
</sheet>`)
	f := ParseRefinitivExcelAddin(body)
	if !f.HasExcelTRFormula {
		t.Fatal("TR/RData/RHistory must flag")
	}
	if f.DistinctARTickers < 3 {
		t.Fatalf("AR tickers=%d want >=3", f.DistinctARTickers)
	}
}

func TestParseWorldCheckConfig(t *testing.T) {
	body := []byte(`[WorldCheck]
api_key=wcSecretAbCdEfGhIjKlMnOpQrStUv
aml_screening=true
pep_screening=true
sanctions_screening=true
`)
	f := ParseWorldCheckConfig(body)
	if !f.HasWorldCheckMarker {
		t.Fatal("world-check marker must flag")
	}
}

func TestParseDatastreamConfig(t *testing.T) {
	body := []byte(`[Datastream]
dws_username=alice@example.com
dws_password=hardcoded
RHistory=2010..2026
tick_history=true
`)
	f := ParseDatastreamConfig(body)
	if !f.HasDatastreamMarker {
		t.Fatal("datastream marker must flag")
	}
}

func TestParseLSEGWorkspaceConfig(t *testing.T) {
	body := []byte(`[LSEG]
workspace_2024=true
lseg_rebrand=enabled
lseg_workspace_endpoint=https://workspace.lseg.com
`)
	f := ParseLSEGWorkspaceConfig(body)
	if !f.HasLSEGRebrandMarker {
		t.Fatal("LSEG rebrand must flag")
	}
}

func TestParseRefinitivEmpty(t *testing.T) {
	f := ParseRefinitivConfig(nil)
	if f.HasPassword || f.SessionToken != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "Refinitiv")
	must(t, os.MkdirAll(filepath.Join(dir, "Datastream"), 0o755))
	must(t, os.MkdirAll(filepath.Join(dir, "WorldCheck"), 0o755))

	cfgPath := filepath.Join(dir, "eikon_config.xml")
	must(t, os.WriteFile(cfgPath, []byte(`[Eikon]
eikon_username=alice@example.com
eikon_password=secret123
eikon_token=aBcDeFgHiJkLmNoPqRsTuVwX12345
ticker_1=GGAL.BA
ticker_2=ARAL30=
ticker_3=YPFD.BA
ticker_4=BMA.BA
cliente_cuit=27-11111111-4
`), 0o644))

	dsPath := filepath.Join(dir, "Datastream", "datastream_config.xml")
	must(t, os.WriteFile(dsPath, []byte(`<Datastream>
<dws_username>alice@example.com</dws_username>
<RHistory>2010..2026</RHistory>
</Datastream>`), 0o644))

	wcPath := filepath.Join(dir, "WorldCheck", "world_check_config.json")
	must(t, os.WriteFile(wcPath, []byte(`{
"api_key": "wcSecretAbCdEfGhIjKlMnOpQrStUv",
"aml_screening": true,
"pep_screening": true
}`), 0o644))

	stratPath := filepath.Join(usersBase, "alice", "projects", "refinitiv", "refinitiv_data_script.py")
	must(t, os.MkdirAll(filepath.Dir(stratPath), 0o755))
	must(t, os.WriteFile(stratPath, []byte(`import refinitiv.data as rd
session = rd.session.platform.Definition(app_key="abcdefghijklmnopqrst1234").get_session()
ticker = "GGAL.BA"
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "Refinitiv")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "eikon_config.xml"),
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
		t.Fatalf("want 4 (cfg+ds+wc+strat), got %d: %+v", len(got), got)
	}

	var cfg, ds, wc, strat Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case dsPath:
			ds = r
		case wcPath:
			wc = r
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

	if ds.ArtifactKind != KindDatastreamConfig {
		t.Fatalf("ds kind=%q", ds.ArtifactKind)
	}
	if !ds.HasDatastreamSubscription {
		t.Fatalf("ds must flag datastream: %+v", ds)
	}
	if ds.SubscriptionTier != TierDatastream {
		t.Fatalf("ds tier=%q want datastream", ds.SubscriptionTier)
	}
	if ds.ProductClass != ProductHistoricalData {
		t.Fatalf("ds product=%q want historical-data", ds.ProductClass)
	}

	if wc.ArtifactKind != KindWorldCheckConfig {
		t.Fatalf("wc kind=%q", wc.ArtifactKind)
	}
	if !wc.HasWorldCheckScreening {
		t.Fatalf("wc must flag: %+v", wc)
	}
	if wc.ProductClass != ProductAMLKYCWorldCheck {
		t.Fatalf("wc product=%q want aml-kyc-world-check", wc.ProductClass)
	}

	if strat.ArtifactKind != KindPythonSDK {
		t.Fatalf("strat kind=%q", strat.ArtifactKind)
	}
	if !strat.HasPythonSDK {
		t.Fatalf("strat must flag: %+v", strat)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-refinitiv")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "eikon_config.xml"),
		[]byte(`eikon_username=alice@example.com`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "REFINITIV_DIR" {
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
		installRoots: []string{"/nope-refinitiv"},
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
	// At "a": "eikon-config" < "eikon-license" alphabetically.
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,eikon-config)", in[0])
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
