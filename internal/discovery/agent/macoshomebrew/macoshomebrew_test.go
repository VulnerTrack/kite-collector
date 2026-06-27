package macoshomebrew

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindBrewInstallReceipt), "brew-install-receipt"},
		{string(KindBrewFormulaRB), "brew-formula-rb"},
		{string(KindCaskMetadataJSON), "cask-metadata-json"},
		{string(KindBrewfile), "brewfile"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(DPDSHandlesPII), "handles-pii"},
		{string(DPDSDevTool), "dev-tool"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"INSTALL_RECEIPT.json",
		"openssl.rb",
		"firefox.json",
		"Brewfile",
	}
	no := []string{"", "factura.xml", "cv.docx", "random.txt"}
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

func TestArtifactKindFromPath(t *testing.T) {
	cases := map[string]ArtifactKind{
		"/opt/homebrew/Cellar/openssl/3.0.7/INSTALL_RECEIPT.json":                            KindBrewInstallReceipt,
		"/opt/homebrew/Cellar/openssl/3.0.7/.brew/openssl.rb":                                KindBrewFormulaRB,
		"/opt/homebrew/Caskroom/firefox/120.0/.metadata/120.0/1700000000/Casks/firefox.json": KindCaskMetadataJSON,
		"/usr/local/Cellar/git/2.43.0/INSTALL_RECEIPT.json":                                  KindBrewInstallReceipt,
		"/Users/admin/Documents/Brewfiles/Brewfile":                                          KindBrewfile,
		"/random/path.json": KindOther,
		"":                  KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromPath(in); got != want {
			t.Fatalf("ArtifactKindFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestFormulaOrTokenFromPath(t *testing.T) {
	cases := map[string]string{
		"/opt/homebrew/Cellar/openssl/3.0.7/INSTALL_RECEIPT.json":                     "openssl",
		"/opt/homebrew/Caskroom/firefox/120.0/.metadata/120.0/.../Casks/firefox.json": "firefox",
		"/usr/local/Cellar/git/2.43.0/INSTALL_RECEIPT.json":                           "git",
		"/usr/local/Caskroom/microsoft-teams/1.6.00/...":                              "microsoft-teams",
		"/random/path.json": "",
	}
	for in, want := range cases {
		if got := FormulaOrTokenFromPath(in); got != want {
			t.Fatalf("FormulaOrTokenFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCaskPath(t *testing.T) {
	yes := []string{
		"/opt/homebrew/Caskroom/firefox/...",
		"/usr/local/Caskroom/microsoft-teams/...",
	}
	no := []string{
		"/opt/homebrew/Cellar/openssl/...",
		"/usr/local/Cellar/git/...",
		"",
	}
	for _, v := range yes {
		if !IsCaskPath(v) {
			t.Fatalf("expected cask: %q", v)
		}
	}
	for _, v := range no {
		if IsCaskPath(v) {
			t.Fatalf("expected NOT cask: %q", v)
		}
	}
}

func TestClassifyDPDS(t *testing.T) {
	cases := map[string]DPDSClass{
		"firefox":           DPDSHandlesPII,
		"google-chrome":     DPDSHandlesPII,
		"microsoft-outlook": DPDSHandlesPII,
		"slack":             DPDSHandlesPII,
		"postgresql":        DPDSHandlesPII,
		"keepassxc":         DPDSHandlesPII,
		"quickbooks":        DPDSHandlesFinancial,
		"openemr":           DPDSHandlesPHI,
		"git":               DPDSDevTool,
		"awscli":            DPDSDevTool,
		"vlc":               DPDSMediaTool,
		"unknown-formula":   DPDSUnknown,
		"":                  DPDSUnknown,
	}
	for in, want := range cases {
		if got := ClassifyDPDS(in); got != want {
			t.Fatalf("ClassifyDPDS(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsPIIHandlingClass(t *testing.T) {
	yes := []DPDSClass{
		DPDSHandlesPII, DPDSHandlesFinancial,
		DPDSHandlesPHI, DPDSHandlesPCI, DPDSHandlesBiometric,
	}
	no := []DPDSClass{DPDSDevTool, DPDSMediaTool, DPDSUnknown}
	for _, v := range yes {
		if !IsPIIHandlingClass(v) {
			t.Fatalf("expected PII: %q", v)
		}
	}
	for _, v := range no {
		if IsPIIHandlingClass(v) {
			t.Fatalf("expected NOT PII: %q", v)
		}
	}
}

// -- ParseInstallReceipt ------------------------------------------

func TestParseInstallReceipt(t *testing.T) {
	body := []byte(`{
  "homebrew_version": "4.0.1",
  "time": 1718383200,
  "built_as_bottle": true,
  "poured_from_bottle": true,
  "installed_on_request": true,
  "installed_as_dependency": false,
  "runtime_dependencies": [
    {"full_name": "ca-certificates", "version": "2024-09-24"},
    {"full_name": "lz4", "version": "1.10.0"}
  ],
  "source": {
    "spec": "stable",
    "stable": {
      "version": "3.0.7"
    }
  }
}`)
	r, ok := ParseInstallReceipt(body)
	if !ok {
		t.Fatal("must parse")
	}
	if r.HomebrewVersion != "4.0.1" {
		t.Fatalf("brew version=%q", r.HomebrewVersion)
	}
	if r.Time != 1718383200 {
		t.Fatalf("time=%d", r.Time)
	}
	if !r.InstalledOnRequest {
		t.Fatal("on_request must be true")
	}
	if r.Version != "3.0.7" {
		t.Fatalf("version=%q", r.Version)
	}
	if r.RuntimeDeps != 2 {
		t.Fatalf("deps=%d want 2", r.RuntimeDeps)
	}
}

func TestParseInstallReceiptEmpty(t *testing.T) {
	if _, ok := ParseInstallReceipt([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

func TestParseInstallReceiptNonJSON(t *testing.T) {
	if _, ok := ParseInstallReceipt([]byte(`<xml/>`)); ok {
		t.Fatal("non-JSON must NOT parse")
	}
}

// -- ParseCaskMetadata --------------------------------------------

func TestParseCaskMetadata(t *testing.T) {
	body := []byte(`{
  "token": "firefox",
  "name": ["Mozilla Firefox"],
  "desc": "Web browser",
  "homepage": "https://www.mozilla.org/firefox/",
  "version": "120.0",
  "url": "https://download.mozilla.org/?product=firefox-120.0",
  "auto_updates": true
}`)
	f, ok := ParseCaskMetadata(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.Token != "firefox" {
		t.Fatalf("token=%q", f.Token)
	}
	if f.Name != "Mozilla Firefox" {
		t.Fatalf("name=%q", f.Name)
	}
	if f.Description != "Web browser" {
		t.Fatalf("desc=%q", f.Description)
	}
	if f.Homepage != "https://www.mozilla.org/firefox/" {
		t.Fatalf("homepage=%q", f.Homepage)
	}
	if f.Version != "120.0" {
		t.Fatalf("version=%q", f.Version)
	}
	if !f.AutoUpdates {
		t.Fatal("auto_updates must be true")
	}
}

func TestParseCaskMetadataURLObject(t *testing.T) {
	body := []byte(`{
  "token": "slack",
  "name": ["Slack"],
  "url": {"url": "https://downloads.slack-edge.com/releases/macos/4.36.0/Slack.dmg", "verified": "downloads.slack-edge.com/"}
}`)
	f, ok := ParseCaskMetadata(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.URL == "" {
		t.Fatal("url object must be extracted")
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateRecentInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:    KindBrewInstallReceipt,
		FormulaOrToken:  "openssl",
		InstallTimeUnix: now().Add(-5 * 24 * time.Hour).Unix(),
		FileMode:        0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasRecentInstall {
		t.Fatalf("5d ago must flag recent: %+v", r)
	}
	if r.InstallDateYYYYMMDD == "" {
		t.Fatal("install_date must be populated from unix time")
	}
}

func TestAnnotateOldInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:    KindBrewInstallReceipt,
		FormulaOrToken:  "openssl",
		InstallTimeUnix: 1640000000, // ~2021
		FileMode:        0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.HasRecentInstall {
		t.Fatal("> 30d old must NOT flag recent")
	}
}

func TestAnnotateHasHomepage(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:   KindCaskMetadataJSON,
		FormulaOrToken: "firefox",
		Homepage:       "https://www.mozilla.org/",
		FileMode:       0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasHomepage {
		t.Fatal("homepage set must flag")
	}
}

func TestAnnotatePIIExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:   KindCaskMetadataJSON,
		FormulaOrToken: "firefox",
		DPDSClass:      DPDSHandlesPII,
		FileMode:       0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsPIIHandling {
		t.Fatal("PII class must flag handling")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + token + PII = exposure")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:   KindCaskMetadataJSON,
		FormulaOrToken: "firefox",
		DPDSClass:      DPDSHandlesPII,
		FileMode:       0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoTokenNoExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind: KindCaskMetadataJSON,
		DPDSClass:    DPDSHandlesPII,
		FileMode:     0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("no token must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksBrewTree(t *testing.T) {
	tmp := t.TempDir()
	brewRoot := filepath.Join(tmp, "opt", "homebrew")

	// CLI formula INSTALL_RECEIPT.json (postgresql), world-readable.
	pgDir := filepath.Join(brewRoot, "Cellar", "postgresql", "15.4")
	must(t, os.MkdirAll(pgDir, 0o755))
	pgPath := filepath.Join(pgDir, "INSTALL_RECEIPT.json")
	must(t, os.WriteFile(pgPath, []byte(`{
  "homebrew_version": "4.0.1",
  "time": 1748736000,
  "built_as_bottle": true,
  "poured_from_bottle": true,
  "installed_on_request": true,
  "installed_as_dependency": false,
  "runtime_dependencies": [{"full_name": "openssl@3"}, {"full_name": "icu4c"}],
  "source": {"spec": "stable", "stable": {"version": "15.4"}}
}`), 0o644))

	// Cask metadata (firefox), locked down.
	ffDir := filepath.Join(brewRoot, "Caskroom", "firefox", "120.0",
		".metadata", "120.0", "1700000000", "Casks")
	must(t, os.MkdirAll(ffDir, 0o755))
	ffPath := filepath.Join(ffDir, "firefox.json")
	must(t, os.WriteFile(ffPath, []byte(`{
  "token": "firefox",
  "name": ["Mozilla Firefox"],
  "desc": "Web browser",
  "homepage": "https://www.mozilla.org/firefox/",
  "version": "120.0",
  "auto_updates": true
}`), 0o600))

	// Random ignored (must not match candidate name).
	must(t, os.WriteFile(filepath.Join(pgDir, "random.dat"),
		[]byte(`noise`), 0o644))

	c := &fileCollector{
		installRoots: []string{brewRoot},
		usersBases:   nil,
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now: func() time.Time {
			// Set "now" to be 5 days after the install time (1748736000 → 2025-06-01).
			return time.Unix(1748736000, 0).UTC().Add(5 * 24 * time.Hour)
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (pg+firefox), got %d: %+v", len(got), got)
	}

	var pg, ff Row
	for _, r := range got {
		switch r.FilePath {
		case pgPath:
			pg = r
		case ffPath:
			ff = r
		}
	}
	if pg.ArtifactKind != KindBrewInstallReceipt {
		t.Fatalf("pg kind=%q", pg.ArtifactKind)
	}
	if pg.FormulaOrToken != "postgresql" {
		t.Fatalf("pg formula=%q", pg.FormulaOrToken)
	}
	if pg.HomebrewVersion != "4.0.1" {
		t.Fatalf("pg brew=%q", pg.HomebrewVersion)
	}
	if pg.Version != "15.4" {
		t.Fatalf("pg version=%q", pg.Version)
	}
	if pg.RuntimeDepsCount != 2 {
		t.Fatalf("pg deps=%d", pg.RuntimeDepsCount)
	}
	if !pg.InstalledOnRequest {
		t.Fatal("pg must be installed_on_request")
	}
	if pg.DPDSClass != DPDSHandlesPII {
		t.Fatalf("pg dp_ds=%q (postgresql should be PII)", pg.DPDSClass)
	}
	if !pg.IsPIIHandling {
		t.Fatal("pg must flag PII")
	}
	if !pg.IsCredentialExposureRisk {
		t.Fatalf("pg readable + token + PII = exposure: %+v", pg)
	}
	if !pg.HasRecentInstall {
		t.Fatalf("pg 5d-old must flag recent: %+v", pg)
	}
	if pg.InstallDateYYYYMMDD == "" {
		t.Fatal("pg install_date must populate")
	}

	if ff.ArtifactKind != KindCaskMetadataJSON {
		t.Fatalf("ff kind=%q", ff.ArtifactKind)
	}
	if !ff.IsCask {
		t.Fatal("firefox path under Caskroom = is_cask")
	}
	if ff.FormulaOrToken != "firefox" {
		t.Fatalf("ff token=%q", ff.FormulaOrToken)
	}
	if ff.DisplayName != "Mozilla Firefox" {
		t.Fatalf("ff name=%q", ff.DisplayName)
	}
	if ff.Homepage != "https://www.mozilla.org/firefox/" {
		t.Fatalf("ff homepage=%q", ff.Homepage)
	}
	if !ff.HasHomepage {
		t.Fatal("ff homepage must flag")
	}
	if ff.DPDSClass != DPDSHandlesPII {
		t.Fatalf("ff dp_ds=%q", ff.DPDSClass)
	}
	if !ff.InstalledOnRequest {
		t.Fatal("cask is always installed_on_request")
	}
	if ff.IsCredentialExposureRisk {
		t.Fatalf("ff 0o600 must NOT flag: %+v", ff)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-brew", "Cellar", "git", "2.43.0")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "INSTALL_RECEIPT.json"),
		[]byte(`{"homebrew_version": "4.0.1", "time": 1700000000}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "HOMEBREW_DIR" {
				return filepath.Join(tmp, "custom-brew")
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
	if len(got) != 1 || got[0].ArtifactKind != KindBrewInstallReceipt {
		t.Fatalf("env: %+v", got)
	}
	if got[0].FormulaOrToken != "git" {
		t.Fatalf("env formula=%q", got[0].FormulaOrToken)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-brew"},
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
		{FilePath: "z", ArtifactKind: KindBrewInstallReceipt, FormulaOrToken: "z"},
		{FilePath: "a", ArtifactKind: KindBrewInstallReceipt, FormulaOrToken: "z"},
		{FilePath: "a", ArtifactKind: KindBrewInstallReceipt, FormulaOrToken: "a"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].FormulaOrToken != "a" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
