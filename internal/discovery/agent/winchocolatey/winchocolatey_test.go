package winchocolatey

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindChocoNuspec), "choco-nuspec"},
		{string(KindChocoLog), "choco-log"},
		{string(KindChocoConfig), "choco-config"},
		{string(KindChocoExtensionNuspec), "choco-extension-nuspec"},
		{string(KindChocoPin), "choco-pin"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(DPDSHandlesPII), "handles-pii"},
		{string(DPDSHandlesFinancial), "handles-financial"},
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
		"googlechrome.nuspec",
		"quickbooks.nuspec",
		"chocolatey.log",
		"chocolatey.config",
		"chocolatey-extension.xml",
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
		`C:\ProgramData\chocolatey\lib\googlechrome\googlechrome.nuspec`:              KindChocoNuspec,
		`C:\ProgramData\chocolatey\extensions\chocolatey-core\chocolatey-core.nuspec`: KindChocoExtensionNuspec,
		`C:\ProgramData\chocolatey\logs\chocolatey.log`:                               KindChocoLog,
		`C:\ProgramData\chocolatey\config\chocolatey.config`:                          KindChocoConfig,
		`C:\ProgramData\chocolatey\.chocolatey\pinlist.txt`:                           KindChocoPin,
		`random.txt`: KindOther,
		``:           KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromPath(in); got != want {
			t.Fatalf("ArtifactKindFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseNuspec(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>googlechrome</id>
    <title>Google Chrome</title>
    <authors>Google Inc.</authors>
    <copyright>(c) Google LLC</copyright>
    <version>120.0.6099.71</version>
    <projectUrl>https://www.google.com/chrome/</projectUrl>
    <licenseUrl>https://www.google.com/chrome/eula.html</licenseUrl>
    <description>Google Chrome is a fast, secure web browser.</description>
    <tags>browser google chrome</tags>
    <releaseNotes>https://chromereleases.googleblog.com/</releaseNotes>
  </metadata>
</package>`)
	f, ok := ParseNuspec(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.PackageID != "googlechrome" {
		t.Fatalf("id=%q", f.PackageID)
	}
	if f.Title != "Google Chrome" {
		t.Fatalf("title=%q", f.Title)
	}
	if f.Authors != "Google Inc." {
		t.Fatalf("authors=%q", f.Authors)
	}
	if f.Version != "120.0.6099.71" {
		t.Fatalf("version=%q", f.Version)
	}
	if f.ProjectURL != "https://www.google.com/chrome/" {
		t.Fatalf("project=%q", f.ProjectURL)
	}
	if f.LicenseURL != "https://www.google.com/chrome/eula.html" {
		t.Fatalf("license=%q", f.LicenseURL)
	}
	if f.Tags != "browser google chrome" {
		t.Fatalf("tags=%q", f.Tags)
	}
}

func TestParseNuspecEmpty(t *testing.T) {
	if _, ok := ParseNuspec([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

func TestParseNuspecNonXML(t *testing.T) {
	if _, ok := ParseNuspec([]byte(`{"id": "x"}`)); ok {
		t.Fatal("non-XML must NOT parse")
	}
}

func TestPublisherFromNuspec(t *testing.T) {
	if PublisherFromNuspec(NuspecFields{Authors: "A", Copyright: "C"}) != "A" {
		t.Fatal("authors must win over copyright")
	}
	if PublisherFromNuspec(NuspecFields{Copyright: "C"}) != "C" {
		t.Fatal("copyright fallback")
	}
	if PublisherFromNuspec(NuspecFields{}) != "" {
		t.Fatal("empty when neither set")
	}
}

func TestTitleFromNuspec(t *testing.T) {
	if TitleFromNuspec(NuspecFields{Title: "T", PackageID: "P"}) != "T" {
		t.Fatal("title must win over id")
	}
	if TitleFromNuspec(NuspecFields{PackageID: "P"}) != "P" {
		t.Fatal("id fallback")
	}
}

func TestClassifyDPDS(t *testing.T) {
	cases := []struct {
		id, title, tags string
		want            DPDSClass
	}{
		{"googlechrome", "Google Chrome", "browser", DPDSHandlesPII},
		{"outlook", "Outlook", "email", DPDSHandlesPII},
		{"quickbooks", "QuickBooks Pro", "accounting", DPDSHandlesFinancial},
		{"openemr", "OpenEMR", "ehr", DPDSHandlesPHI},
		{"stripe-cli", "Stripe CLI", "payments", DPDSHandlesPCI},
		{"git", "Git", "vcs", DPDSDevTool},
		{"random", "Random", "tool", DPDSUnknown},
		{"", "", "", DPDSUnknown},
	}
	for _, c := range cases {
		if got := ClassifyDPDS(c.id, c.title, c.tags); got != c.want {
			t.Fatalf("ClassifyDPDS(%q,%q,%q)=%q want %q",
				c.id, c.title, c.tags, got, c.want)
		}
	}
}

func TestIsPIIHandlingClass(t *testing.T) {
	yes := []DPDSClass{DPDSHandlesPII, DPDSHandlesFinancial, DPDSHandlesPHI, DPDSHandlesPCI}
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

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateHasURLs(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind: KindChocoNuspec,
		PackageID:    "googlechrome",
		ProjectURL:   "https://www.google.com/chrome/",
		LicenseURL:   "https://www.google.com/chrome/eula.html",
		FileMode:     0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasProjectURL {
		t.Fatal("project URL set must flag")
	}
	if !r.HasLicenseURL {
		t.Fatal("license URL set must flag")
	}
}

func TestAnnotateRecentInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindChocoNuspec,
		PackageID:           "x",
		InstallDateYYYYMMDD: "20260601",
		FileMode:            0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasRecentInstall {
		t.Fatalf("2026-06-01 within 30d of 2026-06-16: %+v", r)
	}
}

func TestAnnotateOldInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindChocoNuspec,
		PackageID:           "x",
		InstallDateYYYYMMDD: "20240101",
		FileMode:            0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.HasRecentInstall {
		t.Fatal("> 30d old must NOT flag")
	}
}

func TestAnnotatePIIExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind: KindChocoNuspec,
		PackageID:    "quickbooks",
		Title:        "QuickBooks Pro",
		DPDSClass:    DPDSHandlesFinancial,
		FileMode:     0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsPIIHandling {
		t.Fatal("financial must flag PII")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + PII + package_id = exposure")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind: KindChocoNuspec,
		PackageID:    "quickbooks",
		DPDSClass:    DPDSHandlesFinancial,
		FileMode:     0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoPackageNoExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind: KindChocoNuspec,
		DPDSClass:    DPDSHandlesFinancial,
		FileMode:     0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("no package_id must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksTree(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "ProgramData", "chocolatey", "lib")

	// PII-handling package (Google Chrome), world-readable.
	chromeDir := filepath.Join(root, "googlechrome")
	must(t, os.MkdirAll(chromeDir, 0o755))
	chromePath := filepath.Join(chromeDir, "googlechrome.nuspec")
	must(t, os.WriteFile(chromePath, []byte(`<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>googlechrome</id>
    <title>Google Chrome</title>
    <authors>Google Inc.</authors>
    <version>120.0.6099.71</version>
    <projectUrl>https://www.google.com/chrome/</projectUrl>
    <licenseUrl>https://www.google.com/chrome/eula.html</licenseUrl>
    <description>Web browser.</description>
    <tags>browser google chrome</tags>
  </metadata>
</package>`), 0o644))

	// Financial-handling package (QuickBooks), locked down.
	qbDir := filepath.Join(root, "quickbooks")
	must(t, os.MkdirAll(qbDir, 0o755))
	qbPath := filepath.Join(qbDir, "quickbooks.nuspec")
	must(t, os.WriteFile(qbPath, []byte(`<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>quickbooks</id>
    <title>QuickBooks Pro</title>
    <authors>Intuit Inc.</authors>
    <version>2025.1</version>
    <projectUrl>https://quickbooks.intuit.com</projectUrl>
    <description>Accounting software.</description>
  </metadata>
</package>`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(chromeDir, "random.txt"),
		[]byte(`noise`), 0o644))

	c := &fileCollector{
		installRoots: []string{root},
		usersBases:   nil,
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (chrome+quickbooks), got %d: %+v", len(got), got)
	}

	var chrome, qb Row
	for _, r := range got {
		switch r.FilePath {
		case chromePath:
			chrome = r
		case qbPath:
			qb = r
		}
	}
	if chrome.ArtifactKind != KindChocoNuspec {
		t.Fatalf("chrome kind=%q", chrome.ArtifactKind)
	}
	if chrome.PackageID != "googlechrome" {
		t.Fatalf("chrome id=%q", chrome.PackageID)
	}
	if chrome.Title != "Google Chrome" {
		t.Fatalf("chrome title=%q", chrome.Title)
	}
	if chrome.Publisher != "Google Inc." {
		t.Fatalf("chrome publisher=%q", chrome.Publisher)
	}
	if chrome.ProjectURL != "https://www.google.com/chrome/" {
		t.Fatalf("chrome project=%q", chrome.ProjectURL)
	}
	if chrome.LicenseURL != "https://www.google.com/chrome/eula.html" {
		t.Fatalf("chrome license=%q", chrome.LicenseURL)
	}
	if chrome.DPDSClass != DPDSHandlesPII {
		t.Fatalf("chrome dp_ds=%q", chrome.DPDSClass)
	}
	if !chrome.HasProjectURL || !chrome.HasLicenseURL {
		t.Fatalf("chrome URLs must flag: %+v", chrome)
	}
	if !chrome.IsPIIHandling {
		t.Fatal("chrome must flag PII")
	}
	if !chrome.IsCredentialExposureRisk {
		t.Fatalf("readable + PII + id = exposure: %+v", chrome)
	}

	if qb.ArtifactKind != KindChocoNuspec {
		t.Fatalf("qb kind=%q", qb.ArtifactKind)
	}
	if qb.DPDSClass != DPDSHandlesFinancial {
		t.Fatalf("qb dp_ds=%q", qb.DPDSClass)
	}
	if !qb.IsPIIHandling {
		t.Fatal("qb must flag PII (financial)")
	}
	if qb.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", qb)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-choco", "x")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "x.nuspec"),
		[]byte(`<?xml version="1.0"?>
<package><metadata><id>x</id><title>X</title><authors>Y</authors></metadata></package>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "CHOCOLATEY_DIR" {
				return filepath.Join(tmp, "custom-choco")
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
	if len(got) != 1 || got[0].ArtifactKind != KindChocoNuspec {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-choco"},
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
		{FilePath: "z", ArtifactKind: KindChocoNuspec, PackageID: "z"},
		{FilePath: "a", ArtifactKind: KindChocoNuspec, PackageID: "z"},
		{FilePath: "a", ArtifactKind: KindChocoNuspec, PackageID: "a"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].PackageID != "a" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
