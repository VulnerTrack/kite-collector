package winwingetexport

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindWingetExportJSON), "winget-export-json"},
		{string(KindWingetPinList), "winget-pin-list"},
		{string(KindWingetSourceList), "winget-source-list"},
		{string(KindWingetInstallLog), "winget-install-log"},
		{string(KindWingetUninstallLog), "winget-uninstall-log"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"winget-export.json",
		"winget-export-2026-06-15.json",
		"winget_export_LAPTOP01.json",
		"pinned.json",
		"sources.json",
		"winget.log",
		"Microsoft.Office.installLog",
	}
	no := []string{"", "factura.xml", "random.txt"}
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
		"winget-export.json":            KindWingetExportJSON,
		"winget_export_LAPTOP.json":     KindWingetExportJSON,
		"pinned.json":                   KindWingetPinList,
		"winget-pin-list.json":          KindWingetPinList,
		"sources.json":                  KindWingetSourceList,
		"winget-source-list.json":       KindWingetSourceList,
		"winget-install.log":            KindWingetInstallLog,
		"Microsoft.Office.installLog":   KindWingetInstallLog,
		"winget.log":                    KindWingetInstallLog,
		"winget-uninstall.log":          KindWingetUninstallLog,
		"Microsoft.Office.uninstallLog": KindWingetUninstallLog,
		"random.json":                   KindOther,
		"":                              KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPackagePublisher(t *testing.T) {
	cases := map[string]string{
		"Microsoft.Office":        "microsoft",
		"Google.Chrome":           "google",
		"Intuit.QuickBooks":       "intuit",
		"Adobe.Acrobat.Reader.64": "adobe",
		"NoPublisher":             "",
		".LeadingDot":             "",
		"":                        "",
	}
	for in, want := range cases {
		if got := PackagePublisher(in); got != want {
			t.Fatalf("PackagePublisher(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCountPackages(t *testing.T) {
	body := []byte(`{
"Sources": [{
  "Packages": [
    {"PackageIdentifier": "Microsoft.Office", "Version": "16.0"},
    {"PackageIdentifier": "Google.Chrome", "Version": "120"},
    {"PackageIdentifier": "Intuit.QuickBooks", "Version": "2025"}
  ]
}]
}`)
	if got := CountPackages(body); got != 3 {
		t.Fatalf("CountPackages=%d want 3", got)
	}
}

func TestPublisherSplit(t *testing.T) {
	body := []byte(`{
"Packages": [
  {"PackageIdentifier": "Microsoft.Office"},
  {"PackageIdentifier": "Microsoft.Teams"},
  {"PackageIdentifier": "Google.Chrome"},
  {"PackageIdentifier": "Intuit.QuickBooks"}
]
}`)
	ms, tp := PublisherSplit(body)
	if ms != 2 {
		t.Fatalf("microsoft=%d want 2", ms)
	}
	if tp != 2 {
		t.Fatalf("third_party=%d want 2", tp)
	}
}

func TestCountPIIPackages(t *testing.T) {
	body := []byte(`{
"Packages": [
  {"PackageIdentifier": "Microsoft.Office"},
  {"PackageIdentifier": "Google.Chrome"},
  {"PackageIdentifier": "Intuit.QuickBooks"},
  {"PackageIdentifier": "VideoLAN.VLC"},
  {"PackageIdentifier": "Microsoft.Notepad"}
]
}`)
	// Office (PII), Chrome (PII), QuickBooks (financial).
	// VLC + Notepad NOT in PII catalogue.
	got := CountPIIPackages(body)
	if got != 3 {
		t.Fatalf("CountPIIPackages=%d want 3", got)
	}
}

func TestSourceListFromBody(t *testing.T) {
	body := []byte(`{
"Sources": [
  {"Name": "winget", "Argument": "https://cdn.winget.microsoft.com/cache"},
  {"Name": "msstore", "Argument": "https://storeedgefd.dsx.mp.microsoft.com"}
]
}`)
	name, arg := SourceListFromBody(body)
	if name != "winget" {
		t.Fatalf("name=%q", name)
	}
	if arg != "https://cdn.winget.microsoft.com/cache" {
		t.Fatalf("arg=%q", arg)
	}
}

func TestHasMSStoreSource(t *testing.T) {
	yes := [][]byte{
		[]byte(`{"Sources": [{"Name": "winget"}, {"Name": "msstore"}]}`),
		[]byte(`{"Name": "MsStore"}`),
	}
	no := [][]byte{
		[]byte(`{"Sources": [{"Name": "winget"}]}`),
		[]byte(`{}`),
	}
	for _, v := range yes {
		if !HasMSStoreSource(v) {
			t.Fatalf("expected MSStore: %q", v)
		}
	}
	for _, v := range no {
		if HasMSStoreSource(v) {
			t.Fatalf("expected NOT MSStore: %q", v)
		}
	}
}

func TestHasThirdPartySource(t *testing.T) {
	yes := []byte(`{"Sources": [{"Name": "winget"}, {"Name": "corporate-mirror"}]}`)
	no := []byte(`{"Sources": [{"Name": "winget"}, {"Name": "msstore"}]}`)
	if !HasThirdPartySource(yes) {
		t.Fatal("expected third-party")
	}
	if HasThirdPartySource(no) {
		t.Fatal("expected NOT third-party")
	}
}

func TestWingetVersionFromBody(t *testing.T) {
	body := []byte(`{"WinGetVersion": "1.6.3133", "CreationDate": "2026-06-15T12:00:00Z"}`)
	if got := WingetVersionFromBody(body); got != "1.6.3133" {
		t.Fatalf("version=%q", got)
	}
}

func TestCreationTimestampFromBody(t *testing.T) {
	body := []byte(`{"WinGetVersion": "1.6.3133", "CreationDate": "2026-06-15T12:00:00Z"}`)
	if got := CreationTimestampFromBody(body); got != "2026-06-15T12:00:00Z" {
		t.Fatalf("ts=%q", got)
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotatePIIExposure(t *testing.T) {
	r := Row{
		ArtifactKind:    KindWingetExportJSON,
		PackageCount:    10,
		PIIPackageCount: 3,
		FileMode:        0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasPIIPackages {
		t.Fatal("PII count > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + packages + PII = exposure")
	}
}

func TestAnnotateThirdPartySourceExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindWingetSourceList,
		HasThirdPartySource: true,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + sources-list + third-party = exposure")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:    KindWingetExportJSON,
		PackageCount:    10,
		PIIPackageCount: 3,
		FileMode:        0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoPackagesNoExposure(t *testing.T) {
	r := Row{
		ArtifactKind:    KindWingetExportJSON,
		PackageCount:    0,
		PIIPackageCount: 0,
		FileMode:        0o644,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0 packages must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksTree(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Microsoft", "WinGet")
	must(t, os.MkdirAll(root, 0o755))

	// winget export JSON, world-readable, with PII packages.
	expPath := filepath.Join(root, "winget-export-LAPTOP01.json")
	must(t, os.WriteFile(expPath, []byte(`{
  "$schema": "https://aka.ms/winget-packages.schema.2.0.json",
  "WinGetVersion": "1.6.3133",
  "CreationDate": "2026-06-15T12:00:00Z",
  "Sources": [{
    "Packages": [
      {"PackageIdentifier": "Microsoft.Office", "Version": "16.0.18025"},
      {"PackageIdentifier": "Microsoft.Teams", "Version": "1.6"},
      {"PackageIdentifier": "Google.Chrome", "Version": "120.0.6099"},
      {"PackageIdentifier": "Intuit.QuickBooks", "Version": "2025.1"},
      {"PackageIdentifier": "VideoLAN.VLC", "Version": "3.0.20"}
    ],
    "SourceDetails": {
      "Name": "winget",
      "Identifier": "Microsoft.Winget.Source",
      "Argument": "https://cdn.winget.microsoft.com/cache",
      "Type": "Microsoft.PreIndexed.Package"
    }
  }]
}`), 0o644))

	// sources.json with third-party corporate source, locked down.
	srcPath := filepath.Join(root, "sources.json")
	must(t, os.WriteFile(srcPath, []byte(`{
  "Sources": [
    {"Name": "winget", "Argument": "https://cdn.winget.microsoft.com/cache"},
    {"Name": "msstore", "Argument": "https://storeedgefd.dsx.mp.microsoft.com"},
    {"Name": "corporate-mirror", "Argument": "https://internal.example.com/winget"}
  ]
}`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(root, "random.txt"),
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
		t.Fatalf("want 2 (export+sources), got %d: %+v", len(got), got)
	}

	var exp, src Row
	for _, r := range got {
		switch r.FilePath {
		case expPath:
			exp = r
		case srcPath:
			src = r
		}
	}
	if exp.ArtifactKind != KindWingetExportJSON {
		t.Fatalf("exp kind=%q", exp.ArtifactKind)
	}
	if exp.WingetVersion != "1.6.3133" {
		t.Fatalf("exp version=%q", exp.WingetVersion)
	}
	if exp.CreationTimestamp != "2026-06-15T12:00:00Z" {
		t.Fatalf("exp ts=%q", exp.CreationTimestamp)
	}
	if exp.PackageCount != 5 {
		t.Fatalf("exp packages=%d want 5", exp.PackageCount)
	}
	if exp.MicrosoftPackageCount != 2 {
		t.Fatalf("exp microsoft=%d want 2", exp.MicrosoftPackageCount)
	}
	if exp.ThirdPartyPackageCount != 3 {
		t.Fatalf("exp third_party=%d want 3", exp.ThirdPartyPackageCount)
	}
	if exp.PIIPackageCount < 3 {
		t.Fatalf("exp PII=%d want >=3 (Office/Teams/Chrome/QuickBooks)", exp.PIIPackageCount)
	}
	if !exp.HasPIIPackages {
		t.Fatal("exp must flag PII")
	}
	if !exp.IsCredentialExposureRisk {
		t.Fatalf("exp readable + packages + PII = exposure: %+v", exp)
	}

	if src.ArtifactKind != KindWingetSourceList {
		t.Fatalf("src kind=%q", src.ArtifactKind)
	}
	if !src.HasMSStoreSource {
		t.Fatal("src must flag MS Store")
	}
	if !src.HasThirdPartySource {
		t.Fatal("src must flag third-party (corporate-mirror)")
	}
	if src.IsCredentialExposureRisk {
		t.Fatalf("src 0o600 must NOT flag exposure: %+v", src)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-winget")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "winget-export-x.json"),
		[]byte(`{"WinGetVersion": "1.6", "Sources": [{"Packages": [{"PackageIdentifier": "Microsoft.Office"}]}]}`),
		0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "WINGET_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindWingetExportJSON {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-winget"},
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
		{FilePath: "z", ArtifactKind: KindWingetExportJSON},
		{FilePath: "a", ArtifactKind: KindWingetSourceList},
		{FilePath: "a", ArtifactKind: KindWingetExportJSON},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindWingetExportJSON {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
