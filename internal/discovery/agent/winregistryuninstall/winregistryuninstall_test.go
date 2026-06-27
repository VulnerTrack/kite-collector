package winregistryuninstall

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindRegUninstallHKLM), "reg-uninstall-hklm"},
		{string(KindRegUninstallHKCU), "reg-uninstall-hkcu"},
		{string(KindAddRemoveCSV), "addremove-csv"},
		{string(KindAppxPackagesJSON), "appx-packages-json"},
		{string(KindAppxPackagesCSV), "appx-packages-csv"},
		{string(KindPSGetPackage), "ps-get-package"},
		{string(KindWMIWin32Product), "wmi-win32-product"},
		{string(KindDISMFeaturesCSV), "dism-features-csv"},
		{string(KindProgramsFeatures), "programs-features-csv"},
		{string(KindInstalledPrograms), "installed-programs-csv"},
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
		"uninstall_export_HKLM_LAPTOP01.reg",
		"uninstall_export_HKCU_LAPTOP01.reg",
		"addremoveprograms_LAPTOP01.csv",
		"appx_packages_LAPTOP01.json",
		"Get-Package_LAPTOP01.json",
		"Get-AppxPackage_LAPTOP01.csv",
		"Win32_Product_LAPTOP01.csv",
		"DISM_features_LAPTOP01.csv",
		"programs_and_features_LAPTOP01.csv",
		"installed_programs_LAPTOP01.csv",
	}
	no := []string{"", "factura.xml", "cv.docx", "random.csv"}
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
		"uninstall_export_HKLM_LAPTOP01.reg": KindRegUninstallHKLM,
		"uninstall_export_HKCU_LAPTOP01.reg": KindRegUninstallHKCU,
		"addremoveprograms_LAPTOP01.csv":     KindAddRemoveCSV,
		"appx_packages_LAPTOP01.json":        KindAppxPackagesJSON,
		"appx_packages_LAPTOP01.csv":         KindAppxPackagesCSV,
		"Get-Package_LAPTOP01.json":          KindPSGetPackage,
		"Win32_Product_LAPTOP01.csv":         KindWMIWin32Product,
		"DISM_features_LAPTOP01.csv":         KindDISMFeaturesCSV,
		"programs_and_features_LAPTOP01.csv": KindProgramsFeatures,
		"installed_programs_LAPTOP01.csv":    KindInstalledPrograms,
		"random.csv":                         KindOther,
		"":                                   KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestRegEntryCount(t *testing.T) {
	body := []byte(`Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID-1}]
"DisplayName"="Microsoft Office"
"Publisher"="Microsoft Corporation"

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID-2}]
"DisplayName"="QuickBooks Pro"
"Publisher"="Intuit Inc."

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID-3}]
"DisplayName"="JetBrains IntelliJ IDEA"
"Publisher"="JetBrains s.r.o."
`)
	if got := RegEntryCount(body); got != 3 {
		t.Fatalf("RegEntryCount=%d want 3", got)
	}
}

func TestCSVRowCount(t *testing.T) {
	body := []byte(`DisplayName,Publisher,Version,InstallDate
Microsoft Office,Microsoft,16.0,20240101
Google Chrome,Google,120,20250101
QuickBooks Pro,Intuit,2025,20250601
`)
	if got := CSVRowCount(body); got != 3 {
		t.Fatalf("CSVRowCount=%d want 3", got)
	}
}

func TestPublisherSplit(t *testing.T) {
	body := []byte(`[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID-1}]
"DisplayName"="Microsoft Office"
"Publisher"="Microsoft Corporation"

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID-2}]
"DisplayName"="QuickBooks Pro"
"Publisher"="Intuit Inc."

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID-3}]
"DisplayName"="Suspicious Tool"
"Publisher"=""
`)
	ms, tp, uns := PublisherSplit(body)
	if ms != 1 {
		t.Fatalf("microsoft=%d want 1", ms)
	}
	if tp != 1 {
		t.Fatalf("third_party=%d want 1", tp)
	}
	if uns != 1 {
		t.Fatalf("unsigned=%d want 1", uns)
	}
}

func TestRecentInstallStats(t *testing.T) {
	body := []byte(`[HKLM\...\Uninstall\{A}]
"DisplayName"="A"
"InstallDate"="20260601"

[HKLM\...\Uninstall\{B}]
"DisplayName"="B"
"InstallDate"="20240101"

[HKLM\...\Uninstall\{C}]
"DisplayName"="C"
"InstallDate"="20260610"
`)
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	recent, minD, maxD := RecentInstallStats(body, now)
	if recent != 2 {
		t.Fatalf("recent=%d want 2 (within 30d of 2026-06-16)", recent)
	}
	if minD != "20240101" {
		t.Fatalf("min=%q", minD)
	}
	if maxD != "20260610" {
		t.Fatalf("max=%q", maxD)
	}
}

func TestCountPIIRows(t *testing.T) {
	body := []byte(`Microsoft Outlook,Microsoft
Google Chrome,Google
QuickBooks Pro,Intuit
Visual Studio,Microsoft
Adobe Photoshop,Adobe
`)
	got := CountPIIRows(body)
	if got != 3 {
		t.Fatalf("CountPIIRows=%d want 3 (Outlook/Chrome/QuickBooks)", got)
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateRecentInstall(t *testing.T) {
	r := Row{
		ArtifactKind:       KindRegUninstallHKLM,
		EntryCount:         100,
		RecentInstallCount: 5,
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasRecentInstall {
		t.Fatal("recent_install_count > 0 must flag")
	}
}

func TestAnnotateUnsignedPublisher(t *testing.T) {
	r := Row{
		ArtifactKind:           KindRegUninstallHKLM,
		EntryCount:             100,
		UnsignedPublisherCount: 3,
		FileMode:               0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasUnsignedPublisher {
		t.Fatal("unsigned_publisher_count > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + unsigned + entries = exposure")
	}
}

func TestAnnotatePIIExposure(t *testing.T) {
	r := Row{
		ArtifactKind:     KindWMIWin32Product,
		EntryCount:       100,
		PIISoftwareCount: 5,
		FileMode:         0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasPIISoftware {
		t.Fatal("PII count > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + PII = exposure")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:     KindWMIWin32Product,
		EntryCount:       100,
		PIISoftwareCount: 5,
		FileMode:         0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoRiskClean(t *testing.T) {
	r := Row{
		ArtifactKind: KindRegUninstallHKLM,
		EntryCount:   100,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("no PII / unsigned must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksTree(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "ProgramData", "Inventory")
	must(t, os.MkdirAll(root, 0o755))

	// Realistic HKLM Uninstall export with PII + unsigned entry.
	regPath := filepath.Join(root, "uninstall_export_HKLM_LAPTOP01.reg")
	must(t, os.WriteFile(regPath, []byte(`Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID-1}]
"DisplayName"="Microsoft Outlook"
"Publisher"="Microsoft Corporation"
"InstallDate"="20260601"

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID-2}]
"DisplayName"="QuickBooks Pro"
"Publisher"="Intuit Inc."
"InstallDate"="20260610"

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID-3}]
"DisplayName"="Unknown Tool"
"Publisher"=""
"InstallDate"="20240101"
`), 0o644))

	// WMI Win32_Product CSV, locked down.
	wmiPath := filepath.Join(root, "Win32_Product_LAPTOP01.csv")
	must(t, os.WriteFile(wmiPath, []byte(`Name,Vendor,Version,InstallDate
Microsoft Office,Microsoft,16.0,20240101
Slack,Slack Technologies,4.36,20250601
`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(root, "random.csv"),
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
		t.Fatalf("want 2 (reg+wmi), got %d: %+v", len(got), got)
	}

	var reg, wmi Row
	for _, r := range got {
		switch r.FilePath {
		case regPath:
			reg = r
		case wmiPath:
			wmi = r
		}
	}
	if reg.ArtifactKind != KindRegUninstallHKLM {
		t.Fatalf("reg kind=%q", reg.ArtifactKind)
	}
	if reg.EntryCount != 3 {
		t.Fatalf("reg entry_count=%d want 3", reg.EntryCount)
	}
	if reg.MicrosoftPublisherCount != 1 {
		t.Fatalf("reg microsoft=%d want 1", reg.MicrosoftPublisherCount)
	}
	if reg.ThirdPartyPublisherCount != 1 {
		t.Fatalf("reg third_party=%d want 1", reg.ThirdPartyPublisherCount)
	}
	if reg.UnsignedPublisherCount != 1 {
		t.Fatalf("reg unsigned=%d want 1", reg.UnsignedPublisherCount)
	}
	if !reg.HasUnsignedPublisher {
		t.Fatal("reg must flag unsigned")
	}
	if reg.PIISoftwareCount < 2 {
		t.Fatalf("reg PII=%d want >=2 (Outlook+QuickBooks)", reg.PIISoftwareCount)
	}
	if !reg.HasRecentInstall {
		t.Fatal("reg must flag recent install (2026-06-01, 2026-06-10)")
	}
	if !reg.IsCredentialExposureRisk {
		t.Fatalf("reg readable + PII = exposure: %+v", reg)
	}

	if wmi.ArtifactKind != KindWMIWin32Product {
		t.Fatalf("wmi kind=%q", wmi.ArtifactKind)
	}
	if wmi.EntryCount != 2 {
		t.Fatalf("wmi entry_count=%d", wmi.EntryCount)
	}
	if wmi.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", wmi)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "uninstall_export_HKLM_x.reg"),
		[]byte(`[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\{X}]
"DisplayName"="X"
"Publisher"="Microsoft"
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "WIN_UNINSTALL_INVENTORY_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindRegUninstallHKLM {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-uninst"},
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
		{FilePath: "z", ArtifactKind: KindRegUninstallHKLM},
		{FilePath: "a", ArtifactKind: KindWMIWin32Product},
		{FilePath: "a", ArtifactKind: KindRegUninstallHKLM},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindRegUninstallHKLM {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
