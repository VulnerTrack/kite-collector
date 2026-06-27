package winappxmanifest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindAppxManifestXML), "appxmanifest-xml"},
		{string(KindAppxBlockMapXML), "appxblockmap-xml"},
		{string(KindAppxMetadata), "appxmetadata"},
		{string(KindAppxSignatureP7X), "appxsignature-p7x"},
		{string(KindMSIXInstaller), "msix-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(DPDSHandlesPII), "handles-pii"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"AppxManifest.xml",
		"appxmanifest.xml",
		"AppxBlockMap.xml",
		"AppxSignature.p7x",
		"Microsoft.WindowsCalculator_11.2410.0.0_x64.msix",
		"acme.appxbundle",
	}
	no := []string{"", "random.xml", "factura.xml", "cv.docx"}
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
		`C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2410.0.0_x64__8wekyb3d8bbwe\AppxManifest.xml`:  KindAppxManifestXML,
		`C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2410.0.0_x64__8wekyb3d8bbwe\AppxBlockMap.xml`:  KindAppxBlockMapXML,
		`C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2410.0.0_x64__8wekyb3d8bbwe\AppxSignature.p7x`: KindAppxSignatureP7X,
		`C:\Admin\inventory\msix\Mozilla.Firefox_120.0.0.0_x64.msix`:                                                KindMSIXInstaller,
		`C:\random\path.xml`: KindOther,
		``:                   KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromPath(in); got != want {
			t.Fatalf("ArtifactKindFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPublisherCN(t *testing.T) {
	cases := map[string]string{
		"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US": "Microsoft Corporation",
		"CN=Mozilla Foundation, O=Mozilla, L=Mountain View, S=CA, C=US":                    "Mozilla Foundation",
		"CN=8wekyb3d8bbwe":      "8wekyb3d8bbwe",
		"Microsoft Corporation": "Microsoft Corporation",
		"":                      "",
	}
	for in, want := range cases {
		if got := PublisherCN(in); got != want {
			t.Fatalf("PublisherCN(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCapabilityToField(t *testing.T) {
	cases := []struct {
		check func(Row) bool
		cap   string
	}{
		{cap: "webcam", check: func(r Row) bool { return r.HasCameraCapability }},
		{cap: "microphone", check: func(r Row) bool { return r.HasMicrophoneCapability }},
		{cap: "location", check: func(r Row) bool { return r.HasLocationCapability }},
		{cap: "contacts", check: func(r Row) bool { return r.HasContactsCapability }},
		{cap: "appointments", check: func(r Row) bool { return r.HasAppointmentsCapability }},
		{cap: "phoneCallHistory", check: func(r Row) bool { return r.HasPhonecallCapability }},
		{cap: "phoneCallHistoryPublic", check: func(r Row) bool { return r.HasPhonecallCapability }},
		{cap: "documentsLibrary", check: func(r Row) bool { return r.HasDocumentsLib }},
		{cap: "picturesLibrary", check: func(r Row) bool { return r.HasPicturesLib }},
		{cap: "videosLibrary", check: func(r Row) bool { return r.HasVideosLib }},
		{cap: "musicLibrary", check: func(r Row) bool { return r.HasMusicLib }},
		{cap: "internetClient", check: func(r Row) bool { return r.HasInternetClient }},
		{cap: "internetClientServer", check: func(r Row) bool { return r.HasInternetServer }},
	}
	for _, c := range cases {
		var r Row
		if !CapabilityToField(&r, c.cap) {
			t.Fatalf("CapabilityToField(%q) must succeed", c.cap)
		}
		if !c.check(r) {
			t.Fatalf("CapabilityToField(%q) wrong field", c.cap)
		}
	}
	var r Row
	if CapabilityToField(&r, "unknownCapability") {
		t.Fatal("unknown capability must return false")
	}
}

func TestClassifyDPDS(t *testing.T) {
	cases := []struct {
		name string
		want DPDSClass
		r    Row
	}{
		{name: "catalogue Outlook", r: Row{PackageName: "Microsoft.Outlook"}, want: DPDSHandlesPII},
		{name: "catalogue Teams", r: Row{PackageName: "Microsoft.Teams"}, want: DPDSHandlesPII},
		{name: "catalogue Chrome", r: Row{PackageName: "Google.Chrome"}, want: DPDSHandlesPII},
		{name: "catalogue QuickBooks", r: Row{PackageName: "Intuit.QuickBooks"}, want: DPDSHandlesFinancial},
		{name: "catalogue VSCode", r: Row{PackageName: "Microsoft.VisualStudioCode"}, want: DPDSDevTool},
		{name: "catalogue VLC", r: Row{PackageName: "VideoLAN.VLC"}, want: DPDSMediaTool},
		{name: "camera capability", r: Row{HasCameraCapability: true}, want: DPDSHandlesPII},
		{name: "microphone capability", r: Row{HasMicrophoneCapability: true}, want: DPDSHandlesPII},
		{name: "location capability", r: Row{HasLocationCapability: true}, want: DPDSHandlesPII},
		{name: "contacts capability", r: Row{HasContactsCapability: true}, want: DPDSHandlesPII},
		{name: "documents library", r: Row{HasDocumentsLib: true}, want: DPDSHandlesPII},
		{name: "no signals", r: Row{}, want: DPDSUnknown},
		{name: "internet only (no PII)", r: Row{HasInternetClient: true}, want: DPDSUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyDPDS(&c.r); got != c.want {
				t.Fatalf("ClassifyDPDS=%q want %q (row=%+v)", got, c.want, c.r)
			}
		})
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

// -- ParseAppxManifest --------------------------------------------

func TestParseAppxManifestCalculator(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="Microsoft.WindowsCalculator"
            Publisher="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
            Version="11.2410.0.0" />
  <Properties>
    <DisplayName>Microsoft Calculator</DisplayName>
    <PublisherDisplayName>Microsoft Corporation</PublisherDisplayName>
    <Description>The trusted Microsoft Calculator.</Description>
    <Logo>Assets\StoreLogo.png</Logo>
  </Properties>
  <Capabilities>
    <Capability Name="internetClient" />
  </Capabilities>
</Package>`)
	f, ok := ParseAppxManifest(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.PackageName != "Microsoft.WindowsCalculator" {
		t.Fatalf("name=%q", f.PackageName)
	}
	if f.PackagePublisher != "Microsoft Corporation" {
		t.Fatalf("publisher=%q", f.PackagePublisher)
	}
	if f.Version != "11.2410.0.0" {
		t.Fatalf("version=%q", f.Version)
	}
	if f.DisplayName != "Microsoft Calculator" {
		t.Fatalf("display=%q", f.DisplayName)
	}
	if f.PublisherDisplayName != "Microsoft Corporation" {
		t.Fatalf("pubdisplay=%q", f.PublisherDisplayName)
	}
	if len(f.Capabilities) != 1 || f.Capabilities[0] != "internetClient" {
		t.Fatalf("capabilities=%v", f.Capabilities)
	}
}

func TestParseAppxManifestWithDeviceCaps(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="Microsoft.WindowsCamera"
            Publisher="CN=Microsoft Corporation"
            Version="2024.2410.0.0" />
  <Properties>
    <DisplayName>Camera</DisplayName>
  </Properties>
  <Capabilities>
    <Capability Name="internetClient" />
    <DeviceCapability Name="webcam" />
    <DeviceCapability Name="microphone" />
    <uap:Capability Name="picturesLibrary" />
    <uap:Capability Name="videosLibrary" />
  </Capabilities>
</Package>`)
	f, ok := ParseAppxManifest(body)
	if !ok {
		t.Fatal("must parse")
	}
	want := map[string]bool{
		"internetClient":  true,
		"webcam":          true,
		"microphone":      true,
		"picturesLibrary": true,
		"videosLibrary":   true,
	}
	got := make(map[string]bool)
	for _, c := range f.Capabilities {
		got[c] = true
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("missing capability %q in %v", k, f.Capabilities)
		}
	}
}

func TestParseAppxManifestEmpty(t *testing.T) {
	if _, ok := ParseAppxManifest([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

func TestParseAppxManifestNonXML(t *testing.T) {
	if _, ok := ParseAppxManifest([]byte(`{"foo":"bar"}`)); ok {
		t.Fatal("non-XML must NOT parse")
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateCameraCapability(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindAppxManifestXML,
		PackageName:         "Microsoft.WindowsCamera",
		HasCameraCapability: true,
		FileMode:            0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.DPDSClass != DPDSHandlesPII {
		t.Fatalf("dp_ds=%q", r.DPDSClass)
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + package + PII = exposure")
	}
}

func TestAnnotateRecentInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindAppxManifestXML,
		PackageName:         "Microsoft.Outlook",
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
		ArtifactKind:        KindAppxManifestXML,
		PackageName:         "Microsoft.Outlook",
		InstallDateYYYYMMDD: "20240101",
		FileMode:            0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.HasRecentInstall {
		t.Fatal("> 30d old must NOT flag")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindAppxManifestXML,
		PackageName:         "Microsoft.Outlook",
		HasCameraCapability: true,
		FileMode:            0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoNameNoExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindAppxManifestXML,
		HasCameraCapability: true,
		FileMode:            0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("no package_name must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksAppxTree(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Program Files", "WindowsApps")

	// Camera app with webcam + microphone capabilities,
	// world-readable.
	camDir := filepath.Join(root,
		"Microsoft.WindowsCamera_2024.2410.0.0_x64__8wekyb3d8bbwe")
	must(t, os.MkdirAll(camDir, 0o755))
	camPath := filepath.Join(camDir, "AppxManifest.xml")
	must(t, os.WriteFile(camPath, []byte(`<?xml version="1.0"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="Microsoft.WindowsCamera"
            Publisher="CN=Microsoft Corporation, O=Microsoft Corporation"
            Version="2024.2410.0.0" />
  <Properties>
    <DisplayName>Windows Camera</DisplayName>
    <PublisherDisplayName>Microsoft Corporation</PublisherDisplayName>
    <Description>Take photos and videos.</Description>
    <Logo>Assets\StoreLogo.png</Logo>
  </Properties>
  <Capabilities>
    <Capability Name="internetClient" />
    <DeviceCapability Name="webcam" />
    <DeviceCapability Name="microphone" />
    <uap:Capability Name="picturesLibrary" />
  </Capabilities>
</Package>`), 0o644))

	// Calculator with only internetClient — should NOT flag PII.
	// Locked down.
	calcDir := filepath.Join(root,
		"Microsoft.WindowsCalculator_11.2410.0.0_x64__8wekyb3d8bbwe")
	must(t, os.MkdirAll(calcDir, 0o755))
	calcPath := filepath.Join(calcDir, "AppxManifest.xml")
	must(t, os.WriteFile(calcPath, []byte(`<?xml version="1.0"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Microsoft.WindowsCalculator"
            Publisher="CN=Microsoft Corporation"
            Version="11.2410.0.0" />
  <Properties>
    <DisplayName>Calculator</DisplayName>
  </Properties>
  <Capabilities>
    <Capability Name="internetClient" />
  </Capabilities>
</Package>`), 0o600))

	// Random ignored (.bin doesn't match candidate ext).
	must(t, os.WriteFile(filepath.Join(camDir, "random.bin"),
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
		t.Fatalf("want 2 (camera+calculator), got %d: %+v", len(got), got)
	}

	var cam, calc Row
	for _, r := range got {
		switch r.FilePath {
		case camPath:
			cam = r
		case calcPath:
			calc = r
		}
	}
	if cam.ArtifactKind != KindAppxManifestXML {
		t.Fatalf("cam kind=%q", cam.ArtifactKind)
	}
	if cam.PackageName != "Microsoft.WindowsCamera" {
		t.Fatalf("cam name=%q", cam.PackageName)
	}
	if cam.PackagePublisher != "Microsoft Corporation" {
		t.Fatalf("cam publisher=%q", cam.PackagePublisher)
	}
	if cam.Version != "2024.2410.0.0" {
		t.Fatalf("cam version=%q", cam.Version)
	}
	if cam.DisplayName != "Windows Camera" {
		t.Fatalf("cam display=%q", cam.DisplayName)
	}
	if cam.CapabilitiesCount < 4 {
		t.Fatalf("cam caps=%d want >=4", cam.CapabilitiesCount)
	}
	if !cam.HasCameraCapability || !cam.HasMicrophoneCapability ||
		!cam.HasPicturesLib || !cam.HasInternetClient {
		t.Fatalf("cam cap flags: %+v", cam)
	}
	if cam.DPDSClass != DPDSHandlesPII {
		t.Fatalf("cam dp_ds=%q", cam.DPDSClass)
	}
	if !cam.IsCredentialExposureRisk {
		t.Fatalf("cam readable + package + PII = exposure: %+v", cam)
	}

	if calc.PackageName != "Microsoft.WindowsCalculator" {
		t.Fatalf("calc name=%q", calc.PackageName)
	}
	if calc.DPDSClass == DPDSHandlesPII {
		t.Fatalf("calc must NOT flag PII (only internetClient)")
	}
	if calc.IsCredentialExposureRisk {
		t.Fatalf("calc 0o600 + no PII must NOT flag: %+v", calc)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-appx",
		"Microsoft.WindowsCalculator")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "AppxManifest.xml"),
		[]byte(`<?xml version="1.0"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Microsoft.WindowsCalculator"
            Publisher="CN=Microsoft Corporation"
            Version="11.2410.0.0" />
  <Properties>
    <DisplayName>Calculator</DisplayName>
  </Properties>
</Package>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "WIN_APPX_DIR" {
				return filepath.Join(tmp, "custom-appx")
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
	if len(got) != 1 || got[0].ArtifactKind != KindAppxManifestXML {
		t.Fatalf("env: %+v", got)
	}
	if got[0].PackageName != "Microsoft.WindowsCalculator" {
		t.Fatalf("env name=%q", got[0].PackageName)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-appx"},
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
		{FilePath: "z", ArtifactKind: KindAppxManifestXML, PackageName: "z"},
		{FilePath: "a", ArtifactKind: KindAppxManifestXML, PackageName: "z"},
		{FilePath: "a", ArtifactKind: KindAppxManifestXML, PackageName: "a"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].PackageName != "a" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
