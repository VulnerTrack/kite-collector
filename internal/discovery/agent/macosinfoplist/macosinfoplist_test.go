package macosinfoplist

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindAppInfoPlist), "app-info-plist"},
		{string(KindLicensePlist), "license-plist"},
		{string(KindEmbeddedInfoPlist), "embedded-info-plist"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(DPDSHandlesPII), "handles-pii"},
		{string(DPDSHandlesFinancial), "handles-financial"},
		{string(DPDSHandlesPHI), "handles-phi"},
		{string(DPDSHandlesBiometric), "handles-biometric"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"Info.plist",
		"info.plist",
		"License.plist",
		"license.plist",
		"License-Info.plist",
		"Registration.plist",
		"Info-Extras.plist",
	}
	no := []string{"", "random.plist", "data.xml", "cv.docx"}
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
		"/Applications/Microsoft Outlook.app/Contents/Info.plist":                             KindAppInfoPlist,
		"/Applications/Adobe Acrobat.app/Contents/Info.plist":                                 KindAppInfoPlist,
		"/Library/Application Support/Microsoft/MAU/Microsoft Update.app/Contents/Info.plist": KindAppInfoPlist,
		"/Library/Application Support/Microsoft/MAU/Info.plist":                               KindEmbeddedInfoPlist,
		"/Library/Application Support/Intuit/QuickBooks/license.plist":                        KindLicensePlist,
		"/Library/Application Support/Adobe/registration.plist":                               KindLicensePlist,
		"/random.plist": KindOther,
		"":              KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromPath(in); got != want {
			t.Fatalf("ArtifactKindFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPublisherFromBundleID(t *testing.T) {
	cases := map[string]string{
		"com.microsoft.Outlook":    "microsoft",
		"com.google.Chrome":        "google",
		"com.adobe.Acrobat.Reader": "adobe",
		"org.mozilla.firefox":      "mozilla",
		"us.zoom.xos":              "zoom",
		"single":                   "",
		"":                         "",
	}
	for in, want := range cases {
		if got := PublisherFromBundleID(in); got != want {
			t.Fatalf("PublisherFromBundleID(%q)=%q want %q", in, got, want)
		}
	}
}

func TestProductFromBundleID(t *testing.T) {
	cases := map[string]string{
		"com.microsoft.Outlook": "Outlook",
		"com.adobe.Acrobat":     "Acrobat",
		"org.mozilla.firefox":   "firefox",
		"single":                "single",
	}
	for in, want := range cases {
		if got := ProductFromBundleID(in); got != want {
			t.Fatalf("ProductFromBundleID(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPrivacyKeyToField(t *testing.T) {
	cases := []struct {
		check func(Row) bool
		key   string
	}{
		{key: "NSCameraUsageDescription", check: func(r Row) bool { return r.HasCameraAccess }},
		{key: "NSMicrophoneUsageDescription", check: func(r Row) bool { return r.HasMicrophoneAccess }},
		{key: "NSContactsUsageDescription", check: func(r Row) bool { return r.HasContactsAccess }},
		{key: "NSPhotoLibraryUsageDescription", check: func(r Row) bool { return r.HasPhotosAccess }},
		{key: "NSCalendarsUsageDescription", check: func(r Row) bool { return r.HasCalendarAccess }},
		{key: "NSLocationWhenInUseUsageDescription", check: func(r Row) bool { return r.HasLocationAccess }},
		{key: "NSHealthShareUsageDescription", check: func(r Row) bool { return r.HasHealthAccess }},
		{key: "NSFaceIDUsageDescription", check: func(r Row) bool { return r.HasFaceIDAccess }},
		{key: "NSAppleEventsUsageDescription", check: func(r Row) bool { return r.HasAppleEventsAccess }},
	}
	for _, c := range cases {
		var r Row
		if !PrivacyKeyToField(&r, c.key) {
			t.Fatalf("PrivacyKeyToField(%q) should match", c.key)
		}
		if !c.check(r) {
			t.Fatalf("PrivacyKeyToField(%q) did not set the right field", c.key)
		}
	}
	// Unknown key returns false.
	var r Row
	if PrivacyKeyToField(&r, "NSUnknownUsageDescription") {
		t.Fatal("unknown key must return false")
	}
}

func TestClassifyDPDS(t *testing.T) {
	cases := []struct {
		name string
		want DPDSClass
		r    Row
	}{
		{name: "catalogue match (Outlook)", r: Row{BundleID: "com.microsoft.Outlook"}, want: DPDSHandlesPII},
		{name: "catalogue match (QuickBooks)", r: Row{BundleID: "com.intuit.QuickBooksMac"}, want: DPDSHandlesFinancial},
		{name: "health key", r: Row{HasHealthAccess: true}, want: DPDSHandlesPHI},
		{name: "faceid key", r: Row{HasFaceIDAccess: true}, want: DPDSHandlesBiometric},
		{name: "camera only", r: Row{HasCameraAccess: true}, want: DPDSHandlesPII},
		{name: "contacts only", r: Row{HasContactsAccess: true}, want: DPDSHandlesPII},
		{name: "location only", r: Row{HasLocationAccess: true}, want: DPDSHandlesPII},
		{name: "no signals", r: Row{}, want: DPDSUnknown},
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

// -- ParseInfoPlist ----------------------------------------------

func TestParseInfoPlistOutlook(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.microsoft.Outlook</string>
    <key>CFBundleDisplayName</key>
    <string>Microsoft Outlook</string>
    <key>CFBundleShortVersionString</key>
    <string>16.94</string>
    <key>NSHumanReadableCopyright</key>
    <string>© 2024 Microsoft Corporation</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.productivity</string>
    <key>NSCameraUsageDescription</key>
    <string>Outlook needs camera access for meetings.</string>
    <key>NSMicrophoneUsageDescription</key>
    <string>Outlook needs microphone access for meetings.</string>
    <key>NSContactsUsageDescription</key>
    <string>Outlook syncs contacts.</string>
</dict>
</plist>`)
	f, ok := ParseInfoPlist(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.BundleID != "com.microsoft.Outlook" {
		t.Fatalf("bundle=%q", f.BundleID)
	}
	if f.DisplayName != "Microsoft Outlook" {
		t.Fatalf("display=%q", f.DisplayName)
	}
	if f.Version != "16.94" {
		t.Fatalf("version=%q", f.Version)
	}
	if f.Copyright == "" {
		t.Fatal("copyright must be set")
	}
	if f.Category != "public.app-category.productivity" {
		t.Fatalf("category=%q", f.Category)
	}
	if len(f.PrivacyKeys) != 3 {
		t.Fatalf("privacy keys=%d want 3 (camera/microphone/contacts): %+v", len(f.PrivacyKeys), f.PrivacyKeys)
	}
}

func TestParseInfoPlistEmpty(t *testing.T) {
	if _, ok := ParseInfoPlist([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

func TestParseInfoPlistBinary(t *testing.T) {
	// Binary plist signature.
	if _, ok := ParseInfoPlist([]byte("bplist00\x00\x00")); ok {
		t.Fatal("binary plist must NOT parse (out of scope)")
	}
}

func TestParseInfoPlistNonPlist(t *testing.T) {
	if _, ok := ParseInfoPlist([]byte(`{"foo":"bar"}`)); ok {
		t.Fatal("JSON must NOT parse")
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateCameraPII(t *testing.T) {
	r := Row{
		ArtifactKind:    KindAppInfoPlist,
		BundleID:        "com.example.cam",
		HasCameraAccess: true,
		FileMode:        0o644,
	}
	AnnotateSecurity(&r)
	if r.DPDSClass != DPDSHandlesPII {
		t.Fatalf("dp_ds=%q", r.DPDSClass)
	}
	if !r.IsPIIHandling {
		t.Fatal("camera must flag PII")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + bundle + PII = exposure")
	}
}

func TestAnnotateHealthPHI(t *testing.T) {
	r := Row{
		ArtifactKind:    KindAppInfoPlist,
		BundleID:        "com.example.healthapp",
		HasHealthAccess: true,
		FileMode:        0o644,
	}
	AnnotateSecurity(&r)
	if r.DPDSClass != DPDSHandlesPHI {
		t.Fatalf("dp_ds=%q want PHI", r.DPDSClass)
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + bundle + PHI = exposure")
	}
}

func TestAnnotateFaceIDBiometric(t *testing.T) {
	r := Row{
		ArtifactKind:    KindAppInfoPlist,
		BundleID:        "com.example.bankapp",
		HasFaceIDAccess: true,
		FileMode:        0o600,
	}
	AnnotateSecurity(&r)
	if r.DPDSClass != DPDSHandlesBiometric {
		t.Fatalf("dp_ds=%q want biometric", r.DPDSClass)
	}
	if !r.IsPIIHandling {
		t.Fatal("FaceID must flag PII")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateCatalogueOutlook(t *testing.T) {
	r := Row{
		ArtifactKind: KindAppInfoPlist,
		BundleID:     "com.microsoft.Outlook",
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if r.DPDSClass != DPDSHandlesPII {
		t.Fatalf("dp_ds=%q", r.DPDSClass)
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("Outlook readable = exposure")
	}
}

func TestAnnotateCatalogueQuickBooks(t *testing.T) {
	r := Row{
		ArtifactKind: KindAppInfoPlist,
		BundleID:     "com.intuit.QuickBooksMac",
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if r.DPDSClass != DPDSHandlesFinancial {
		t.Fatalf("dp_ds=%q want financial", r.DPDSClass)
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("QuickBooks readable = exposure")
	}
}

func TestAnnotateNoSignalsClean(t *testing.T) {
	r := Row{
		ArtifactKind: KindAppInfoPlist,
		BundleID:     "com.example.calculator",
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if r.IsPIIHandling {
		t.Fatal("no signals must NOT flag PII")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("no PII must NOT flag exposure")
	}
}

func TestAnnotateNoBundleNoExposure(t *testing.T) {
	r := Row{
		ArtifactKind:    KindAppInfoPlist,
		HasCameraAccess: true,
		FileMode:        0o644,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("no bundle_id must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksAppTree(t *testing.T) {
	tmp := t.TempDir()
	apps := filepath.Join(tmp, "Applications")

	// PII-handling Outlook with privacy keys, world-readable.
	outDir := filepath.Join(apps, "Microsoft Outlook.app", "Contents")
	must(t, os.MkdirAll(outDir, 0o755))
	outPath := filepath.Join(outDir, "Info.plist")
	must(t, os.WriteFile(outPath, []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.microsoft.Outlook</string>
    <key>CFBundleDisplayName</key>
    <string>Microsoft Outlook</string>
    <key>CFBundleShortVersionString</key>
    <string>16.94</string>
    <key>NSHumanReadableCopyright</key>
    <string>© 2024 Microsoft Corporation</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.productivity</string>
    <key>NSCameraUsageDescription</key>
    <string>Meetings need camera.</string>
    <key>NSMicrophoneUsageDescription</key>
    <string>Meetings need microphone.</string>
    <key>NSContactsUsageDescription</key>
    <string>Sync contacts.</string>
</dict>
</plist>`), 0o644))

	// Financial QuickBooks, locked down.
	qbDir := filepath.Join(apps, "QuickBooks Mac.app", "Contents")
	must(t, os.MkdirAll(qbDir, 0o755))
	qbPath := filepath.Join(qbDir, "Info.plist")
	must(t, os.WriteFile(qbPath, []byte(`<?xml version="1.0"?>
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.intuit.QuickBooksMac</string>
    <key>CFBundleDisplayName</key>
    <string>QuickBooks Mac</string>
    <key>CFBundleShortVersionString</key>
    <string>2025.1</string>
    <key>NSHumanReadableCopyright</key>
    <string>© 2024 Intuit Inc.</string>
</dict>
</plist>`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(apps, "Random.plist"),
		[]byte(`noise`), 0o644))

	c := &fileCollector{
		installRoots: []string{apps},
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
		t.Fatalf("want 2 (Outlook+QuickBooks), got %d: %+v", len(got), got)
	}

	var out, qb Row
	for _, r := range got {
		switch r.FilePath {
		case outPath:
			out = r
		case qbPath:
			qb = r
		}
	}
	if out.ArtifactKind != KindAppInfoPlist {
		t.Fatalf("out kind=%q", out.ArtifactKind)
	}
	if out.BundleID != "com.microsoft.Outlook" {
		t.Fatalf("out bundle=%q", out.BundleID)
	}
	if out.Publisher != "microsoft" {
		t.Fatalf("out publisher=%q", out.Publisher)
	}
	if out.DisplayName != "Microsoft Outlook" {
		t.Fatalf("out display=%q", out.DisplayName)
	}
	if out.Version != "16.94" {
		t.Fatalf("out version=%q", out.Version)
	}
	if out.Category != "public.app-category.productivity" {
		t.Fatalf("out category=%q", out.Category)
	}
	if out.PrivacyKeysCount < 3 {
		t.Fatalf("out privacy keys=%d want >=3", out.PrivacyKeysCount)
	}
	if !out.HasCameraAccess || !out.HasMicrophoneAccess || !out.HasContactsAccess {
		t.Fatalf("out privacy flags: %+v", out)
	}
	if out.DPDSClass != DPDSHandlesPII {
		t.Fatalf("out dp_ds=%q", out.DPDSClass)
	}
	if !out.IsPIIHandling {
		t.Fatal("out must flag PII")
	}
	if !out.IsCredentialExposureRisk {
		t.Fatalf("out readable + bundle + PII = exposure: %+v", out)
	}

	if qb.ArtifactKind != KindAppInfoPlist {
		t.Fatalf("qb kind=%q", qb.ArtifactKind)
	}
	if qb.DPDSClass != DPDSHandlesFinancial {
		t.Fatalf("qb dp_ds=%q", qb.DPDSClass)
	}
	if qb.IsCredentialExposureRisk {
		t.Fatalf("qb 0o600 must NOT flag: %+v", qb)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "plists", "X.app", "Contents")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "Info.plist"),
		[]byte(`<?xml version="1.0"?>
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.x</string>
    <key>CFBundleDisplayName</key>
    <string>X</string>
</dict>
</plist>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "MACOS_PLIST_DIR" {
				return filepath.Join(tmp, "plists")
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
	if len(got) != 1 || got[0].ArtifactKind != KindAppInfoPlist {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-plist"},
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
		{FilePath: "z", ArtifactKind: KindAppInfoPlist, BundleID: "z"},
		{FilePath: "a", ArtifactKind: KindAppInfoPlist, BundleID: "z"},
		{FilePath: "a", ArtifactKind: KindAppInfoPlist, BundleID: "a"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].BundleID != "a" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
