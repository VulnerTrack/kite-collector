package linuxflatpak

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindFlatpakMetadata), "flatpak-metadata"},
		{string(KindFlatpakMetainfoXML), "flatpak-metainfo-xml"},
		{string(KindFlatpakAppdataXML), "flatpak-appdata-xml"},
		{string(KindFlatpakDesktop), "flatpak-desktop"},
		{string(KindFlatpakRepoRef), "flatpak-repo-ref"},
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
		"metadata",
		"org.mozilla.firefox.desktop",
		"org.mozilla.firefox.metainfo.xml",
		"org.signal.signal.appdata.xml",
		"flathub.ref",
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

func TestArtifactKindFromPath(t *testing.T) {
	cases := map[string]ArtifactKind{
		"/var/lib/flatpak/app/org.mozilla.firefox/current/active/metadata":                     KindFlatpakMetadata,
		"/var/lib/flatpak/exports/share/metainfo/org.mozilla.firefox.metainfo.xml":             KindFlatpakMetainfoXML,
		"/var/lib/flatpak/exports/share/applications/org.signal.signal.appdata.xml":            KindFlatpakAppdataXML,
		"/var/lib/flatpak/exports/share/applications/org.mozilla.firefox.desktop":              KindFlatpakDesktop,
		"/var/lib/flatpak/repo/refs/remotes/flathub/app/org.mozilla.firefox/x86_64/stable.ref": KindFlatpakRepoRef,
		"/random/path.xml": KindOther,
		"":                 KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromPath(in); got != want {
			t.Fatalf("ArtifactKindFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAppIDFromPath(t *testing.T) {
	cases := map[string]string{
		"/var/lib/flatpak/app/org.mozilla.firefox/current/active/metadata":         "org.mozilla.firefox",
		"/var/lib/flatpak/exports/share/metainfo/org.mozilla.firefox.metainfo.xml": "org.mozilla.firefox",
		"/var/lib/flatpak/exports/share/applications/org.signal.signal.desktop":    "org.signal.signal",
		"/random/path.xml": "",
	}
	for in, want := range cases {
		if got := AppIDFromPath(in); got != want {
			t.Fatalf("AppIDFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPublisherFromAppID(t *testing.T) {
	cases := map[string]string{
		"org.mozilla.firefox":     "mozilla",
		"com.spotify.Client":      "spotify",
		"us.zoom.Zoom":            "zoom",
		"com.valvesoftware.Steam": "valvesoftware",
		"single":                  "",
		"":                        "",
	}
	for in, want := range cases {
		if got := PublisherFromAppID(in); got != want {
			t.Fatalf("PublisherFromAppID(%q)=%q want %q", in, got, want)
		}
	}
}

func TestContextValueToFields(t *testing.T) {
	cases := []struct {
		check func(Row) bool
		key   string
		value string
	}{
		{key: "sockets", value: "x11;wayland;pulseaudio", check: func(r Row) bool {
			return r.HasX11Socket && r.HasWaylandSocket && r.HasPulseaudioSocket
		}},
		{key: "sockets", value: "fallback-x11;wayland", check: func(r Row) bool {
			return r.HasX11Socket && r.HasWaylandSocket
		}},
		{key: "devices", value: "all", check: func(r Row) bool { return r.HasCameraDevice }},
		{key: "filesystems", value: "home;xdg-download", check: func(r Row) bool {
			return r.HasHomeFilesystem
		}},
		{key: "filesystems", value: "host;home", check: func(r Row) bool {
			return r.HasHostFilesystem && r.HasHomeFilesystem
		}},
		{key: "shared", value: "network;ipc", check: func(r Row) bool { return r.HasNetworkShared }},
	}
	for _, c := range cases {
		var r Row
		if !ContextValueToFields(&r, c.key, c.value) {
			t.Fatalf("ContextValueToFields(%q,%q) must match", c.key, c.value)
		}
		if !c.check(r) {
			t.Fatalf("ContextValueToFields(%q,%q) wrong field: %+v",
				c.key, c.value, r)
		}
	}
}

func TestClassifyDPDS(t *testing.T) {
	cases := []struct {
		name string
		want DPDSClass
		r    Row
	}{
		{name: "catalogue firefox", r: Row{AppID: "org.mozilla.firefox"}, want: DPDSHandlesPII},
		{name: "catalogue slack", r: Row{AppID: "com.slack.slack"}, want: DPDSHandlesPII},
		{name: "catalogue gnucash", r: Row{AppID: "org.gnucash.gnucash"}, want: DPDSHandlesFinancial},
		{name: "catalogue vscode", r: Row{AppID: "com.visualstudio.code"}, want: DPDSDevTool},
		{name: "catalogue vlc", r: Row{AppID: "org.videolan.vlc"}, want: DPDSMediaTool},
		{name: "camera device", r: Row{HasCameraDevice: true}, want: DPDSHandlesPII},
		{name: "pulseaudio socket", r: Row{HasPulseaudioSocket: true}, want: DPDSHandlesPII},
		{name: "host filesystem", r: Row{HasHostFilesystem: true}, want: DPDSHandlesPII},
		{name: "home filesystem", r: Row{HasHomeFilesystem: true}, want: DPDSHandlesPII},
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

// -- ParseFlatpakMetadata -----------------------------------------

func TestParseFlatpakMetadataFirefox(t *testing.T) {
	body := []byte(`[Application]
name=org.mozilla.firefox
runtime=org.freedesktop.Platform/x86_64/23.08
sdk=org.freedesktop.Sdk/x86_64/23.08
command=firefox

[Context]
shared=network;ipc
sockets=x11;wayland;pulseaudio;pcsc;cups
devices=all
filesystems=home;xdg-download;xdg-documents
`)
	f, ok := ParseFlatpakMetadata(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.AppID != "org.mozilla.firefox" {
		t.Fatalf("app_id=%q", f.AppID)
	}
	if f.Runtime != "org.freedesktop.Platform/x86_64/23.08" {
		t.Fatalf("runtime=%q", f.Runtime)
	}
	if f.Sockets != "x11;wayland;pulseaudio;pcsc;cups" {
		t.Fatalf("sockets=%q", f.Sockets)
	}
	if f.Devices != "all" {
		t.Fatalf("devices=%q", f.Devices)
	}
	if f.Filesystems != "home;xdg-download;xdg-documents" {
		t.Fatalf("filesystems=%q", f.Filesystems)
	}
	if f.Shared != "network;ipc" {
		t.Fatalf("shared=%q", f.Shared)
	}
}

func TestParseFlatpakMetadataEmpty(t *testing.T) {
	if _, ok := ParseFlatpakMetadata([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- ParseMetainfoXML ---------------------------------------------

func TestParseMetainfoXML(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop">
  <id>org.mozilla.firefox</id>
  <name>Firefox</name>
  <summary>Mozilla Firefox web browser</summary>
  <description>Firefox is a fast, secure web browser.</description>
  <project_license>MPL-2.0</project_license>
  <url type="homepage">https://www.mozilla.org/firefox</url>
  <url type="bugtracker">https://bugzilla.mozilla.org</url>
  <releases>
    <release version="120.0.1" date="2026-06-15"/>
    <release version="119.0" date="2026-05-01"/>
  </releases>
</component>`)
	f, ok := ParseMetainfoXML(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.AppID != "org.mozilla.firefox" {
		t.Fatalf("app_id=%q", f.AppID)
	}
	if f.Name != "Firefox" {
		t.Fatalf("name=%q", f.Name)
	}
	if f.Summary != "Mozilla Firefox web browser" {
		t.Fatalf("summary=%q", f.Summary)
	}
	if f.License != "MPL-2.0" {
		t.Fatalf("license=%q", f.License)
	}
	if f.Homepage != "https://www.mozilla.org/firefox" {
		t.Fatalf("homepage=%q", f.Homepage)
	}
	if f.Version != "120.0.1" {
		t.Fatalf("version=%q", f.Version)
	}
	if f.ReleaseDate != "2026-06-15" {
		t.Fatalf("date=%q", f.ReleaseDate)
	}
}

func TestParseMetainfoXMLEmpty(t *testing.T) {
	if _, ok := ParseMetainfoXML([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateHostFilesystem(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:      KindFlatpakMetadata,
		AppID:             "com.example.app",
		HasHostFilesystem: true,
		FileMode:          0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.DPDSClass != DPDSHandlesPII {
		t.Fatalf("dp_ds=%q want PII (host fs)", r.DPDSClass)
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + app_id + PII = exposure")
	}
}

func TestAnnotateRecentInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindFlatpakMetadata,
		AppID:               "org.mozilla.firefox",
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
		ArtifactKind:        KindFlatpakMetadata,
		AppID:               "com.example.app",
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
		ArtifactKind:    KindFlatpakMetadata,
		AppID:           "org.mozilla.firefox",
		HasCameraDevice: true,
		FileMode:        0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoAppIDNoExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:    KindFlatpakMetadata,
		HasCameraDevice: true,
		FileMode:        0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("no app_id must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksFlatpakTree(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "var", "lib", "flatpak")

	// Firefox metadata with PII permissions, world-readable.
	ffDir := filepath.Join(root, "app", "org.mozilla.firefox",
		"current", "active")
	must(t, os.MkdirAll(ffDir, 0o755))
	ffPath := filepath.Join(ffDir, "metadata")
	must(t, os.WriteFile(ffPath, []byte(`[Application]
name=org.mozilla.firefox
runtime=org.freedesktop.Platform/x86_64/23.08
command=firefox

[Context]
shared=network;ipc
sockets=x11;wayland;pulseaudio
devices=all
filesystems=home;xdg-download
`), 0o644))

	// metainfo.xml with rich AppStream data, locked down.
	metaDir := filepath.Join(root, "exports", "share", "metainfo")
	must(t, os.MkdirAll(metaDir, 0o755))
	metaPath := filepath.Join(metaDir, "org.mozilla.firefox.metainfo.xml")
	must(t, os.WriteFile(metaPath, []byte(`<?xml version="1.0"?>
<component type="desktop">
<id>org.mozilla.firefox</id>
<name>Firefox</name>
<summary>Mozilla Firefox web browser</summary>
<project_license>MPL-2.0</project_license>
<url type="homepage">https://www.mozilla.org/firefox</url>
<releases>
<release version="120.0.1" date="2026-06-15"/>
</releases>
</component>`), 0o600))

	// Random ignored (.bin doesn't match candidate ext anyway).
	must(t, os.WriteFile(filepath.Join(ffDir, "random.bin"),
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
		t.Fatalf("want 2 (metadata+metainfo), got %d: %+v", len(got), got)
	}

	var meta, mi Row
	for _, r := range got {
		switch r.FilePath {
		case ffPath:
			meta = r
		case metaPath:
			mi = r
		}
	}
	if meta.ArtifactKind != KindFlatpakMetadata {
		t.Fatalf("meta kind=%q", meta.ArtifactKind)
	}
	if meta.AppID != "org.mozilla.firefox" {
		t.Fatalf("meta app_id=%q", meta.AppID)
	}
	if meta.Publisher != "mozilla" {
		t.Fatalf("meta publisher=%q", meta.Publisher)
	}
	if meta.Runtime != "org.freedesktop.Platform/x86_64/23.08" {
		t.Fatalf("meta runtime=%q", meta.Runtime)
	}
	if !meta.HasX11Socket || !meta.HasWaylandSocket || !meta.HasPulseaudioSocket {
		t.Fatalf("meta socket flags: %+v", meta)
	}
	if !meta.HasCameraDevice {
		t.Fatal("meta devices=all must flag camera")
	}
	if !meta.HasHomeFilesystem {
		t.Fatal("meta filesystems=home must flag")
	}
	if !meta.HasNetworkShared {
		t.Fatal("meta shared=network must flag")
	}
	if meta.DPDSClass != DPDSHandlesPII {
		t.Fatalf("meta dp_ds=%q", meta.DPDSClass)
	}
	if !meta.IsCredentialExposureRisk {
		t.Fatalf("meta readable + app + PII = exposure: %+v", meta)
	}

	if mi.ArtifactKind != KindFlatpakMetainfoXML {
		t.Fatalf("mi kind=%q", mi.ArtifactKind)
	}
	if mi.DisplayName != "Firefox" {
		t.Fatalf("mi name=%q", mi.DisplayName)
	}
	if mi.License != "MPL-2.0" {
		t.Fatalf("mi license=%q", mi.License)
	}
	if mi.Homepage != "https://www.mozilla.org/firefox" {
		t.Fatalf("mi homepage=%q", mi.Homepage)
	}
	if mi.Version != "120.0.1" {
		t.Fatalf("mi version=%q", mi.Version)
	}
	// metainfo.xml install_date should override mtime with the
	// release date.
	if mi.InstallDateYYYYMMDD != "20260615" {
		t.Fatalf("mi install_date=%q (should be release date)", mi.InstallDateYYYYMMDD)
	}
	if mi.IsCredentialExposureRisk {
		t.Fatalf("mi 0o600 must NOT flag: %+v", mi)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-flatpak",
		"app", "org.mozilla.firefox", "current", "active")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "metadata"),
		[]byte(`[Application]
name=org.mozilla.firefox
runtime=org.freedesktop.Platform
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "FLATPAK_INVENTORY_DIR" {
				return filepath.Join(tmp, "custom-flatpak")
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
	if len(got) != 1 || got[0].ArtifactKind != KindFlatpakMetadata {
		t.Fatalf("env: %+v", got)
	}
	if got[0].AppID != "org.mozilla.firefox" {
		t.Fatalf("env app_id=%q", got[0].AppID)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-flatpak"},
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
		{FilePath: "z", ArtifactKind: KindFlatpakMetadata, AppID: "z"},
		{FilePath: "a", ArtifactKind: KindFlatpakMetadata, AppID: "z"},
		{FilePath: "a", ArtifactKind: KindFlatpakMetadata, AppID: "a"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].AppID != "a" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
