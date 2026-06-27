package linuxsnap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindSnapYAML), "snap-yaml"},
		{string(KindSnapManifestYAML), "snap-manifest-yaml"},
		{string(KindSnapStateJSON), "snap-state-json"},
		{string(KindSnapSeed), "snap-seed"},
		{string(KindSnapDesktopEntry), "snap-desktop-entry"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(ConfinementStrict), "strict"},
		{string(ConfinementDevmode), "devmode"},
		{string(ConfinementClassic), "classic"},
		{string(SnapTypeApp), "app"},
		{string(SnapTypeBase), "base"},
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
		"snap.yaml",
		"manifest.yaml",
		"state.json",
		"firefox_2906.snap",
		"firefox.desktop",
	}
	no := []string{"", "random.txt", "cv.docx"}
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
		"/snap/firefox/2906/meta/snap.yaml":              KindSnapYAML,
		"/snap/firefox/2906/manifest.yaml":               KindSnapManifestYAML,
		"/var/lib/snapd/state.json":                      KindSnapStateJSON,
		"/var/lib/snapd/seed/snaps/firefox_2906.snap":    KindSnapSeed,
		"/snap/firefox/current/meta/gui/firefox.desktop": KindSnapDesktopEntry,
		"/random/snap.yaml":                              KindSnapYAML, // base = snap.yaml so still matches
		"/random/path.yaml":                              KindOther,
		"":                                               KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromPath(in); got != want {
			t.Fatalf("ArtifactKindFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSnapNameFromPath(t *testing.T) {
	cases := map[string]string{
		"/snap/firefox/2906/meta/snap.yaml":           "firefox",
		"/snap/postgresql/current/meta/snap.yaml":     "postgresql",
		"/snap/code/current/manifest.yaml":            "code",
		"/var/lib/snapd/seed/snaps/firefox_2906.snap": "",
		"/random/path.yaml":                           "",
	}
	for in, want := range cases {
		if got := SnapNameFromPath(in); got != want {
			t.Fatalf("SnapNameFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestConfinementFromText(t *testing.T) {
	cases := map[string]Confinement{
		"strict":  ConfinementStrict,
		"devmode": ConfinementDevmode,
		"classic": ConfinementClassic,
		"":        ConfinementEmpty,
		"other":   ConfinementOther,
	}
	for in, want := range cases {
		if got := ConfinementFromText(in); got != want {
			t.Fatalf("ConfinementFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSnapTypeFromText(t *testing.T) {
	cases := map[string]SnapType{
		"app":    SnapTypeApp,
		"gadget": SnapTypeGadget,
		"kernel": SnapTypeKernel,
		"base":   SnapTypeBase,
		"snapd":  SnapTypeSnapd,
		"core":   SnapTypeCore,
		"":       SnapTypeEmpty,
		"other":  SnapTypeOther,
	}
	for in, want := range cases {
		if got := SnapTypeFromText(in); got != want {
			t.Fatalf("SnapTypeFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPlugCapabilityKnown(t *testing.T) {
	yes := []string{
		"camera", "audio-record", "pulseaudio", "alsa",
		"location-observe", "location-control",
		"contacts-service", "home", "personal-files",
		"system-files", "removable-media", "network",
	}
	no := []string{"unknown-plug", "made-up-plug", ""}
	for _, v := range yes {
		if !PlugCapabilityKnown(v) {
			t.Fatalf("expected known: %q", v)
		}
	}
	for _, v := range no {
		if PlugCapabilityKnown(v) {
			t.Fatalf("expected NOT known: %q", v)
		}
	}
}

func TestPlugToField(t *testing.T) {
	cases := []struct {
		check func(Row) bool
		plug  string
	}{
		{plug: "camera", check: func(r Row) bool { return r.HasCameraPlug }},
		{plug: "audio-record", check: func(r Row) bool { return r.HasAudioPlug }},
		{plug: "alsa", check: func(r Row) bool { return r.HasAudioPlug }},
		{plug: "location-observe", check: func(r Row) bool { return r.HasLocationPlug }},
		{plug: "contacts-service", check: func(r Row) bool { return r.HasContactsPlug }},
		{plug: "home", check: func(r Row) bool { return r.HasHomePlug }},
		{plug: "personal-files", check: func(r Row) bool { return r.HasPersonalFilesPlug }},
		{plug: "system-files", check: func(r Row) bool { return r.HasPersonalFilesPlug }},
		{plug: "removable-media", check: func(r Row) bool { return r.HasPersonalFilesPlug }},
		{plug: "network", check: func(r Row) bool { return r.HasNetworkPlug }},
		{plug: "network-bind", check: func(r Row) bool { return r.HasNetworkPlug }},
	}
	for _, c := range cases {
		var r Row
		if !PlugToField(&r, c.plug) {
			t.Fatalf("PlugToField(%q) must succeed", c.plug)
		}
		if !c.check(r) {
			t.Fatalf("PlugToField(%q) set wrong field", c.plug)
		}
	}
	var r Row
	if PlugToField(&r, "unknown-plug") {
		t.Fatal("unknown plug must return false")
	}
}

func TestClassifyDPDS(t *testing.T) {
	cases := []struct {
		name string
		want DPDSClass
		r    Row
	}{
		{name: "catalogue firefox", r: Row{SnapName: "firefox"}, want: DPDSHandlesPII},
		{name: "catalogue keepassxc", r: Row{SnapName: "keepassxc"}, want: DPDSHandlesPII},
		{name: "catalogue gnucash", r: Row{SnapName: "gnucash"}, want: DPDSHandlesFinancial},
		{name: "catalogue code", r: Row{SnapName: "code"}, want: DPDSDevTool},
		{name: "catalogue vlc", r: Row{SnapName: "vlc"}, want: DPDSMediaTool},
		{name: "camera plug", r: Row{HasCameraPlug: true}, want: DPDSHandlesPII},
		{name: "audio plug", r: Row{HasAudioPlug: true}, want: DPDSHandlesPII},
		{name: "contacts plug", r: Row{HasContactsPlug: true}, want: DPDSHandlesPII},
		{name: "location plug", r: Row{HasLocationPlug: true}, want: DPDSHandlesPII},
		{name: "personal-files plug", r: Row{HasPersonalFilesPlug: true}, want: DPDSHandlesPII},
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

// -- ParseSnapYAML ------------------------------------------------

func TestParseSnapYAMLFirefox(t *testing.T) {
	body := []byte(`name: firefox
version: '120.0.1-1'
summary: Mozilla Firefox web browser
description: |
  Firefox is a powerful, extensible web browser.
license: MPL-2.0
base: core20
confinement: strict
type: app
website: https://www.mozilla.org/firefox
publisher: Mozilla
contact: https://support.mozilla.org/
plugs:
  audio-record:
  audio-playback:
  camera:
  home:
  network:
  removable-media:
apps:
  firefox:
    plugs:
      - audio-playback
      - camera
      - home
      - network
      - removable-media
`)
	f, ok := ParseSnapYAML(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.Name != "firefox" {
		t.Fatalf("name=%q", f.Name)
	}
	if f.Version != "120.0.1-1" {
		t.Fatalf("version=%q", f.Version)
	}
	if f.Summary != "Mozilla Firefox web browser" {
		t.Fatalf("summary=%q", f.Summary)
	}
	if f.License != "MPL-2.0" {
		t.Fatalf("license=%q", f.License)
	}
	if f.Base != "core20" {
		t.Fatalf("base=%q", f.Base)
	}
	if f.Confinement != ConfinementStrict {
		t.Fatalf("confinement=%q", f.Confinement)
	}
	if f.Type != SnapTypeApp {
		t.Fatalf("type=%q", f.Type)
	}
	if f.Publisher != "Mozilla" {
		t.Fatalf("publisher=%q", f.Publisher)
	}
	if f.Website != "https://www.mozilla.org/firefox" {
		t.Fatalf("website=%q", f.Website)
	}
	// Plugs should include camera, audio-record, audio-playback,
	// home, network, removable-media (deduped).
	plugSet := make(map[string]bool)
	for _, p := range f.Plugs {
		plugSet[p] = true
	}
	for _, want := range []string{
		"camera", "audio-record", "audio-playback",
		"home", "network", "removable-media",
	} {
		if !plugSet[want] {
			t.Fatalf("missing plug %q from %v", want, f.Plugs)
		}
	}
}

func TestParseSnapYAMLClassic(t *testing.T) {
	body := []byte(`name: code
version: '1.85.0'
summary: Visual Studio Code
license: Proprietary
base: core22
confinement: classic
type: app
website: https://code.visualstudio.com/
`)
	f, ok := ParseSnapYAML(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.Confinement != ConfinementClassic {
		t.Fatalf("confinement=%q want classic", f.Confinement)
	}
	if f.Name != "code" {
		t.Fatalf("name=%q", f.Name)
	}
}

func TestParseSnapYAMLEmpty(t *testing.T) {
	if _, ok := ParseSnapYAML([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateClassicConfinement(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind: KindSnapYAML,
		SnapName:     "code",
		Confinement:  ConfinementClassic,
		FileMode:     0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasClassicConfinement {
		t.Fatal("classic confinement must flag")
	}
}

func TestAnnotateRecentInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindSnapYAML,
		SnapName:            "firefox",
		InstallDateYYYYMMDD: "20260601",
		FileMode:            0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasRecentInstall {
		t.Fatalf("2026-06-01 within 30d: %+v", r)
	}
}

func TestAnnotateOldInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindSnapYAML,
		SnapName:            "firefox",
		InstallDateYYYYMMDD: "20240101",
		FileMode:            0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.HasRecentInstall {
		t.Fatal("> 30d old must NOT flag")
	}
}

func TestAnnotatePIIFromCatalogue(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind: KindSnapYAML,
		SnapName:     "firefox",
		FileMode:     0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.DPDSClass != DPDSHandlesPII {
		t.Fatalf("dp_ds=%q", r.DPDSClass)
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + name + PII = exposure")
	}
}

func TestAnnotatePIIFromPlug(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:    KindSnapYAML,
		SnapName:        "some-app",
		HasCameraPlug:   true,
		HasAudioPlug:    true,
		HasLocationPlug: true,
		FileMode:        0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.DPDSClass != DPDSHandlesPII {
		t.Fatalf("dp_ds=%q want PII", r.DPDSClass)
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + name + plug PII = exposure")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:  KindSnapYAML,
		SnapName:      "firefox",
		HasCameraPlug: true,
		FileMode:      0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoNameNoExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:  KindSnapYAML,
		HasCameraPlug: true,
		FileMode:      0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("no snap_name must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksSnapTree(t *testing.T) {
	tmp := t.TempDir()
	snapRoot := filepath.Join(tmp, "snap")

	// Firefox snap.yaml with camera + audio plugs, world-readable.
	ffDir := filepath.Join(snapRoot, "firefox", "current", "meta")
	must(t, os.MkdirAll(ffDir, 0o755))
	ffPath := filepath.Join(ffDir, "snap.yaml")
	must(t, os.WriteFile(ffPath, []byte(`name: firefox
version: '120.0.1-1'
summary: Mozilla Firefox web browser
license: MPL-2.0
base: core20
confinement: strict
type: app
website: https://www.mozilla.org/firefox
publisher: Mozilla
plugs:
  audio-record:
  audio-playback:
  camera:
  home:
  network:
`), 0o644))

	// Code snap.yaml with classic confinement, locked down.
	codeDir := filepath.Join(snapRoot, "code", "current", "meta")
	must(t, os.MkdirAll(codeDir, 0o755))
	codePath := filepath.Join(codeDir, "snap.yaml")
	must(t, os.WriteFile(codePath, []byte(`name: code
version: '1.85.0'
summary: Visual Studio Code
license: Proprietary
base: core22
confinement: classic
type: app
website: https://code.visualstudio.com/
`), 0o600))

	// Random ignored (.txt won't match candidate ext anyway).
	must(t, os.WriteFile(filepath.Join(ffDir, "random.txt"),
		[]byte(`noise`), 0o644))

	c := &fileCollector{
		installRoots: []string{snapRoot},
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
		t.Fatalf("want 2 (firefox+code), got %d: %+v", len(got), got)
	}

	var ff, code Row
	for _, r := range got {
		switch r.FilePath {
		case ffPath:
			ff = r
		case codePath:
			code = r
		}
	}
	if ff.ArtifactKind != KindSnapYAML {
		t.Fatalf("ff kind=%q", ff.ArtifactKind)
	}
	if ff.SnapName != "firefox" {
		t.Fatalf("ff name=%q", ff.SnapName)
	}
	if ff.SnapVersion != "120.0.1-1" {
		t.Fatalf("ff version=%q", ff.SnapVersion)
	}
	if ff.Publisher != "Mozilla" {
		t.Fatalf("ff publisher=%q", ff.Publisher)
	}
	if ff.License != "MPL-2.0" {
		t.Fatalf("ff license=%q", ff.License)
	}
	if ff.Website != "https://www.mozilla.org/firefox" {
		t.Fatalf("ff website=%q", ff.Website)
	}
	if ff.Confinement != ConfinementStrict {
		t.Fatalf("ff confinement=%q", ff.Confinement)
	}
	if ff.SnapType != SnapTypeApp {
		t.Fatalf("ff type=%q", ff.SnapType)
	}
	if !ff.HasCameraPlug || !ff.HasAudioPlug || !ff.HasHomePlug || !ff.HasNetworkPlug {
		t.Fatalf("ff plug flags: %+v", ff)
	}
	if ff.DPDSClass != DPDSHandlesPII {
		t.Fatalf("ff dp_ds=%q", ff.DPDSClass)
	}
	if !ff.IsCredentialExposureRisk {
		t.Fatalf("ff readable + name + PII = exposure: %+v", ff)
	}

	if code.SnapName != "code" {
		t.Fatalf("code name=%q", code.SnapName)
	}
	if code.Confinement != ConfinementClassic {
		t.Fatalf("code confinement=%q", code.Confinement)
	}
	if !code.HasClassicConfinement {
		t.Fatal("code must flag classic confinement")
	}
	if code.IsCredentialExposureRisk {
		t.Fatalf("code 0o600 must NOT flag: %+v", code)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-snap", "firefox", "current", "meta")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "snap.yaml"),
		[]byte(`name: firefox
version: '120'
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "SNAP_INVENTORY_DIR" {
				return filepath.Join(tmp, "custom-snap")
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
	if len(got) != 1 || got[0].ArtifactKind != KindSnapYAML {
		t.Fatalf("env: %+v", got)
	}
	if got[0].SnapName != "firefox" {
		t.Fatalf("env snap_name=%q", got[0].SnapName)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-snap"},
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
		{FilePath: "z", ArtifactKind: KindSnapYAML, SnapName: "z"},
		{FilePath: "a", ArtifactKind: KindSnapYAML, SnapName: "z"},
		{FilePath: "a", ArtifactKind: KindSnapYAML, SnapName: "a"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].SnapName != "a" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
