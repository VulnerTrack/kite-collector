package browserext

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(BrowserChrome), "chrome"},
		{string(BrowserChromium), "chromium"},
		{string(BrowserEdge), "edge"},
		{string(BrowserBrave), "brave"},
		{string(BrowserOpera), "opera"},
		{string(BrowserVivaldi), "vivaldi"},
		{string(BrowserArc), "arc"},
		{string(BrowserFirefox), "firefox"},
		{string(BrowserFirefoxESR), "firefox-esr"},
		{string(BrowserLibrewolf), "librewolf"},
		{string(BrowserSafari), "safari"},
		{string(BrowserUnknown), "unknown"},
		{string(InstallStore), "store"},
		{string(InstallSideloaded), "sideloaded"},
		{string(InstallEnterprisePolicy), "enterprise-policy"},
		{string(InstallDeveloper), "developer"},
		{string(InstallSystem), "system"},
		{string(InstallUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestEncodeStringList(t *testing.T) {
	if got := EncodeStringList(nil); got != "[]" {
		t.Fatalf("nil = %q, want []", got)
	}
	if got := EncodeStringList([]string{}); got != "[]" {
		t.Fatalf("empty = %q, want []", got)
	}
	got := EncodeStringList([]string{"tabs", "storage"})
	if got != `["tabs","storage"]` {
		t.Fatalf("got %q", got)
	}
}

func TestIsBroadHostPermission(t *testing.T) {
	broad := []string{
		"<all_urls>",
		"*://*/*",
		"http://*/*",
		"https://*/*",
		"*://*:*/*",
		"file:///*",
		"*://*",
		"*://*/",
	}
	for _, p := range broad {
		if !IsBroadHostPermission(p) {
			t.Fatalf("%q must be broad", p)
		}
	}
	narrow := []string{
		"",
		"https://example.com/*",
		"https://*.example.com/*",
		"https://docs.google.com/*",
		"chrome://extensions/",
	}
	for _, p := range narrow {
		if IsBroadHostPermission(p) {
			t.Fatalf("%q must NOT be broad", p)
		}
	}
}

func TestHasBroadPermissionsTrueWhenAnyBroad(t *testing.T) {
	e := Extension{HostPermissions: []string{"https://example.com/*", "<all_urls>"}}
	if !HasBroadPermissions(e) {
		t.Fatalf("any broad permission must trigger the flag")
	}
	e2 := Extension{HostPermissions: []string{"https://example.com/*"}}
	if HasBroadPermissions(e2) {
		t.Fatalf("scoped permissions must not trigger")
	}
}

func TestIsManifestV2DeprecatedChromiumOnly(t *testing.T) {
	chromiumMV2 := Extension{Browser: BrowserChrome, ManifestVersion: 2}
	if !IsManifestV2Deprecated(chromiumMV2) {
		t.Fatalf("Chrome MV2 must be deprecated")
	}
	chromiumMV3 := Extension{Browser: BrowserChrome, ManifestVersion: 3}
	if IsManifestV2Deprecated(chromiumMV3) {
		t.Fatalf("Chrome MV3 is current, not deprecated")
	}
	firefoxMV2 := Extension{Browser: BrowserFirefox, ManifestVersion: 2}
	if IsManifestV2Deprecated(firefoxMV2) {
		t.Fatalf("Firefox MV2 still supported")
	}
}

func TestClassifyInstallSource(t *testing.T) {
	cases := map[string]InstallSource{
		"": InstallStore, // empty = store default
		"https://clients2.google.com/service/update2/crx":         InstallStore,
		"https://chrome.google.com/webstore/update":               InstallStore,
		"https://edge.microsoft.com/extensionwebstorebase/v1/crx": InstallStore,
		"https://addons.opera.com/somepath":                       InstallStore,
		"https://internal.corp.example.com/extensions/policy.xml": InstallEnterprisePolicy,
		"http://attacker.example/crx":                             InstallEnterprisePolicy,
	}
	for in, want := range cases {
		if got := classifyInstallSource(in); got != want {
			t.Fatalf("classifyInstallSource(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSortExtensionsDeterministic(t *testing.T) {
	in := []Extension{
		{Browser: BrowserChrome, Profile: "Default", ExtensionID: "z"},
		{Browser: BrowserFirefox, Profile: "default", ExtensionID: "a"},
		{Browser: BrowserChrome, Profile: "Default", ExtensionID: "a"},
		{Browser: BrowserChrome, Profile: "Profile 1", ExtensionID: "m"},
	}
	SortExtensions(in)
	// chrome < firefox; within chrome: Default < Profile 1; within Default: a < z
	want := []struct {
		b  Browser
		p  string
		id string
	}{
		{BrowserChrome, "Default", "a"},
		{BrowserChrome, "Default", "z"},
		{BrowserChrome, "Profile 1", "m"},
		{BrowserFirefox, "default", "a"},
	}
	for i, e := range in {
		if e.Browser != want[i].b || e.Profile != want[i].p || e.ExtensionID != want[i].id {
			t.Fatalf("pos %d: got (%q,%q,%q), want (%q,%q,%q)",
				i, e.Browser, e.Profile, e.ExtensionID,
				want[i].b, want[i].p, want[i].id)
		}
	}
}

func TestParseChromiumManifestMV3(t *testing.T) {
	raw := []byte(`{
  "manifest_version": 3,
  "name": "Test Extension",
  "version": "1.2.3",
  "description": "Test",
  "permissions": ["tabs", "storage", {"declarativeNetRequest": {"id": "x"}}],
  "host_permissions": ["<all_urls>", "https://example.com/*"],
  "update_url": "https://clients2.google.com/service/update2/crx"
}`)
	ext, ok := parseChromiumManifest(raw)
	if !ok {
		t.Fatal("parse failed")
	}
	if ext.Name != "Test Extension" {
		t.Fatalf("name=%q", ext.Name)
	}
	if ext.Version != "1.2.3" {
		t.Fatalf("version=%q", ext.Version)
	}
	if ext.ManifestVersion != 3 {
		t.Fatalf("manifest_version=%d", ext.ManifestVersion)
	}
	// Permissions: tabs + storage; object form was dropped.
	if len(ext.Permissions) != 2 {
		t.Fatalf("permissions=%v, want 2 strings (object form dropped)", ext.Permissions)
	}
	// Host permissions sorted.
	want := []string{"<all_urls>", "https://example.com/*"}
	for i, p := range ext.HostPermissions {
		if p != want[i] {
			t.Fatalf("host_permissions[%d]=%q, want %q", i, p, want[i])
		}
	}
}

func TestParseChromiumManifestRejectsEmpty(t *testing.T) {
	_, ok := parseChromiumManifest([]byte(`{}`))
	if ok {
		t.Fatal("must reject empty manifest (no name + no version)")
	}
	_, ok = parseChromiumManifest([]byte(`not json`))
	if ok {
		t.Fatal("must reject non-JSON")
	}
}

func TestChromiumCollectorWalksProfiles(t *testing.T) {
	// Build a fake user-data tree:
	//   <home>/.config/google-chrome/Default/{Preferences, Extensions/aaa/1.0/manifest.json}
	//   <home>/.config/google-chrome/Profile 1/{Preferences, Extensions/bbb/2.0/manifest.json}
	tmp := t.TempDir()
	chromeRoot := filepath.Join(tmp, ".config", "google-chrome")

	mustMkdir(t, filepath.Join(chromeRoot, "Default", "Extensions", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.0"))
	mustWrite(t, filepath.Join(chromeRoot, "Default", "Preferences"), `{}`)
	mustWrite(t, filepath.Join(chromeRoot, "Default", "Extensions", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.0", "manifest.json"),
		`{"manifest_version":3,"name":"Aaa","version":"1.0","host_permissions":["<all_urls>"]}`)

	mustMkdir(t, filepath.Join(chromeRoot, "Profile 1", "Extensions", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "2.0"))
	mustWrite(t, filepath.Join(chromeRoot, "Profile 1", "Preferences"), `{}`)
	mustWrite(t, filepath.Join(chromeRoot, "Profile 1", "Extensions", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "2.0", "manifest.json"),
		`{"manifest_version":2,"name":"Bbb","version":"2.0","update_url":"https://attacker.example/crx"}`)

	c := &chromiumCollector{
		homeDirs: func() []string { return []string{tmp} },
		readFile: os.ReadFile,
		walkDir:  filepath.WalkDir,
		browsers: []chromiumBrowser{{BrowserChrome, ".config/google-chrome"}},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 extensions, got %d: %+v", len(got), got)
	}

	// got[0] sorted: Default/aaa first, Profile 1/bbb second.
	a := got[0]
	if a.Name != "Aaa" || a.ExtensionID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("first ext wrong: %+v", a)
	}
	if !HasBroadPermissions(a) {
		t.Fatalf("Aaa has <all_urls>, should be flagged broad")
	}
	if a.InstallSource != InstallStore {
		t.Fatalf("Aaa empty update_url → store, got %q", a.InstallSource)
	}

	b := got[1]
	if b.Name != "Bbb" || b.Profile != "Profile 1" {
		t.Fatalf("second ext wrong: %+v", b)
	}
	if b.InstallSource != InstallEnterprisePolicy {
		t.Fatalf("Bbb attacker.example update_url → enterprise-policy, got %q", b.InstallSource)
	}
	if !IsManifestV2Deprecated(b) {
		t.Fatalf("Bbb is Chrome MV2 → should flag as deprecated")
	}
}

func TestChromiumCollectorSkipsMissingTree(t *testing.T) {
	c := &chromiumCollector{
		homeDirs: func() []string { return []string{"/does/not/exist"} },
		readFile: os.ReadFile,
		walkDir:  filepath.WalkDir,
		browsers: []chromiumBrowser{{BrowserChrome, ".config/google-chrome"}},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing tree must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestChainCollectorSkipsErrors(t *testing.T) {
	good := stubCollector{out: []Extension{{Browser: BrowserChrome, ExtensionID: "x"}}}
	bad := stubCollector{err: errors.New("boom")}
	chain := &chainCollector{collectors: []Collector{good, bad, good}}

	got, err := chain.Collect(context.Background())
	if err != nil {
		t.Fatalf("chain Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (good × 2), got %d", len(got))
	}
}

func TestIsSystemUser(t *testing.T) {
	for _, sys := range []string{"Shared", "Guest", "Public", "Default", "All Users"} {
		if !isSystemUser(sys) {
			t.Fatalf("%q must be flagged system user", sys)
		}
	}
	for _, human := range []string{"alice", "bob", "developer"} {
		if isSystemUser(human) {
			t.Fatalf("%q must NOT be flagged system user", human)
		}
	}
}

// -- helpers --------------------------------------------------------------

type stubCollector struct {
	err error
	out []Extension
}

func (s stubCollector) Name() string { return "stub" }
func (s stubCollector) Collect(_ context.Context) ([]Extension, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.out, nil
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// silence unused fs/json imports if a future refactor drops them
var (
	_ = fs.SkipDir
	_ = json.Marshal
)
