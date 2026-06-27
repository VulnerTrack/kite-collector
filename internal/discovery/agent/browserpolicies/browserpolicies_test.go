package browserpolicies

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedBrowserKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(BrowserChrome), "chrome"},
		{string(BrowserEdge), "edge"},
		{string(BrowserFirefox), "firefox"},
		{string(BrowserUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("browser_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPinnedPolicyValueKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindBool), "bool"},
		{string(KindNumber), "number"},
		{string(KindString), "string"},
		{string(KindArray), "array"},
		{string(KindObject), "object"},
		{string(KindNull), "null"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte(`{"X":1}`))
	b := HashContents([]byte(`{"X":1}`))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateChromeSafeBrowsingOff(t *testing.T) {
	p := Policy{
		BrowserKind:     BrowserChrome,
		PolicyName:      "SafeBrowsingProtectionLevel",
		PolicyValueKind: KindNumber,
		PolicyValue:     "0",
	}
	AnnotateSecurity(&p)
	if !p.IsSafeBrowsingOff || !p.IsConcerning {
		t.Fatalf("flags: %+v", p)
	}
}

func TestAnnotateChromePasswordManagerOff(t *testing.T) {
	p := Policy{
		BrowserKind:     BrowserChrome,
		PolicyName:      "PasswordManagerEnabled",
		PolicyValueKind: KindBool,
		PolicyValue:     "false",
	}
	AnnotateSecurity(&p)
	if !p.IsPasswordManagerOff || !p.IsConcerning {
		t.Fatalf("flags: %+v", p)
	}
}

func TestAnnotateChromeDownloadRestrictionsOff(t *testing.T) {
	p := Policy{
		BrowserKind:     BrowserChrome,
		PolicyName:      "DownloadRestrictions",
		PolicyValueKind: KindNumber,
		PolicyValue:     "0",
	}
	AnnotateSecurity(&p)
	if !p.IsDownloadRestrictionsOff {
		t.Fatal("DownloadRestrictions=0 must flag")
	}
}

func TestAnnotateChromeForceExtensions(t *testing.T) {
	p := Policy{
		BrowserKind:     BrowserChrome,
		PolicyName:      "ExtensionInstallForcelist",
		PolicyValueKind: KindArray,
		PolicyValue:     `["abcdefghij...;https://clients2.google.com/service/update2/crx"]`,
	}
	AnnotateSecurity(&p)
	if !p.IsExtensionForceInstalled {
		t.Fatal("non-empty force-list must flag")
	}
	// Empty force-list must NOT flag.
	p2 := Policy{
		BrowserKind:     BrowserChrome,
		PolicyName:      "ExtensionInstallForcelist",
		PolicyValueKind: KindArray,
		PolicyValue:     "[]",
	}
	AnnotateSecurity(&p2)
	if p2.IsExtensionForceInstalled {
		t.Fatal("empty force-list must NOT flag")
	}
}

func TestAnnotateChromeURLBlocklistEmpty(t *testing.T) {
	p := Policy{
		BrowserKind:     BrowserChrome,
		PolicyName:      "URLBlocklist",
		PolicyValueKind: KindArray,
		PolicyValue:     "[]",
	}
	AnnotateSecurity(&p)
	if !p.IsURLBlocklistEmpty {
		t.Fatal("empty URLBlocklist must flag")
	}
	p2 := Policy{
		BrowserKind:     BrowserChrome,
		PolicyName:      "URLBlocklist",
		PolicyValueKind: KindArray,
		PolicyValue:     `["phishing.example.com"]`,
	}
	AnnotateSecurity(&p2)
	if p2.IsURLBlocklistEmpty {
		t.Fatal("populated URLBlocklist must NOT flag empty")
	}
}

func TestAnnotateEdgeSharesChromeClassifiers(t *testing.T) {
	p := Policy{
		BrowserKind:     BrowserEdge,
		PolicyName:      "PasswordManagerEnabled",
		PolicyValueKind: KindBool,
		PolicyValue:     "false",
	}
	AnnotateSecurity(&p)
	if !p.IsPasswordManagerOff {
		t.Fatal("Edge must share Chrome classifier")
	}
}

func TestAnnotateFirefoxDisableSafeBrowsing(t *testing.T) {
	p := Policy{
		BrowserKind:     BrowserFirefox,
		PolicyName:      "DisableSafeBrowsing",
		PolicyValueKind: KindBool,
		PolicyValue:     "true",
	}
	AnnotateSecurity(&p)
	if !p.IsSafeBrowsingOff {
		t.Fatal("DisableSafeBrowsing=true must flag")
	}
}

func TestAnnotateFirefoxExtensionsForceInstall(t *testing.T) {
	p := Policy{
		BrowserKind:     BrowserFirefox,
		PolicyName:      "Extensions",
		PolicyValueKind: KindObject,
		PolicyValue:     `{"Install":["https://addons.mozilla.org/firefox/addon/ublock-origin/"]}`,
	}
	AnnotateSecurity(&p)
	if !p.IsExtensionForceInstalled {
		t.Fatal("Firefox Install array must flag force-install")
	}
}

func TestAnnotateUnknownVendorClean(t *testing.T) {
	p := Policy{
		BrowserKind:     BrowserUnknown,
		PolicyName:      "PasswordManagerEnabled",
		PolicyValueKind: KindBool,
		PolicyValue:     "false",
	}
	AnnotateSecurity(&p)
	if p.IsConcerning {
		t.Fatal("unknown vendor must leave flags cleared")
	}
}

// -- ParseChromeFamilyPolicy ---------------------------------------

func TestParseChromeFamilyTypical(t *testing.T) {
	body := []byte(`{
        "SafeBrowsingProtectionLevel": 2,
        "PasswordManagerEnabled": true,
        "DownloadRestrictions": 1,
        "URLBlocklist": ["phishing.example.com", "malware.example.com"],
        "ExtensionInstallForcelist": []
    }`)
	got, err := ParseChromeFamilyPolicy(body, "x.json", BrowserChrome)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("rows=%d: %+v", len(got), got)
	}
	byName := map[string]Policy{}
	for _, p := range got {
		byName[p.PolicyName] = p
	}

	if byName["SafeBrowsingProtectionLevel"].PolicyValue != "2" ||
		byName["SafeBrowsingProtectionLevel"].PolicyValueKind != KindNumber {
		t.Fatalf("safe-browsing: %+v", byName["SafeBrowsingProtectionLevel"])
	}
	if byName["SafeBrowsingProtectionLevel"].IsSafeBrowsingOff {
		t.Fatal("level=2 must NOT flag off")
	}
	if byName["PasswordManagerEnabled"].IsPasswordManagerOff {
		t.Fatal("PW manager=true must NOT flag off")
	}
	// URLBlocklist populated → must NOT flag empty.
	if byName["URLBlocklist"].IsURLBlocklistEmpty {
		t.Fatal("populated blocklist must NOT flag empty")
	}
	// Force-list empty → must NOT flag.
	if byName["ExtensionInstallForcelist"].IsExtensionForceInstalled {
		t.Fatal("empty force-list must NOT flag")
	}
}

func TestParseChromeFamilyWorstCase(t *testing.T) {
	body := []byte(`{
        "SafeBrowsingProtectionLevel": 0,
        "PasswordManagerEnabled": false,
        "DownloadRestrictions": 0,
        "URLBlocklist": [],
        "ExtensionInstallForcelist": ["fakeId;https://attacker.com/crx"]
    }`)
	got, err := ParseChromeFamilyPolicy(body, "x.json", BrowserChrome)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Policy{}
	for _, p := range got {
		byName[p.PolicyName] = p
	}
	if !byName["SafeBrowsingProtectionLevel"].IsSafeBrowsingOff {
		t.Fatal("level=0 must flag")
	}
	if !byName["PasswordManagerEnabled"].IsPasswordManagerOff {
		t.Fatal("PW=false must flag")
	}
	if !byName["DownloadRestrictions"].IsDownloadRestrictionsOff {
		t.Fatal("downloads=0 must flag")
	}
	if !byName["URLBlocklist"].IsURLBlocklistEmpty {
		t.Fatal("empty blocklist must flag")
	}
	if !byName["ExtensionInstallForcelist"].IsExtensionForceInstalled {
		t.Fatal("force-list with entries must flag")
	}
}

// -- ParseFirefoxPolicy --------------------------------------------

func TestParseFirefoxPolicyWithWrapper(t *testing.T) {
	body := []byte(`{
        "policies": {
            "DisableSafeBrowsing": true,
            "PasswordManagerEnabled": false,
            "Extensions": {
                "Install": ["https://addons.mozilla.org/firefox/addon/ublock-origin/"]
            }
        }
    }`)
	got, err := ParseFirefoxPolicy(body, "policies.json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("rows=%d: %+v", len(got), got)
	}
	byName := map[string]Policy{}
	for _, p := range got {
		byName[p.PolicyName] = p
	}
	if !byName["DisableSafeBrowsing"].IsSafeBrowsingOff {
		t.Fatal("DisableSafeBrowsing=true must flag")
	}
	if !byName["PasswordManagerEnabled"].IsPasswordManagerOff {
		t.Fatal("PasswordManagerEnabled=false must flag")
	}
	if !byName["Extensions"].IsExtensionForceInstalled {
		t.Fatal("Extensions.Install array must flag")
	}
}

func TestParseFirefoxPolicyWithoutWrapper(t *testing.T) {
	body := []byte(`{"DisableSafeBrowsing": true}`)
	got, err := ParseFirefoxPolicy(body, "policies.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].IsSafeBrowsingOff {
		t.Fatalf("wrapper-less parse broken: %+v", got)
	}
}

// -- error paths ----------------------------------------------------

func TestParseChromeFamilyEmpty(t *testing.T) {
	if _, err := ParseChromeFamilyPolicy(nil, "x", BrowserChrome); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseChromeFamilyMalformed(t *testing.T) {
	if _, err := ParseChromeFamilyPolicy([]byte("not json"), "x", BrowserChrome); err == nil {
		t.Fatal("malformed must error")
	}
}

func TestParseChromeFamilyBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"PasswordManagerEnabled": true}`)...)
	got, err := ParseChromeFamilyPolicy(body, "x", BrowserChrome)
	if err != nil {
		t.Fatalf("BOM should be tolerated: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("rows=%d", len(got))
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksDirAndFile(t *testing.T) {
	tmp := t.TempDir()
	chromeDir := filepath.Join(tmp, "chrome")
	must(t, os.MkdirAll(chromeDir, 0o755))
	must(t, os.WriteFile(filepath.Join(chromeDir, "policy.json"),
		[]byte(`{"PasswordManagerEnabled": false}`), 0o644))
	// Skipped non-JSON file.
	must(t, os.WriteFile(filepath.Join(chromeDir, "README"), []byte("skip"), 0o644))

	firefoxFile := filepath.Join(tmp, "firefox-policies.json")
	must(t, os.WriteFile(firefoxFile,
		[]byte(`{"policies": {"DisableSafeBrowsing": true}}`), 0o644))

	c := &fileCollector{
		seeds: []vendorSeed{
			{browser: BrowserChrome, dirs: []string{chromeDir}},
			{browser: BrowserFirefox, files: []string{firefoxFile}},
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (skip README), got %d: %+v", len(got), got)
	}

	byBrowser := map[BrowserKind]Policy{}
	for _, p := range got {
		byBrowser[p.BrowserKind] = p
	}
	if !byBrowser[BrowserChrome].IsPasswordManagerOff {
		t.Fatalf("chrome row wrong: %+v", byBrowser[BrowserChrome])
	}
	if !byBrowser[BrowserFirefox].IsSafeBrowsingOff {
		t.Fatalf("firefox row wrong: %+v", byBrowser[BrowserFirefox])
	}
}

func TestFileCollectorAllMissingOK(t *testing.T) {
	c := &fileCollector{
		seeds: []vendorSeed{
			{browser: BrowserChrome, dirs: []string{"/nope"}, files: []string{"/nope2"}},
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortPolicies --------------------------------------------------

func TestSortPoliciesDeterministic(t *testing.T) {
	in := []Policy{
		{BrowserKind: BrowserFirefox, FilePath: "z", PolicyName: "B"},
		{BrowserKind: BrowserChrome, FilePath: "a", PolicyName: "Z"},
		{BrowserKind: BrowserChrome, FilePath: "a", PolicyName: "A"},
	}
	SortPolicies(in)
	if in[0].BrowserKind != BrowserChrome || in[0].PolicyName != "A" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].BrowserKind != BrowserFirefox {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
