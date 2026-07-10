package winvscode

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedEditorKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(EditorVSCode), "vscode"},
		{string(EditorVSCodeInsiders), "vscode-insiders"},
		{string(EditorCursor), "cursor"},
		{string(EditorUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("editor_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte(`{"name":"x"}`))
	b := HashContents([]byte(`{"name":"x"}`))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsTrustedPublisher(t *testing.T) {
	hit := []string{
		"microsoft", "Microsoft",
		"ms-python", "MS-Python",
		"github", "redhat", "anthropic",
	}
	for _, p := range hit {
		if !IsTrustedPublisher(p) {
			t.Fatalf("%q must flag trusted", p)
		}
	}
	miss := []string{"evilcorp", "random-publisher", "", "MICROSOFT-IMPOSTER"}
	for _, p := range miss {
		if IsTrustedPublisher(p) {
			t.Fatalf("%q must NOT flag trusted", p)
		}
	}
}

func TestHasWildcardActivationEvent(t *testing.T) {
	for _, ev := range []struct {
		events []string
		want   bool
	}{
		{[]string{"*"}, true},
		{[]string{"onStartupFinished"}, true},
		{[]string{"ONSTARTUPFINISHED"}, true},
		{[]string{"onLanguage:python"}, false},
		{nil, false},
		{[]string{"onCommand:foo.bar"}, false},
	} {
		if got := HasWildcardActivationEvent(ev.events); got != ev.want {
			t.Fatalf("events=%v want %v got %v", ev.events, ev.want, got)
		}
	}
}

func TestParsePublisherAndName(t *testing.T) {
	cases := []struct {
		in, pub, name string
	}{
		{"microsoft.vscode-typescript-next", "microsoft", "vscode-typescript-next"},
		{"ms-python.python", "ms-python", "python"},
		{"single-name", "", "single-name"},
		{"", "", ""},
	}
	for _, c := range cases {
		pub, name := ParsePublisherAndName(c.in)
		if pub != c.pub || name != c.name {
			t.Fatalf("Parse(%q)=(%q,%q) want (%q,%q)", c.in, pub, name, c.pub, c.name)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateMicrosoftExtensionClean(t *testing.T) {
	e := Extension{
		Publisher:        "microsoft",
		ExtensionName:    "python",
		ActivationEvents: []string{"onLanguage:python"},
		Contributes:      []string{"commands", "configuration"},
	}
	AnnotateSecurity(&e)
	if e.IsThirdPartyPublisher {
		t.Fatal("microsoft must NOT flag third-party")
	}
	if e.HasWildcardActivation {
		t.Fatal("onLanguage activation must NOT flag wildcard")
	}
	if e.ContributesTerminal || e.ContributesDebug || e.ContributesTasks {
		t.Fatal("commands+configuration must NOT flag RCE-adjacent")
	}
	if e.IsSupplyChainCandidate {
		t.Fatal("clean MS extension must NOT flag supply-chain")
	}
}

func TestAnnotateThirdPartyDebugAdapter(t *testing.T) {
	e := Extension{
		Publisher:        "smallvendor",
		ExtensionName:    "debug-helper",
		ActivationEvents: []string{"onStartupFinished"},
		Contributes:      []string{"debuggers", "configuration"},
	}
	AnnotateSecurity(&e)
	if !e.IsThirdPartyPublisher {
		t.Fatal("smallvendor must flag third-party")
	}
	if !e.HasWildcardActivation {
		t.Fatal("onStartupFinished must flag wildcard")
	}
	if !e.ContributesDebug {
		t.Fatal("contributes.debuggers must flag")
	}
	if !e.IsSupplyChainCandidate {
		t.Fatalf("third-party + debugger must flag supply-chain: %+v", e)
	}
}

func TestAnnotateThirdPartyTerminalContrib(t *testing.T) {
	e := Extension{
		Publisher:   "vendor",
		Contributes: []string{"terminal"},
	}
	AnnotateSecurity(&e)
	if !e.ContributesTerminal || !e.IsSupplyChainCandidate {
		t.Fatalf("terminal-contrib must flag: %+v", e)
	}
}

func TestAnnotateWorkspaceTrustDisabledFlag(t *testing.T) {
	e := Extension{
		Publisher:                "vendor",
		IsWorkspaceTrustDisabled: true,
	}
	AnnotateSecurity(&e)
	if !e.IsSupplyChainCandidate {
		t.Fatal("third-party + workspace-trust-disabled must flag supply-chain")
	}
}

func TestAnnotateTrustedPublisherIgnoresWildcard(t *testing.T) {
	e := Extension{
		Publisher:                "microsoft",
		ActivationEvents:         []string{"*"},
		Contributes:              []string{"debuggers"},
		IsWorkspaceTrustDisabled: true,
	}
	AnnotateSecurity(&e)
	if e.IsSupplyChainCandidate {
		t.Fatal("trusted publisher must NOT flag supply-chain even with risky contribs")
	}
	if !e.HasWildcardActivation || !e.ContributesDebug {
		t.Fatal("intermediate flags must still propagate for the alert pipeline")
	}
}

// -- ParseManifest end-to-end ---------------------------------------

func TestParseManifestTypicalPython(t *testing.T) {
	body := []byte(`{
        "name": "python",
        "displayName": "Python",
        "version": "2024.0.1",
        "publisher": "ms-python",
        "description": "Python language support",
        "main": "./out/extension.js",
        "engines": {"vscode": "^1.80.0"},
        "activationEvents": ["onLanguage:python", "onLanguage:python"],
        "contributes": {
            "commands": [],
            "configuration": {},
            "debuggers": []
        }
    }`)
	got, err := ParseManifest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Publisher != "ms-python" {
		t.Fatalf("publisher=%q", got.Publisher)
	}
	if got.ExtensionName != "python" {
		t.Fatalf("name=%q", got.ExtensionName)
	}
	if got.ExtensionVersion != "2024.0.1" {
		t.Fatalf("version=%q", got.ExtensionVersion)
	}
	if got.MainEntry != "./out/extension.js" {
		t.Fatalf("main=%q", got.MainEntry)
	}
	if got.EngineVSCode != "^1.80.0" {
		t.Fatalf("engine=%q", got.EngineVSCode)
	}
	if len(got.ActivationEvents) != 1 {
		t.Fatalf("dedupe broken: %+v", got.ActivationEvents)
	}
	if len(got.Contributes) != 3 {
		t.Fatalf("contributes=%+v", got.Contributes)
	}
	if got.IsThirdPartyPublisher {
		t.Fatal("ms-python must NOT flag third-party")
	}
	if !got.ContributesDebug {
		t.Fatal("contributes.debuggers must flag")
	}
}

func TestParseManifestWorkspaceTrustDisabled(t *testing.T) {
	body := []byte(`{
        "name": "needs-trust",
        "publisher": "smallvendor",
        "version": "1.0.0",
        "capabilities": {
            "untrustedWorkspaces": { "supported": false }
        }
    }`)
	got, err := ParseManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsWorkspaceTrustDisabled {
		t.Fatal("supported=false must flag workspace-trust-disabled")
	}
}

func TestParseManifestWorkspaceTrustLimited(t *testing.T) {
	body := []byte(`{
        "name": "trust-limited",
        "publisher": "smallvendor",
        "version": "1.0.0",
        "capabilities": {
            "untrustedWorkspaces": { "supported": "limited" }
        }
    }`)
	got, err := ParseManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.IsWorkspaceTrustDisabled {
		t.Fatal("limited support must NOT flag fully-disabled")
	}
}

func TestParseManifestEmpty(t *testing.T) {
	if _, err := ParseManifest(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseManifestMalformed(t *testing.T) {
	if _, err := ParseManifest([]byte("not json")); err == nil {
		t.Fatal("malformed must error")
	}
}

func TestParseManifestBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"name":"x","publisher":"y","version":"1"}`)...)
	got, err := ParseManifest(body)
	if err != nil {
		t.Fatalf("BOM should be tolerated: %v", err)
	}
	if got.ExtensionName != "x" {
		t.Fatalf("name=%q", got.ExtensionName)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksPerUserAndEditor(t *testing.T) {
	tmp := t.TempDir()

	// alice's VSCode extensions.
	aliceVSCode := filepath.Join(tmp, "alice", ".vscode", "extensions")
	must(t, os.MkdirAll(filepath.Join(aliceVSCode, "ms-python.python-2024.0.1"), 0o755))
	must(t, os.WriteFile(
		filepath.Join(aliceVSCode, "ms-python.python-2024.0.1", "package.json"),
		[]byte(`{"name":"python","publisher":"ms-python","version":"2024.0.1",
                "activationEvents":["onLanguage:python"],
                "contributes":{"commands":[]}}`), 0o644,
	))

	// alice's Cursor extensions — third-party with debug contributes.
	aliceCursor := filepath.Join(tmp, "alice", ".cursor", "extensions")
	must(t, os.MkdirAll(filepath.Join(aliceCursor, "smallvendor.debug-helper-1.2.3"), 0o755))
	must(t, os.WriteFile(
		filepath.Join(aliceCursor, "smallvendor.debug-helper-1.2.3", "package.json"),
		[]byte(`{"name":"debug-helper","publisher":"smallvendor","version":"1.2.3",
                "activationEvents":["*"],
                "contributes":{"debuggers":[]}}`), 0o644,
	))

	// bob's VSCode-Insiders extension with workspace-trust opt-out.
	bobInsiders := filepath.Join(tmp, "bob", ".vscode-insiders", "extensions")
	must(t, os.MkdirAll(filepath.Join(bobInsiders, "vendor.needs-trust-1.0.0"), 0o755))
	must(t, os.WriteFile(
		filepath.Join(bobInsiders, "vendor.needs-trust-1.0.0", "package.json"),
		[]byte(`{"name":"needs-trust","publisher":"vendor","version":"1.0.0",
                "capabilities":{"untrustedWorkspaces":{"supported":false}}}`), 0o644,
	))

	// Public pseudo-profile must be skipped.
	pubExt := filepath.Join(tmp, "Public", ".vscode", "extensions")
	must(t, os.MkdirAll(filepath.Join(pubExt, "evil.skip-1.0.0"), 0o755))
	must(t, os.WriteFile(
		filepath.Join(pubExt, "evil.skip-1.0.0", "package.json"),
		[]byte(`{"name":"skip","publisher":"evil","version":"1.0.0"}`), 0o644,
	))

	c := &fileCollector{
		usersBases: []string{tmp},
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// alice: 2 (python + debug-helper). bob: 1. Public skipped.
	if len(got) != 3 {
		t.Fatalf("want 3 rows, got %d: %+v", len(got), got)
	}

	byID := map[string]Extension{}
	for _, e := range got {
		byID[e.Publisher+"."+e.ExtensionName] = e
	}

	python := byID["ms-python.python"]
	if python.IsSupplyChainCandidate {
		t.Fatalf("MS extension should NOT flag supply-chain: %+v", python)
	}
	if python.EditorKind != EditorVSCode {
		t.Fatalf("editor_kind=%q", python.EditorKind)
	}
	if python.UserProfile != "alice" {
		t.Fatalf("user=%q", python.UserProfile)
	}

	debug := byID["smallvendor.debug-helper"]
	if !debug.IsSupplyChainCandidate || !debug.HasWildcardActivation {
		t.Fatalf("debug-helper must flag supply-chain: %+v", debug)
	}
	if debug.EditorKind != EditorCursor {
		t.Fatalf("debug editor_kind=%q", debug.EditorKind)
	}

	trust := byID["vendor.needs-trust"]
	if !trust.IsWorkspaceTrustDisabled || !trust.IsSupplyChainCandidate {
		t.Fatalf("workspace-trust opt-out must flag supply-chain: %+v", trust)
	}
	if trust.EditorKind != EditorVSCodeInsiders {
		t.Fatalf("trust editor_kind=%q", trust.EditorKind)
	}
	if trust.UserProfile != "bob" {
		t.Fatalf("trust user=%q", trust.UserProfile)
	}
}

func TestFileCollectorMissingBasesOK(t *testing.T) {
	c := &fileCollector{
		usersBases: []string{"/nope-users"},
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortExtensions -------------------------------------------------

func TestSortExtensionsDeterministic(t *testing.T) {
	in := []Extension{
		{EditorKind: EditorVSCode, Publisher: "b", ExtensionName: "a", ExtensionVersion: "2.0.0"},
		{EditorKind: EditorCursor, Publisher: "a", ExtensionName: "a", ExtensionVersion: "1.0.0"},
		{EditorKind: EditorCursor, Publisher: "a", ExtensionName: "a", ExtensionVersion: "0.9.0"},
	}
	SortExtensions(in)
	// EditorCursor < EditorVSCode alphabetically.
	if in[0].EditorKind != EditorCursor || in[0].ExtensionVersion != "0.9.0" {
		t.Fatalf("first=%+v", in[0])
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
