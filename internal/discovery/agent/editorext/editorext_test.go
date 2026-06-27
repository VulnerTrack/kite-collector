package editorext

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPinnedEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(EditorVSCode), "vscode"},
		{string(EditorVSCodium), "vscodium"},
		{string(EditorCursor), "cursor"},
		{string(EditorCodeServer), "code-server"},
		{string(EditorWindsurf), "windsurf"},
		{string(EditorIntelliJ), "intellij"},
		{string(EditorPyCharm), "pycharm"},
		{string(EditorGoLand), "goland"},
		{string(EditorSublime), "sublime"},
		{string(EditorVim), "vim"},
		{string(EditorNeovim), "neovim"},
		{string(EditorEmacs), "emacs"},
		{string(EditorUnknown), "unknown"},
		{string(InstallMarketplace), "marketplace"},
		{string(InstallSideloaded), "sideloaded"},
		{string(InstallSSHRemote), "ssh-remote"},
		{string(InstallDeveloper), "dev"},
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
		t.Fatalf("nil = %q", got)
	}
	if got := EncodeStringList([]string{"a", "b"}); got != `["a","b"]` {
		t.Fatalf("got %q", got)
	}
}

func TestIsStartupActivation(t *testing.T) {
	for _, e := range []string{"*", "onStartupFinished", "onStartup"} {
		if !IsStartupActivation(e) {
			t.Fatalf("%q must be startup activation", e)
		}
	}
	for _, e := range []string{"", "onLanguage:python", "onCommand:foo", "workspaceContains:**/*.go"} {
		if IsStartupActivation(e) {
			t.Fatalf("%q must NOT be startup activation", e)
		}
	}
}

func TestHasStartupActivation(t *testing.T) {
	if !HasStartupActivation([]string{"onLanguage:python", "*"}) {
		t.Fatal("must fire when any element is startup")
	}
	if HasStartupActivation([]string{"onLanguage:python", "onCommand:foo"}) {
		t.Fatal("scoped activation events must not flag")
	}
	if HasStartupActivation(nil) {
		t.Fatal("empty must not flag")
	}
}

func TestIsPublisherLookalike(t *testing.T) {
	for _, p := range []string{"ms-vscode-team", "github-extension", "redhad", "PRITTIER"} {
		if !IsPublisherLookalike(p) {
			t.Fatalf("%q must be flagged as lookalike", p)
		}
	}
	for _, p := range []string{"ms-vscode", "github", "redhat", "prettier", "esbenp"} {
		if IsPublisherLookalike(p) {
			t.Fatalf("legitimate publisher %q must NOT be flagged", p)
		}
	}
}

func TestSortExtensionsDeterministic(t *testing.T) {
	in := []Extension{
		{Editor: EditorVSCode, Profile: "default", Publisher: "ms-python", Name: "python"},
		{Editor: EditorCursor, Profile: "default", Publisher: "esbenp", Name: "prettier"},
		{Editor: EditorVSCode, Profile: "default", Publisher: "esbenp", Name: "prettier"},
	}
	SortExtensions(in)
	// cursor < vscode (lexical); within vscode: esbenp < ms-python.
	want := []struct {
		ed   Editor
		pub  string
		name string
	}{
		{EditorCursor, "esbenp", "prettier"},
		{EditorVSCode, "esbenp", "prettier"},
		{EditorVSCode, "ms-python", "python"},
	}
	for i, e := range in {
		if e.Editor != want[i].ed || e.Publisher != want[i].pub || e.Name != want[i].name {
			t.Fatalf("pos %d: got (%q,%q,%q), want (%q,%q,%q)",
				i, e.Editor, e.Publisher, e.Name,
				want[i].ed, want[i].pub, want[i].name)
		}
	}
}

// -- VS Code manifest parser ---------------------------------------------

func TestParseVSCodeManifestBareString(t *testing.T) {
	raw := []byte(`{
  "name": "python",
  "publisher": "ms-python",
  "version": "2024.0.0",
  "displayName": "Python",
  "description": "Python language support",
  "author": "Microsoft <vscode@microsoft.com>",
  "engines": {"vscode": "^1.85.0"},
  "main": "./out/extension.js",
  "activationEvents": ["onLanguage:python", "onStartupFinished"],
  "categories": ["Programming Languages", "Linters"],
  "keywords": ["python", "django"]
}`)
	ext, ok := parseVSCodeManifest(raw)
	if !ok {
		t.Fatal("parse failed")
	}
	if ext.Name != "python" || ext.Publisher != "ms-python" {
		t.Fatalf("name/publisher lost: %+v", ext)
	}
	if ext.Author != "Microsoft <vscode@microsoft.com>" {
		t.Fatalf("author lost: %q", ext.Author)
	}
	if ext.EngineVersion != "^1.85.0" {
		t.Fatalf("engine version lost: %q", ext.EngineVersion)
	}
	if ext.MainScript != "./out/extension.js" {
		t.Fatalf("main lost: %q", ext.MainScript)
	}
	if len(ext.ActivationEvents) != 2 || ext.ActivationEvents[0] != "onLanguage:python" {
		t.Fatalf("activation events lost (must be sorted): %v", ext.ActivationEvents)
	}
}

func TestParseVSCodeManifestObjectAuthor(t *testing.T) {
	raw := []byte(`{
  "name": "x",
  "publisher": "p",
  "author": {"name": "Alice", "email": "alice@example"}
}`)
	ext, ok := parseVSCodeManifest(raw)
	if !ok {
		t.Fatal("parse failed")
	}
	if ext.Author != "Alice" {
		t.Fatalf("object-form author should extract name: %q", ext.Author)
	}
}

func TestParseVSCodeManifestRejectsMissingMandatoryFields(t *testing.T) {
	_, ok := parseVSCodeManifest([]byte(`{"name": "x"}`))
	if ok {
		t.Fatal("must reject manifest with no publisher")
	}
	_, ok = parseVSCodeManifest([]byte(`{"publisher": "p"}`))
	if ok {
		t.Fatal("must reject manifest with no name")
	}
	_, ok = parseVSCodeManifest([]byte(`not json`))
	if ok {
		t.Fatal("must reject non-JSON")
	}
}

func TestVSCodeClassifyInstall(t *testing.T) {
	// marketplace: .vsixmanifest present
	statHas := func(_ string) (os.FileInfo, error) {
		return fakeFileInfo{name: ".vsixmanifest"}, nil
	}
	if got := vscodeClassifyInstall(statHas, "/home/x/.vscode/extensions/p.n-1.0.0"); got != InstallMarketplace {
		t.Fatalf("with vsixmanifest → marketplace, got %q", got)
	}

	// sideloaded: no .vsixmanifest
	statMissing := func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	if got := vscodeClassifyInstall(statMissing, "/home/x/.vscode/extensions/p.n-1.0.0"); got != InstallSideloaded {
		t.Fatalf("no vsixmanifest → sideloaded, got %q", got)
	}

	// ssh-remote: path contains .vscode-server
	if got := vscodeClassifyInstall(statHas, "/home/x/.vscode-server/extensions/p.n-1.0.0"); got != InstallSSHRemote {
		t.Fatalf(".vscode-server path → ssh-remote, got %q", got)
	}
	if got := vscodeClassifyInstall(statHas, "/root/.local/code-server/extensions/p.n-1.0.0"); got != InstallSSHRemote {
		t.Fatalf("code-server path → ssh-remote, got %q", got)
	}
}

// -- VS Code end-to-end --------------------------------------------------

func TestVSCodeCollectorWalksAndDedupesEditors(t *testing.T) {
	tmp := t.TempDir()
	// Two extensions for VS Code, one with .vsixmanifest (marketplace),
	// one without (sideloaded). One Cursor extension that activates on *.
	mustWriteExt(t, tmp, ".vscode/extensions/ms-python.python-2024.0.0",
		`{"name":"python","publisher":"ms-python","version":"2024.0.0","activationEvents":["onLanguage:python"]}`,
		true)
	mustWriteExt(t, tmp, ".vscode/extensions/attacker.malicious-0.1.0",
		`{"name":"malicious","publisher":"attacker","version":"0.1.0","activationEvents":["*"]}`,
		false)
	mustWriteExt(t, tmp, ".cursor/extensions/esbenp.prettier-3.0.0",
		`{"name":"prettier","publisher":"esbenp","version":"3.0.0","activationEvents":["onStartupFinished"]}`,
		true)

	c := &vscodeCollector{
		homeDirs: func() []string { return []string{tmp} },
		readFile: os.ReadFile,
		statFile: os.Stat,
		walkDir:  filepath.WalkDir,
		editors:  vscodeExtensionPaths(),
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 exts, got %d", len(got))
	}

	by := map[string]Extension{}
	for _, e := range got {
		by[e.ExtensionID] = e
	}

	python := by["ms-python.python"]
	if python.Editor != EditorVSCode {
		t.Fatalf("python editor=%q", python.Editor)
	}
	if python.InstallSource != InstallMarketplace {
		t.Fatalf("python should be marketplace (vsixmanifest present): %q", python.InstallSource)
	}
	if python.ActivatesOnStartup {
		t.Fatalf("python only activates on language, not startup")
	}

	mal := by["attacker.malicious"]
	if mal.InstallSource != InstallSideloaded {
		t.Fatalf("attacker.malicious → sideloaded (no vsixmanifest): %q", mal.InstallSource)
	}
	if !mal.ActivatesOnStartup {
		t.Fatalf(`activationEvents=["*"] must set activates_on_startup`)
	}

	prettier := by["esbenp.prettier"]
	if prettier.Editor != EditorCursor {
		t.Fatalf("prettier editor=%q, want cursor", prettier.Editor)
	}
	if !prettier.ActivatesOnStartup {
		t.Fatalf("onStartupFinished must set activates_on_startup")
	}
}

func TestVSCodeCollectorMissingTreeIsEmpty(t *testing.T) {
	c := &vscodeCollector{
		homeDirs: func() []string { return []string{"/nope"} },
		readFile: os.ReadFile,
		statFile: os.Stat,
		walkDir:  filepath.WalkDir,
		editors:  vscodeExtensionPaths(),
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- chain ---------------------------------------------------------------

func TestChainCollectorSkipsErrors(t *testing.T) {
	good := stubCollector{out: []Extension{{Editor: EditorVSCode, Publisher: "p", Name: "n"}}}
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

// -- helpers --------------------------------------------------------------

func mustWriteExt(t *testing.T, home, relPath, pkgJSON string, withVsixManifest bool) {
	t.Helper()
	dir := filepath.Join(home, relPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if withVsixManifest {
		if err := os.WriteFile(filepath.Join(dir, ".vsixmanifest"), []byte("<xml/>"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

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

type fakeFileInfo struct{ name string }

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return 0 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }
