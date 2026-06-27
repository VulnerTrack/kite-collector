package winnpmrc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileScopeAndEntryKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ScopeUser), "user"},
		{string(ScopeGlobal), "global"},
		{string(ScopeBuiltin), "builtin"},
		{string(ScopeProject), "project"},
		{string(ScopeUnknown), "unknown"},
		{string(EntryAuthToken), "auth-token"},
		{string(EntryPassword), "password"},
		{string(EntryUsername), "username"},
		{string(EntryRegistry), "registry"},
		{string(EntryScopeRegistry), "scope-registry"},
		{string(EntrySetting), "setting"},
		{string(EntryUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("registry=https://x\n"))
	b := HashContents([]byte("registry=https://x\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestAuthTokenPrefix(t *testing.T) {
	cases := map[string]string{
		"npm_abc123def":      "npm_",
		"oauth_secretvalue":  "oaut",
		"ghp_xxxxxxxxxxxxxx": "ghp_",
		"":                   "",
		"abc":                "",
		"   npm_xxx   ":      "npm_",
	}
	for in, want := range cases {
		if got := AuthTokenPrefix(in); got != want {
			t.Fatalf("AuthTokenPrefix(%q)=%q want %q", in, got, want)
		}
	}
}

func TestRegistryHostFromKey(t *testing.T) {
	cases := map[string]string{
		"//registry.npmjs.org/:_authToken":        "registry.npmjs.org",
		"//npm.pkg.github.com/:_authToken":        "npm.pkg.github.com",
		"//registry.example.com:8443/:_authToken": "registry.example.com",
		"//host/path/foo/:_password":              "host",
		"strict-ssl":                              "",
		"registry":                                "",
	}
	for in, want := range cases {
		if got := RegistryHostFromKey(in); got != want {
			t.Fatalf("RegistryHostFromKey(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSettingFromKey(t *testing.T) {
	cases := map[string]string{
		"//registry.npmjs.org/:_authToken": "_authToken",
		"//host/:_password":                "_password",
		"//host/:username":                 "username",
		"registry":                         "",
		"strict-ssl":                       "",
	}
	for in, want := range cases {
		if got := SettingFromKey(in); got != want {
			t.Fatalf("SettingFromKey(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsWorldWritableDir(t *testing.T) {
	yes := []string{
		"/tmp/npm-global",
		"/var/tmp/cache",
		`C:\Users\Public\npm`,
		`c:\Windows\Temp\npm`,
		"%TEMP%\\npm",
	}
	no := []string{
		"/usr/local/lib/npm",
		`C:\Program Files\nodejs`,
		"/home/alice/.npm-global",
		"",
	}
	for _, v := range yes {
		if !IsWorldWritableDir(v) {
			t.Fatalf("expected world-writable: %q", v)
		}
	}
	for _, v := range no {
		if IsWorldWritableDir(v) {
			t.Fatalf("expected NOT world-writable: %q", v)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateAuthTokenWorldReadable(t *testing.T) {
	e := Entry{EntryKind: EntryAuthToken, FileMode: 0o644}
	AnnotateSecurity(&e)
	if !e.IsAuthToken {
		t.Fatal("auth-token flag must set")
	}
	if !e.IsWorldReadable {
		t.Fatal("0o644 must flag world-readable")
	}
	if !e.IsCredentialExposureRisk {
		t.Fatal("auth-token + world-readable must flag exposure")
	}
}

func TestAnnotateAuthToken0600Clean(t *testing.T) {
	e := Entry{EntryKind: EntryAuthToken, FileMode: 0o600}
	AnnotateSecurity(&e)
	if !e.IsAuthToken {
		t.Fatal("auth-token flag must set")
	}
	if e.IsWorldReadable || e.IsGroupReadable {
		t.Fatalf("0o600 must NOT flag perm bits: %+v", e)
	}
	if e.IsCredentialExposureRisk {
		t.Fatal("0o600 auth-token alone is NOT immediate-incident")
	}
}

func TestAnnotatePasswordGroupReadable(t *testing.T) {
	e := Entry{EntryKind: EntryPassword, FileMode: 0o640}
	AnnotateSecurity(&e)
	if !e.IsPasswordSecret {
		t.Fatal("password flag must set")
	}
	if !e.IsGroupReadable || e.IsWorldReadable {
		t.Fatalf("0o640 must flag group only: %+v", e)
	}
	if !e.IsCredentialExposureRisk {
		t.Fatal("password + group-readable must flag")
	}
}

func TestAnnotateStrictSSLFalse(t *testing.T) {
	e := Entry{EntryKind: EntrySetting, Key: "strict-ssl", Value: "false", FileMode: 0o600}
	AnnotateSecurity(&e)
	if !e.IsStrictSSLDisabled {
		t.Fatal("strict-ssl=false must flag")
	}
	if !e.IsCredentialExposureRisk {
		t.Fatal("strict-ssl=false must escalate to exposure risk")
	}
}

func TestAnnotateStrictSSLTrueClean(t *testing.T) {
	e := Entry{EntryKind: EntrySetting, Key: "strict-ssl", Value: "true", FileMode: 0o600}
	AnnotateSecurity(&e)
	if e.IsStrictSSLDisabled {
		t.Fatal("strict-ssl=true must NOT flag")
	}
}

func TestAnnotateScriptShellOverride(t *testing.T) {
	e := Entry{EntryKind: EntrySetting, Key: "script-shell", Value: "/tmp/mysh", FileMode: 0o600}
	AnnotateSecurity(&e)
	if !e.IsScriptShellOverride {
		t.Fatal("script-shell override must flag")
	}
}

func TestAnnotatePrefixWorldWritable(t *testing.T) {
	e := Entry{EntryKind: EntrySetting, Key: "prefix", Value: "/tmp/npm-global", FileMode: 0o600}
	AnnotateSecurity(&e)
	if !e.IsPrefixInWorldWritableDir {
		t.Fatal("prefix in /tmp must flag world-writable")
	}
	if !e.IsCredentialExposureRisk {
		t.Fatal("prefix in world-writable dir must escalate")
	}
}

func TestAnnotatePrefixSafe(t *testing.T) {
	e := Entry{EntryKind: EntrySetting, Key: "prefix", Value: "/usr/local", FileMode: 0o600}
	AnnotateSecurity(&e)
	if e.IsPrefixInWorldWritableDir {
		t.Fatal("/usr/local prefix must NOT flag")
	}
}

// -- ParseNpmrc ----------------------------------------------------

func TestParseNpmrcTypical(t *testing.T) {
	body := []byte(`# user npmrc
//registry.npmjs.org/:_authToken=npm_xxxxxxxxxxxxxx
//npm.pkg.github.com/:_authToken=ghp_yyyyyyyyyyyyyyy
//legacy.example.com/:_password=cGFzcw==
//legacy.example.com/:username=alice
@myorg:registry=https://npm.pkg.github.com
registry=https://registry.npmjs.org/
strict-ssl=false
script-shell=/tmp/mysh
prefix=/tmp/npm-global
always-auth
`)
	got := ParseNpmrc(body)
	if len(got) != 10 {
		t.Fatalf("rows=%d, want 10: %+v", len(got), got)
	}

	byKey := map[string]Entry{}
	for _, e := range got {
		byKey[e.Key] = e
	}

	tok := byKey["//registry.npmjs.org/:_authToken"]
	if tok.EntryKind != EntryAuthToken {
		t.Fatalf("token kind=%q", tok.EntryKind)
	}
	if tok.Value != "npm_" {
		t.Fatalf("token value should be 4-char prefix, got %q", tok.Value)
	}
	if tok.RegistryHost != "registry.npmjs.org" {
		t.Fatalf("token host=%q", tok.RegistryHost)
	}

	gh := byKey["//npm.pkg.github.com/:_authToken"]
	if gh.Value != "ghp_" {
		t.Fatalf("gh token prefix=%q", gh.Value)
	}

	pwd := byKey["//legacy.example.com/:_password"]
	if pwd.EntryKind != EntryPassword {
		t.Fatalf("pwd kind=%q", pwd.EntryKind)
	}
	if pwd.Value != "" {
		t.Fatalf("password must be cleared, got %q", pwd.Value)
	}

	user := byKey["//legacy.example.com/:username"]
	if user.EntryKind != EntryUsername {
		t.Fatalf("username kind=%q", user.EntryKind)
	}

	scoped := byKey["@myorg:registry"]
	if scoped.EntryKind != EntryScopeRegistry {
		t.Fatalf("scope kind=%q", scoped.EntryKind)
	}
	if scoped.Scope != "@myorg" {
		t.Fatalf("scope=%q", scoped.Scope)
	}

	reg := byKey["registry"]
	if reg.EntryKind != EntryRegistry {
		t.Fatalf("registry kind=%q", reg.EntryKind)
	}

	ssl := byKey["strict-ssl"]
	if ssl.EntryKind != EntrySetting || ssl.Value != "false" {
		t.Fatalf("strict-ssl: %+v", ssl)
	}

	shell := byKey["script-shell"]
	if shell.Value != "/tmp/mysh" {
		t.Fatalf("script-shell: %+v", shell)
	}

	prefix := byKey["prefix"]
	if prefix.Value != "/tmp/npm-global" {
		t.Fatalf("prefix: %+v", prefix)
	}

	bare := byKey["always-auth"]
	if bare.Value != "true" {
		t.Fatalf("bool-shortcut must default to true: %+v", bare)
	}
}

func TestParseBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte("registry=https://x\n")...)
	got := ParseNpmrc(body)
	if len(got) != 1 || got[0].EntryKind != EntryRegistry {
		t.Fatalf("BOM should be tolerated: %+v", got)
	}
}

func TestParseCommentsAndBlanksSkipped(t *testing.T) {
	body := []byte(`# top
; semi

# blank above
registry=https://x
`)
	got := ParseNpmrc(body)
	if len(got) != 1 {
		t.Fatalf("rows: %+v", got)
	}
}

func TestParseQuotedValueStripped(t *testing.T) {
	body := []byte(`registry="https://example.com"` + "\n")
	got := ParseNpmrc(body)
	if len(got) != 1 || got[0].Value != "https://example.com" {
		t.Fatalf("quoted value not stripped: %+v", got)
	}
}

// -- collector end-to-end -----------------------------------------

func TestFileCollectorWalksPerUserAndEnv(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")

	// alice's npmrc: token + strict-ssl=false, world-readable.
	aliceNpmrc := filepath.Join(usersBase, "alice", ".npmrc")
	must(t, os.MkdirAll(filepath.Dir(aliceNpmrc), 0o755))
	must(t, os.WriteFile(aliceNpmrc, []byte(`//registry.npmjs.org/:_authToken=npm_alice
strict-ssl=false
`), 0o644))

	// Env-supplied user config.
	envNpmrc := filepath.Join(tmp, "extra", "userconfig")
	must(t, os.MkdirAll(filepath.Dir(envNpmrc), 0o755))
	must(t, os.WriteFile(envNpmrc, []byte(`//npm.pkg.github.com/:_authToken=ghp_ci
`), 0o600))

	// Public profile must be skipped.
	must(t, os.MkdirAll(filepath.Join(usersBase, "Public"), 0o755))
	must(t, os.WriteFile(filepath.Join(usersBase, "Public", ".npmrc"),
		[]byte("//registry.npmjs.org/:_authToken=skip\n"), 0o644))

	c := &fileCollector{
		usersBases:  []string{usersBase},
		globalPaths: nil,
		getenv: func(k string) string {
			if k == "NPM_CONFIG_USERCONFIG" {
				return envNpmrc
			}
			return ""
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// alice: 2. env: 1. Public: skipped. Total = 3.
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}

	var aliceTok Entry
	for _, e := range got {
		if e.UserProfile == "alice" && e.EntryKind == EntryAuthToken {
			aliceTok = e
		}
	}
	if aliceTok.FilePath == "" {
		t.Fatal("alice auth-token row missing")
	}
	if !aliceTok.IsCredentialExposureRisk {
		t.Fatalf("alice token + world-readable must flag: %+v", aliceTok)
	}
	if aliceTok.Value != "npm_" {
		t.Fatalf("alice token value=%q want npm_", aliceTok.Value)
	}

	var ci Entry
	for _, e := range got {
		if e.FilePath == envNpmrc {
			ci = e
		}
	}
	if ci.FilePath == "" {
		t.Fatal("env-supplied userconfig missing — NPM_CONFIG_USERCONFIG not honoured")
	}
	if ci.Value != "ghp_" {
		t.Fatalf("ci token prefix=%q", ci.Value)
	}

	// strict-ssl row must be present and flagged.
	var ssl Entry
	for _, e := range got {
		if e.Key == "strict-ssl" {
			ssl = e
		}
	}
	if !ssl.IsStrictSSLDisabled {
		t.Fatalf("strict-ssl row missing or unflagged: %+v", ssl)
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		usersBases:  []string{"/nope-users"},
		globalPaths: nil,
		getenv:      func(string) string { return "" },
		readFile:    os.ReadFile,
		readDir:     os.ReadDir,
		statFile:    os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortEntries ---------------------------------------------------

func TestSortEntriesDeterministic(t *testing.T) {
	in := []Entry{
		{FilePath: "z", EntryKind: EntrySetting, Key: "a"},
		{FilePath: "a", EntryKind: EntrySetting, Key: "z"},
		{FilePath: "a", EntryKind: EntryAuthToken, Key: "//x/:_authToken"},
	}
	SortEntries(in)
	if in[0].FilePath != "a" || in[0].EntryKind != EntryAuthToken {
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
