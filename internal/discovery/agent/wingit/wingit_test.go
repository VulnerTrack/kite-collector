package wingit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedFileScopeStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ScopeSystem), "system"},
		{string(ScopeGlobal), "global"},
		{string(ScopeXDG), "xdg"},
		{string(ScopeCredentials), "credentials"},
		{string(ScopeUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("file_scope drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPinnedEntryKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(EntryKindSetting), "setting"},
		{string(EntryKindCredentialRecord), "credential-record"},
		{string(EntryKindUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("entry_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("[core]\n"))
	b := HashContents([]byte("[core]\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsCommandOverrideKey(t *testing.T) {
	for _, k := range []string{"core.editor", "core.pager", "core.sshcommand", "diff.tool"} {
		if !IsCommandOverrideKey(k) {
			t.Fatalf("%q must flag command override", k)
		}
	}
	for _, k := range []string{"core.editor.alias", "user.name", ""} {
		if IsCommandOverrideKey(k) {
			t.Fatalf("%q must NOT flag command override", k)
		}
	}
}

func TestIsWorldWritableDir(t *testing.T) {
	hit := []string{
		`C:\Users\Public\hooks`,
		`/tmp/hooks`,
		`/var/tmp/foo`,
		`%TEMP%\hooks`,
	}
	for _, d := range hit {
		if !IsWorldWritableDir(d) {
			t.Fatalf("%q must flag world-writable", d)
		}
	}
	for _, d := range []string{`C:\Program Files\Git\hooks`, "/usr/local/etc/hooks", ""} {
		if IsWorldWritableDir(d) {
			t.Fatalf("%q must NOT flag world-writable", d)
		}
	}
}

func TestCredentialRecordHost(t *testing.T) {
	cases := map[string]string{
		"https://alice:abc@github.com/org/repo":   "github.com",
		"https://x:y@gitlab.internal.example.com": "gitlab.internal.example.com",
		"https://alice:abc@gitea.local:8443/x":    "gitea.local",
		"":                                        "",
		"not a url":                               "",
	}
	for in, want := range cases {
		if got := CredentialRecordHost(in); got != want {
			t.Fatalf("CredentialRecordHost(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateCredentialHelperStore(t *testing.T) {
	e := Entry{
		EntryKind: EntryKindSetting,
		Key:       "credential.helper",
		Value:     "store",
	}
	AnnotateSecurity(&e)
	if !e.IsCredentialStoreHelper || !e.IsCredentialExposureRisk {
		t.Fatalf("credential.helper=store must flag: %+v", e)
	}
}

func TestAnnotateCredentialHelperEmpty(t *testing.T) {
	e := Entry{
		EntryKind: EntryKindSetting,
		Key:       "credential.helper",
		Value:     "",
	}
	AnnotateSecurity(&e)
	if !e.IsNoCredentialHelper || !e.IsCredentialExposureRisk {
		t.Fatalf("empty credential.helper must flag: %+v", e)
	}
}

func TestAnnotateCredentialHelperManagerClean(t *testing.T) {
	e := Entry{
		EntryKind: EntryKindSetting,
		Key:       "credential.helper",
		Value:     "manager-core",
	}
	AnnotateSecurity(&e)
	if e.IsCredentialStoreHelper || e.IsCredentialExposureRisk {
		t.Fatal("manager-core helper must NOT flag")
	}
}

func TestAnnotateURLRewrite(t *testing.T) {
	e := Entry{
		EntryKind:  EntryKindSetting,
		Section:    "url",
		Subsection: "git@github.com:",
		Key:        "url.git@github.com:.insteadof",
		Value:      "https://github.com/",
	}
	AnnotateSecurity(&e)
	if !e.IsURLRewrite {
		t.Fatal("url.X.insteadOf must flag")
	}
}

func TestAnnotateExternalHooksPath(t *testing.T) {
	e := Entry{
		EntryKind: EntryKindSetting,
		Key:       "core.hookspath",
		Value:     "/tmp/hooks",
	}
	AnnotateSecurity(&e)
	if !e.IsExternalHooksPath {
		t.Fatal("/tmp hookspath must flag")
	}
	if !e.IsCredentialExposureRisk {
		t.Fatal("external hookspath must flag exposure")
	}
}

func TestAnnotateCommandOverride(t *testing.T) {
	e := Entry{
		EntryKind: EntryKindSetting,
		Key:       "core.sshcommand",
		Value:     "ssh -i ~/.ssh/key",
	}
	AnnotateSecurity(&e)
	if !e.HasCommandOverride {
		t.Fatal("core.sshcommand must flag")
	}
}

func TestAnnotatePlaintextCredentialRow(t *testing.T) {
	e := Entry{
		EntryKind: EntryKindCredentialRecord,
		Key:       "credential.github.com",
		Value:     "github.com",
	}
	AnnotateSecurity(&e)
	if !e.IsPlaintextCredential || !e.IsCredentialExposureRisk {
		t.Fatalf("credential-record row must flag plaintext: %+v", e)
	}
}

func TestAnnotateFileModeFlags(t *testing.T) {
	e := Entry{EntryKind: EntryKindCredentialRecord, FileMode: 0o644}
	AnnotateSecurity(&e)
	if !e.IsWorldReadable {
		t.Fatal("0o644 must flag world-readable")
	}
	if !e.IsCredentialExposureRisk {
		t.Fatal("plaintext + world-readable must flag")
	}
}

// -- ParseGitConfig end-to-end --------------------------------------

func TestParseGitConfigTypical(t *testing.T) {
	body := []byte(`# alice's git config
[user]
    name = Alice
    email = alice@example.com
    signingkey = ABC123
[credential]
    helper = store
[url "git@github.com:"]
    insteadOf = https://github.com/
[core]
    editor = vim
    hookspath = /tmp/hooks
    sshCommand = ssh -i ~/.ssh/key
[boolean.flag]
    enabled
`)
	got := ParseGitConfig(body)
	if len(got) < 9 {
		t.Fatalf("rows=%d, want >=9: %+v", len(got), got)
	}

	byKey := map[string]Entry{}
	for _, e := range got {
		byKey[e.Key] = e
	}
	if byKey["user.name"].Value != "Alice" {
		t.Fatalf("user.name=%q", byKey["user.name"].Value)
	}
	if byKey["credential.helper"].Value != "store" {
		t.Fatalf("credential.helper=%q", byKey["credential.helper"].Value)
	}
	rewrite, ok := byKey["url.git@github.com:.insteadof"]
	if !ok {
		t.Fatalf("url.X.insteadOf key missing: %+v", got)
	}
	if rewrite.Value != "https://github.com/" {
		t.Fatalf("insteadof=%q", rewrite.Value)
	}
	if byKey["core.hookspath"].Value != "/tmp/hooks" {
		t.Fatal("hookspath value lost")
	}
	// Bare-key boolean shortcut.
	if byKey["boolean.flag.enabled"].Value != "true" {
		t.Fatalf("bool shortcut: %+v", byKey["boolean.flag.enabled"])
	}
}

func TestParseGitConfigDottedSubsection(t *testing.T) {
	body := []byte(`[remote.origin]
    url = git@github.com:org/repo
`)
	got := ParseGitConfig(body)
	if len(got) != 1 {
		t.Fatalf("rows=%d", len(got))
	}
	if got[0].Subsection != "origin" {
		t.Fatalf("subsection=%q", got[0].Subsection)
	}
	if got[0].Key != "remote.origin.url" {
		t.Fatalf("key=%q", got[0].Key)
	}
}

func TestParseGitConfigInlineComment(t *testing.T) {
	body := []byte(`[core]
    editor = vim   # my preference
    name = "value;with;semis"   ; line comment
`)
	got := ParseGitConfig(body)
	if len(got) != 2 {
		t.Fatalf("rows=%d", len(got))
	}
	if got[0].Value != "vim" {
		t.Fatalf("inline-comment strip wrong: %q", got[0].Value)
	}
	if got[1].Value != "value;with;semis" {
		t.Fatalf("quoted-semi value lost: %q", got[1].Value)
	}
}

func TestParseGitConfigBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF},
		[]byte("[user]\n    name = X\n")...)
	got := ParseGitConfig(body)
	if len(got) != 1 || got[0].Value != "X" {
		t.Fatalf("BOM parse: %+v", got)
	}
}

func TestParseGitCredentialsStore(t *testing.T) {
	body := []byte(`# stored creds
https://alice:secret@github.com
https://bob:x@gitlab.example.com:8443/org

https://no-creds.example.com
not-a-url
`)
	got := ParseGitCredentialsStore(body)
	if len(got) != 3 {
		t.Fatalf("rows=%d, want 3: %+v", len(got), got)
	}
	hosts := map[string]bool{}
	for _, e := range got {
		hosts[e.Value] = true
	}
	if !hosts["github.com"] || !hosts["gitlab.example.com"] ||
		!hosts["no-creds.example.com"] {
		t.Fatalf("hosts=%+v", hosts)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksGlobalAndCredentials(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")

	// alice's gitconfig with credential.helper=store + url rewrite.
	aliceHome := filepath.Join(usersBase, "alice")
	must(t, os.MkdirAll(aliceHome, 0o755))
	must(t, os.WriteFile(filepath.Join(aliceHome, ".gitconfig"), []byte(`[user]
    name = Alice
[credential]
    helper = store
[url "git@github.com:"]
    insteadOf = https://github.com/
`), 0o600))

	// alice's git-credentials world-readable.
	must(t, os.WriteFile(filepath.Join(aliceHome, ".git-credentials"),
		[]byte(`https://alice:abc@github.com`+"\n"), 0o644))

	// Public profile must be skipped.
	pubHome := filepath.Join(usersBase, "Public")
	must(t, os.MkdirAll(pubHome, 0o755))
	must(t, os.WriteFile(filepath.Join(pubHome, ".gitconfig"),
		[]byte("[user]\nname = Skip\n"), 0o644))

	// System gitconfig (not present in tmp — should be silently
	// skipped via systemConfigs missing).

	c := &fileCollector{
		usersBases:    []string{usersBase},
		systemConfigs: nil,
		getenv:        func(string) string { return "" },
		readFile:      os.ReadFile,
		readDir:       os.ReadDir,
		statFile:      os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// alice .gitconfig: 3 settings. alice .git-credentials: 1. Public: 0.
	if len(got) != 4 {
		t.Fatalf("want 4, got %d: %+v", len(got), got)
	}

	byKey := map[string]Entry{}
	for _, e := range got {
		byKey[e.Key+"|"+string(e.FileScope)] = e
	}

	helper := byKey["credential.helper|global"]
	if !helper.IsCredentialStoreHelper {
		t.Fatalf("helper=store flag missing: %+v", helper)
	}

	rewrite := byKey["url.git@github.com:.insteadof|global"]
	if !rewrite.IsURLRewrite {
		t.Fatalf("rewrite flag missing: %+v", rewrite)
	}

	cred := byKey["credential.github.com|credentials"]
	if !cred.IsPlaintextCredential || !cred.IsCredentialExposureRisk {
		t.Fatalf("credential leak flag missing: %+v", cred)
	}
	if !cred.IsWorldReadable {
		t.Fatalf("0o644 must flag world-readable: %+v", cred)
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		usersBases:    []string{"/nope-users"},
		systemConfigs: []string{"/nope-system"},
		getenv:        func(string) string { return "" },
		readFile:      os.ReadFile,
		readDir:       os.ReadDir,
		statFile:      os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortEntries ----------------------------------------------------

func TestSortEntriesDeterministic(t *testing.T) {
	in := []Entry{
		{FilePath: "z", Section: "a", Key: "a"},
		{FilePath: "a", Section: "z", Key: "a"},
		{FilePath: "a", Section: "a", Key: "z"},
	}
	SortEntries(in)
	if in[0].FilePath != "a" || in[0].Section != "a" {
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
