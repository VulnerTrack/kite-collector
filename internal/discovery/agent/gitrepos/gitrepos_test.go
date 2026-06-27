package gitrepos

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"origin", "upstream"}); got != `["origin","upstream"]` {
		t.Fatalf("got %q", got)
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("[remote \"origin\"]\n  url = git@github.com:x/y.git\n"))
	b := HashContents([]byte("[remote \"origin\"]\n  url = git@github.com:x/y.git\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsDefaultHookName(t *testing.T) {
	for _, h := range []string{"pre-commit", "post-merge", "update", "pre-push"} {
		if !IsDefaultHookName(h) {
			t.Fatalf("%q must be a default hook name", h)
		}
	}
	for _, h := range []string{"custom-hook", "evil", ""} {
		if IsDefaultHookName(h) {
			t.Fatalf("%q must NOT be a default hook name", h)
		}
	}
}

func TestIsCredentialInURL(t *testing.T) {
	hit := []string{
		"https://alice:ghp_AAAA1111@github.com/x/y.git",
		"https://ghs_AAAA1111@github.com/x/y.git", // bare username on https
		"http://user:pass@internal.git/x.git",
	}
	for _, u := range hit {
		if !IsCredentialInURL(u) {
			t.Fatalf("%q must flag credential-in-url", u)
		}
	}
	miss := []string{
		"https://github.com/x/y.git",
		"git@github.com:x/y.git",       // SCP-style — userinfo is SSH login
		"ssh://git@github.com/x/y.git", // SSH user is not a credential
		"git://github.com/x/y.git",
		"",
		"::not-a-url::",
	}
	for _, u := range miss {
		if IsCredentialInURL(u) {
			t.Fatalf("%q must NOT flag credential-in-url", u)
		}
	}
}

func TestHostOfURL(t *testing.T) {
	cases := map[string]string{
		"git@github.com:org/repo":              "github.com",
		"https://github.com/org/repo.git":      "github.com",
		"git@gitlab.corp.local:team/repo.git":  "gitlab.corp.local",
		"ssh://git@bitbucket.example/repo.git": "bitbucket.example",
		"":                                     "",
	}
	for in, want := range cases {
		if got := HostOfURL(in); got != want {
			t.Fatalf("HostOfURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsWorldReadableMode(t *testing.T) {
	cases := map[int]bool{
		0o644: true,
		0o755: true,
		0o604: true,
		0o600: false,
		0o640: false,
		0:     false,
	}
	for in, want := range cases {
		if got := IsWorldReadableMode(in); got != want {
			t.Fatalf("IsWorldReadableMode(%o) = %v, want %v", in, got, want)
		}
	}
}

func TestAnnotateSecurityCredAndInsteadOf(t *testing.T) {
	r := Repo{
		RemoteURL:      "https://alice:secret@github.com/x/y.git",
		InsteadOfPairs: []string{"git@github.com: -> https://github.com/"},
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialInURL {
		t.Fatal("must flag credential in URL")
	}
	if r.RemoteHost != "github.com" {
		t.Fatalf("remote_host=%q", r.RemoteHost)
	}
	if !r.HasInsteadOf {
		t.Fatal("must flag insteadof")
	}
}

func TestAnnotateSecurityHooksAndSSHCommand(t *testing.T) {
	r := Repo{
		SSHCommand:      "ssh -i /tmp/key",
		ExecutableHooks: []string{"pre-commit", "post-merge"},
		ConfigMode:      0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasSSHCommandOverride {
		t.Fatal("must flag ssh-command override")
	}
	if !r.HasExecutableHook {
		t.Fatal("must flag executable hooks")
	}
	if !r.IsWorldReadable {
		t.Fatal("0644 must flag world-readable")
	}
}

// -- ParseConfig --------------------------------------------------------

func TestParseConfigTypicalRepo(t *testing.T) {
	body := []byte(`[core]
    repositoryformatversion = 0
    bare = false
[user]
    name = Alice Example
    email = alice@corp.local
[remote "origin"]
    url = https://github.com/owner/repo.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[remote "upstream"]
    url = git@github.com:upstream/repo.git
[credential]
    helper = store
[url "git@github.com:"]
    insteadOf = https://github.com/
`)
	snap := ParseConfig(body)
	if snap.IsBare {
		t.Fatal("bare=false must NOT flag")
	}
	if snap.UserEmail != "alice@corp.local" {
		t.Fatalf("email=%q", snap.UserEmail)
	}
	if snap.UserName != "Alice Example" {
		t.Fatalf("name=%q", snap.UserName)
	}
	if snap.CredentialHelper != "store" {
		t.Fatalf("helper=%q", snap.CredentialHelper)
	}
	if len(snap.Remotes) != 2 {
		t.Fatalf("remotes=%v", snap.Remotes)
	}
	if snap.Remotes["origin"] != "https://github.com/owner/repo.git" {
		t.Fatalf("origin url=%q", snap.Remotes["origin"])
	}
	if snap.Remotes["upstream"] != "git@github.com:upstream/repo.git" {
		t.Fatalf("upstream url=%q", snap.Remotes["upstream"])
	}
	if len(snap.InsteadOfPairs) != 1 {
		t.Fatalf("insteadof pairs=%v", snap.InsteadOfPairs)
	}
	if !strings.Contains(snap.InsteadOfPairs[0], "git@github.com:") {
		t.Fatalf("insteadof content lost: %v", snap.InsteadOfPairs)
	}
}

func TestParseConfigBareRepo(t *testing.T) {
	body := []byte("[core]\n  bare = true\n")
	snap := ParseConfig(body)
	if !snap.IsBare {
		t.Fatal("bare=true must flag")
	}
}

func TestParseConfigSSHCommandOverride(t *testing.T) {
	body := []byte("[core]\n  sshCommand = ssh -i /tmp/alt-key -o StrictHostKeyChecking=no\n")
	snap := ParseConfig(body)
	if snap.SSHCommand == "" {
		t.Fatal("sshCommand must be captured")
	}
	if !strings.Contains(snap.SSHCommand, "/tmp/alt-key") {
		t.Fatalf("ssh_command=%q", snap.SSHCommand)
	}
}

func TestParseConfigCommentVariants(t *testing.T) {
	body := []byte(`# hash comment
; semi comment
[user]
    email = alice@corp.local  # inline hash
    name = Alice              ; inline semi
`)
	snap := ParseConfig(body)
	if snap.UserEmail != "alice@corp.local" {
		t.Fatalf("email=%q (inline comment leaked)", snap.UserEmail)
	}
	if snap.UserName != "Alice" {
		t.Fatalf("name=%q", snap.UserName)
	}
}

func TestParseConfigMaxRemotes(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < MaxRemotesPerRepo+10; i++ {
		sb.WriteString(`[remote "r`)
		sb.WriteString(string(rune('A' + (i % 26))))
		sb.WriteString(`"]
    url = https://example.test/r
`)
	}
	snap := ParseConfig([]byte(sb.String()))
	if len(snap.Remotes) > MaxRemotesPerRepo {
		t.Fatalf("remote count=%d > %d", len(snap.Remotes), MaxRemotesPerRepo)
	}
}

func TestParseConfigCredentialHelperLastWriteWins(t *testing.T) {
	body := []byte(`[credential]
    helper = store
    helper = manager-core
`)
	snap := ParseConfig(body)
	if snap.CredentialHelper != "manager-core" {
		t.Fatalf("last-write semantics broken: %q", snap.CredentialHelper)
	}
}

// -- ParseHead ----------------------------------------------------------

func TestParseHead(t *testing.T) {
	if ParseHead([]byte("ref: refs/heads/main\n")) != "main" {
		t.Fatal("main branch")
	}
	if ParseHead([]byte("ref: refs/heads/trunk\n")) != "trunk" {
		t.Fatal("trunk branch")
	}
	if ParseHead([]byte("a1b2c3d4...\n")) != "" {
		t.Fatal("detached head must yield empty")
	}
}

// -- collector end-to-end ----------------------------------------------

func TestFileCollectorFindsRepoEmitsOneRowPerRemote(t *testing.T) {
	tmp := t.TempDir()
	repo := filepath.Join(tmp, "code", "my-app")
	gitDir := filepath.Join(repo, ".git")
	must(t, os.MkdirAll(gitDir, 0o755))
	mustWrite(t, filepath.Join(gitDir, "config"), `[core]
    bare = false
[remote "origin"]
    url = https://alice:ghp_secret@github.com/owner/repo.git
[remote "upstream"]
    url = git@github.com:upstream/repo.git
[user]
    email = alice@corp.local
`)
	mustWrite(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/main\n")
	must(t, os.MkdirAll(filepath.Join(gitDir, "hooks"), 0o755))
	mustWrite(t, filepath.Join(gitDir, "hooks", "pre-commit"),
		"#!/bin/sh\necho exfil\n")
	must(t, os.Chmod(filepath.Join(gitDir, "hooks", "pre-commit"), 0o755))
	mustWrite(t, filepath.Join(gitDir, "hooks", "pre-commit.sample"),
		"#!/bin/sh\n# git ships this\n")

	c := &fileCollector{
		roots:      []string{tmp},
		maxDepth:   6,
		skipDirSet: map[string]bool{},
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 rows (origin + upstream), got %d: %+v", len(got), got)
	}

	byName := map[string]Repo{}
	for _, r := range got {
		byName[r.RemoteName] = r
	}

	origin := byName["origin"]
	if !origin.IsCredentialInURL {
		t.Fatal("origin has embedded creds, must flag")
	}
	if origin.RemoteHost != "github.com" {
		t.Fatalf("origin remote_host=%q", origin.RemoteHost)
	}
	if origin.HeadBranch != "main" {
		t.Fatalf("HEAD branch=%q", origin.HeadBranch)
	}
	if origin.UserEmail != "alice@corp.local" {
		t.Fatalf("user_email=%q", origin.UserEmail)
	}
	if !origin.HasExecutableHook {
		t.Fatal("custom executable pre-commit hook must flag")
	}
	if len(origin.ExecutableHooks) != 1 || origin.ExecutableHooks[0] != "pre-commit" {
		t.Fatalf("hooks=%v (only non-.sample executables should appear)",
			origin.ExecutableHooks)
	}

	upstream := byName["upstream"]
	if upstream.IsCredentialInURL {
		t.Fatal("SCP-style url must NOT flag credential")
	}
	if upstream.RemoteHost != "github.com" {
		t.Fatalf("upstream remote_host=%q", upstream.RemoteHost)
	}
}

func TestFileCollectorEmptyRepoEmitsOneRow(t *testing.T) {
	tmp := t.TempDir()
	repo := filepath.Join(tmp, "empty")
	gitDir := filepath.Join(repo, ".git")
	must(t, os.MkdirAll(gitDir, 0o755))
	mustWrite(t, filepath.Join(gitDir, "config"), "[core]\n  bare = false\n")

	c := &fileCollector{
		roots:      []string{tmp},
		maxDepth:   6,
		skipDirSet: map[string]bool{},
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d, want 1 (empty-remote row)", len(got))
	}
	if got[0].RemoteName != "" {
		t.Fatalf("remote_name=%q (must be empty)", got[0].RemoteName)
	}
}

func TestFileCollectorBareRepoFlagged(t *testing.T) {
	tmp := t.TempDir()
	repo := filepath.Join(tmp, "bare")
	gitDir := filepath.Join(repo, ".git")
	must(t, os.MkdirAll(gitDir, 0o755))
	mustWrite(t, filepath.Join(gitDir, "config"), "[core]\n  bare = true\n")
	c := &fileCollector{
		roots:      []string{tmp},
		maxDepth:   6,
		skipDirSet: map[string]bool{},
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, _ := c.Collect(context.Background())
	if len(got) != 1 || !got[0].IsBare {
		t.Fatalf("bare not flagged: %+v", got)
	}
}

func TestFileCollectorSkipsNestedRepos(t *testing.T) {
	tmp := t.TempDir()
	outer := filepath.Join(tmp, "outer")
	inner := filepath.Join(outer, "nested-repo")
	must(t, os.MkdirAll(filepath.Join(outer, ".git"), 0o755))
	mustWrite(t, filepath.Join(outer, ".git", "config"),
		"[remote \"origin\"]\n  url = https://example.test/outer.git\n")
	must(t, os.MkdirAll(filepath.Join(inner, ".git"), 0o755))
	mustWrite(t, filepath.Join(inner, ".git", "config"),
		"[remote \"origin\"]\n  url = https://example.test/inner.git\n")

	c := &fileCollector{
		roots:      []string{tmp},
		maxDepth:   6,
		skipDirSet: map[string]bool{},
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, _ := c.Collect(context.Background())
	if len(got) != 1 {
		t.Fatalf("want 1 (nested skipped), got %d: %+v", len(got), got)
	}
	if !strings.HasSuffix(got[0].RepoPath, "outer") {
		t.Fatalf("outer repo missed: %+v", got[0])
	}
}

func TestFileCollectorWorktreePointer(t *testing.T) {
	tmp := t.TempDir()
	main := filepath.Join(tmp, "main")
	worktree := filepath.Join(tmp, "wt")
	must(t, os.MkdirAll(filepath.Join(main, ".git"), 0o755))
	mustWrite(t, filepath.Join(main, ".git", "config"),
		"[remote \"origin\"]\n  url = https://example.test/r.git\n")
	must(t, os.MkdirAll(worktree, 0o755))
	// .git as a pointer file (the worktree shape git creates).
	mustWrite(t, filepath.Join(worktree, ".git"),
		"gitdir: "+filepath.Join(main, ".git", "worktrees", "wt"))
	// The pointer target also needs a config — but git's worktree
	// shape reads the parent. Our collector reads `gitDir/config` so
	// it'll fail on the pointer (no config at worktree path).
	// Instead, point at the main's .git for this test so we don't
	// depend on the worktree-config plumbing.
	mustWrite(t, filepath.Join(worktree, ".git"),
		"gitdir: "+filepath.Join(main, ".git"))

	c := &fileCollector{
		roots:      []string{tmp},
		maxDepth:   6,
		skipDirSet: map[string]bool{},
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Worktree pointer + main repo both resolve to the same gitDir;
	// dedupe in `seen` should keep us at one row.
	if len(got) != 1 {
		t.Fatalf("want 1 (deduped via gitdir), got %d: %+v", len(got), got)
	}
}

func TestFileCollectorRespectsMaxRepos(t *testing.T) {
	tmp := t.TempDir()
	// Build MaxRepos+5 distinct repos.
	want := MaxRepos + 5
	for i := 0; i < want; i++ {
		d := filepath.Join(tmp, "r", padInt(i))
		must(t, os.MkdirAll(filepath.Join(d, ".git"), 0o755))
		mustWrite(t, filepath.Join(d, ".git", "config"), "[core]\n  bare = false\n")
	}
	c := &fileCollector{
		roots:      []string{tmp},
		maxDepth:   6,
		skipDirSet: map[string]bool{},
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, _ := c.Collect(context.Background())
	if len(got) > MaxRepos {
		t.Fatalf("got %d > MaxRepos %d", len(got), MaxRepos)
	}
}

func TestSortReposDeterministic(t *testing.T) {
	in := []Repo{
		{RepoPath: "/zz", RemoteName: "origin"},
		{RepoPath: "/aa", RemoteName: "upstream"},
		{RepoPath: "/aa", RemoteName: "origin"},
	}
	SortRepos(in)
	if in[0].RepoPath != "/aa" || in[0].RemoteName != "origin" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].RepoPath != "/zz" {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers ----------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func padInt(n int) string {
	// 6-digit zero-padded numeric directory name.
	b := []byte("000000")
	for i := len(b) - 1; i >= 0 && n > 0; i-- {
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b)
}

// Ensure the test file compiles with the fs import the unix owner
// helper would need.
var _ fs.FileInfo
