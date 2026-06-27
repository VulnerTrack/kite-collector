package pam

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPinnedEnumStrings prevents drift between the Go const values and
// the SQLite CHECK constraint on host_pam_configs.type.
func TestPinnedEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(TypeAuth), "auth"},
		{string(TypeAccount), "account"},
		{string(TypeSession), "session"},
		{string(TypePassword), "password"},
		{string(TypeInclude), "include"},
		{string(TypeSubstack), "substack"},
		{string(TypeUnknown), "unknown"},
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
	got := EncodeStringList([]string{"nullok", "try_first_pass"})
	want := `["nullok","try_first_pass"]`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("auth required pam_unix.so\n"))
	b := HashContents([]byte("auth required pam_unix.so\n"))
	if a != b {
		t.Fatal("not deterministic")
	}
	if len(a) != 64 {
		t.Fatalf("expected sha256 hex, got %d chars", len(a))
	}
	c := HashContents([]byte("auth sufficient pam_permit.so\n"))
	if a == c {
		t.Fatal("hash should differ for different contents")
	}
}

func TestIsUnconditionalPassModule(t *testing.T) {
	for _, m := range []string{"pam_permit.so"} {
		if !IsUnconditionalPassModule(m) {
			t.Fatalf("%q must flag as unconditional-pass", m)
		}
	}
	for _, m := range []string{"pam_unix.so", "pam_sss.so", "", "pam_deny.so"} {
		if IsUnconditionalPassModule(m) {
			t.Fatalf("%q must NOT flag", m)
		}
	}
}

func TestIsStandardModulePath(t *testing.T) {
	cases := map[string]bool{
		"":                              true, // bare-name resolution
		"/usr/lib/security/pam_unix.so": true,
		"/lib/security/pam_unix.so":     true,
		"/usr/lib64/pam_sss.so":         true,
		"/usr/local/lib/security/x.so":  true,
		"/tmp/evil.so":                  false,
		"/home/attacker/pam_bypass.so":  false,
		"/var/lib/something.so":         false,
	}
	for path, want := range cases {
		if got := IsStandardModulePath(path); got != want {
			t.Fatalf("IsStandardModulePath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestSplitMergeContinuationsPAM(t *testing.T) {
	in := "auth required pam_unix.so \\\n    try_first_pass nullok\nplain line\n"
	got := splitMergeContinuations(in)
	if len(got) < 2 {
		t.Fatalf("got %d lines: %q", len(got), got)
	}
	if got[0] != "auth required pam_unix.so try_first_pass nullok" {
		t.Fatalf("continuation merge wrong: %q", got[0])
	}
	if got[1] != "plain line" {
		t.Fatalf("post-continuation line: %q", got[1])
	}
}

func TestSplitTokensRespectingBrackets(t *testing.T) {
	// The classic PAM bracketed control syntax.
	got := splitTokensRespectingBrackets(
		`auth [success=2 default=ignore] pam_unix.so try_first_pass`)
	want := []string{
		"auth",
		"[success=2 default=ignore]",
		"pam_unix.so",
		"try_first_pass",
	}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pos %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSplitTokensTabSeparated(t *testing.T) {
	got := splitTokensRespectingBrackets("auth\trequired\tpam_unix.so")
	if len(got) != 3 || got[0] != "auth" || got[2] != "pam_unix.so" {
		t.Fatalf("tab split failed: %v", got)
	}
}

func TestStripComment(t *testing.T) {
	cases := map[string]string{
		"auth required pam_unix.so # nice comment": "auth required pam_unix.so ",
		"# whole line": "",
		"plain line":   "plain line",
		"":             "",
	}
	for in, want := range cases {
		if got := stripComment(in); got != want {
			t.Fatalf("stripComment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCollapseWhitespace(t *testing.T) {
	got := collapseWhitespace("  auth\trequired\t\tpam_unix.so  nullok ")
	want := "auth required pam_unix.so nullok"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestArgsContainBareAndKeyValue(t *testing.T) {
	args := []string{"nullok", "try_first_pass", "minlen=8", "use_authtok"}
	for _, want := range []string{"nullok", "try_first_pass", "minlen", "use_authtok"} {
		if !argsContain(args, want) {
			t.Fatalf("must find %q in %v", want, args)
		}
	}
	for _, miss := range []string{"deny", "remember", ""} {
		if argsContain(args, miss) {
			t.Fatalf("must NOT find %q in %v", miss, args)
		}
	}
}

// -- parser end-to-end ----------------------------------------------------

func TestParseRealisticSSHDStack(t *testing.T) {
	// Realistic /etc/pam.d/sshd seeded with an attacker's bypass +
	// pam_unix nullok to test both flags simultaneously.
	body := []byte(`# /etc/pam.d/sshd
auth       required     pam_env.so
auth       sufficient   pam_permit.so
auth       [success=1 default=ignore] pam_unix.so nullok try_first_pass
auth       required     pam_deny.so
account    required     pam_unix.so
session    required     pam_unix.so
password   required     pam_unix.so sha512 shadow
@include   common-session
`)
	got := Parse(body, "sshd", "/etc/pam.d/sshd")

	// Verify both threat findings.
	var (
		sawPermit  bool
		sawNullok  bool
		sawInclude bool
	)
	for _, d := range got {
		if d.IsUnconditionalPass {
			sawPermit = true
			if d.Control != "sufficient" || !d.ShortCircuitsStack {
				t.Fatalf("pam_permit.so with control=sufficient must short-circuit: %+v", d)
			}
		}
		if d.IsNullok {
			sawNullok = true
			if d.Module != "pam_unix.so" {
				t.Fatalf("nullok must come from pam_unix.so, got %q", d.Module)
			}
		}
		if d.Type == TypeInclude {
			sawInclude = true
			if d.Module != "common-session" {
				t.Fatalf("@include target wrong: %q", d.Module)
			}
		}
		if d.FileHash == "" {
			t.Fatalf("file_hash missing on %+v", d)
		}
		if d.Service != "sshd" {
			t.Fatalf("service must come from caller, got %q", d.Service)
		}
	}
	if !sawPermit {
		t.Fatal("pam_permit.so bypass not detected (T1556.003 finding lost)")
	}
	if !sawNullok {
		t.Fatal("nullok arg not detected on pam_unix.so")
	}
	if !sawInclude {
		t.Fatal("@include directive lost")
	}

	// Bracketed control must survive splitting.
	var bracket Directive
	for _, d := range got {
		if strings.HasPrefix(d.Control, "[") {
			bracket = d
			break
		}
	}
	if !strings.Contains(bracket.Control, "success=1") {
		t.Fatalf("bracketed control mangled: %q", bracket.Control)
	}
}

func TestParseAbsoluteModulePathDetected(t *testing.T) {
	body := []byte("auth required /tmp/evil.so\n")
	got := Parse(body, "victim", "/etc/pam.d/victim")
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	d := got[0]
	if d.Module != "evil.so" {
		t.Fatalf("module basename=%q", d.Module)
	}
	if d.ModulePath != "/tmp/evil.so" {
		t.Fatalf("module_path=%q", d.ModulePath)
	}
	if !d.IsNonstandardPath {
		t.Fatal("/tmp/* must be flagged as nonstandard (CWE-829)")
	}
}

func TestParseStandardModulePathNotFlagged(t *testing.T) {
	body := []byte("auth required /usr/lib/security/pam_unix.so\n")
	got := Parse(body, "x", "/etc/pam.d/x")
	if len(got) != 1 {
		t.Fatal("len mismatch")
	}
	if got[0].IsNonstandardPath {
		t.Fatal("/usr/lib/security must NOT be flagged nonstandard")
	}
}

func TestParseCommentAndBlankLinesIgnored(t *testing.T) {
	body := []byte("# top comment\n\n  \nauth required pam_unix.so\n# trailing\n")
	got := Parse(body, "x", "/etc/pam.d/x")
	if len(got) != 1 {
		t.Fatalf("len=%d, want 1: %+v", len(got), got)
	}
}

func TestParseHonoursMaxDirectivesCeiling(t *testing.T) {
	// Synthesise body > MaxDirectives lines.
	var sb strings.Builder
	for i := 0; i < MaxDirectives+50; i++ {
		sb.WriteString("auth required pam_unix.so\n")
	}
	got := Parse([]byte(sb.String()), "x", "/etc/pam.d/x")
	if len(got) > MaxDirectives {
		t.Fatalf("got %d > MaxDirectives %d", len(got), MaxDirectives)
	}
}

// -- collector ------------------------------------------------------------

func TestPamIncludesFile(t *testing.T) {
	cases := map[string]bool{
		"sshd":          true,
		"common-auth":   true,
		"system-auth":   true,
		"sshd.bak":      false,
		"sshd.dpkg-old": false,
		"sshd~":         false,
		".hidden":       false,
		"sshd.rpmnew":   false,
		"sshd.swp":      false,
		"":              false,
		"login":         true,
	}
	for in, want := range cases {
		if got := pamIncludesFile(in); got != want {
			t.Fatalf("pamIncludesFile(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFileCollectorWalksPamD(t *testing.T) {
	tmp := t.TempDir()
	pamD := filepath.Join(tmp, "pam.d")
	if err := os.MkdirAll(pamD, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(pamD, "sshd"), `auth sufficient pam_permit.so
account required pam_unix.so
`)
	mustWrite(t, filepath.Join(pamD, "login"), `auth required pam_unix.so nullok
`)
	mustWrite(t, filepath.Join(pamD, "ignored.bak"), `auth required pam_evil.so
`)
	mustWrite(t, filepath.Join(pamD, "vim-swap~"), `auth required pam_evil.so
`)

	c := &fileCollector{
		pamD:     pamD,
		pamConf:  filepath.Join(tmp, "pam.conf-missing"),
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 2 from sshd + 1 from login = 3. Backup + swap MUST be skipped.
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}
	var (
		permit bool
		nullok bool
	)
	for _, d := range got {
		if d.IsUnconditionalPass {
			permit = true
		}
		if d.IsNullok {
			nullok = true
		}
	}
	if !permit {
		t.Fatal("pam_permit.so finding lost across collector boundary")
	}
	if !nullok {
		t.Fatal("nullok finding lost across collector boundary")
	}
}

func TestFileCollectorParsesPamConf(t *testing.T) {
	tmp := t.TempDir()
	pamConf := filepath.Join(tmp, "pam.conf")
	mustWrite(t, pamConf, `# legacy single-file pam.conf
sshd auth sufficient pam_permit.so
sshd account required pam_unix.so
login auth required pam_unix.so nullok
`)
	c := &fileCollector{
		pamD:     filepath.Join(tmp, "pam.d-missing"),
		pamConf:  pamConf,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}
	services := map[string]bool{}
	for _, d := range got {
		services[d.Service] = true
	}
	if !services["sshd"] || !services["login"] {
		t.Fatalf("pam.conf services lost: %v", services)
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		pamD:     "/nope",
		pamConf:  "/also-nope",
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

func TestFileCollectorDriftHash(t *testing.T) {
	tmp := t.TempDir()
	pamD := filepath.Join(tmp, "pam.d")
	if err := os.MkdirAll(pamD, 0o755); err != nil {
		t.Fatal(err)
	}
	sshd := filepath.Join(pamD, "sshd")

	mustWrite(t, sshd, "auth required pam_unix.so\n")
	c := &fileCollector{
		pamD: pamD, pamConf: "/nope",
		readFile: os.ReadFile, readDir: os.ReadDir,
	}
	r1, _ := c.Collect(context.Background())

	// Attacker drops the bypass line.
	mustWrite(t, sshd, "auth required pam_unix.so\nauth sufficient pam_permit.so\n")
	r2, _ := c.Collect(context.Background())

	if r1[0].FileHash == r2[0].FileHash {
		t.Fatal("file_hash must change after the file is modified")
	}
}

func TestSortDirectivesDeterministic(t *testing.T) {
	in := []Directive{
		{FilePath: "/etc/pam.d/sudo", LineNo: 1},
		{FilePath: "/etc/pam.d/sshd", LineNo: 5},
		{FilePath: "/etc/pam.d/sshd", LineNo: 2},
	}
	SortDirectives(in)
	if in[0].FilePath != "/etc/pam.d/sshd" || in[0].LineNo != 2 {
		t.Fatalf("first: %+v", in[0])
	}
	if in[2].FilePath != "/etc/pam.d/sudo" {
		t.Fatalf("last: %+v", in[2])
	}
}

// -- helpers --------------------------------------------------------------

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
