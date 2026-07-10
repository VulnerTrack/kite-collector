package auditrules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedRuleKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(RuleKindFileWatch), "file-watch"},
		{string(RuleKindSyscall), "syscall"},
		{string(RuleKindControl), "control"},
		{string(RuleKindUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("rule_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPinnedListAndActionStrings(t *testing.T) {
	for _, p := range []struct{ got, want string }{
		{string(ListExit), "exit"},
		{string(ListExclude), "exclude"},
		{string(ListUser), "user"},
		{string(ListTask), "task"},
		{string(ListUnknown), "unknown"},
	} {
		if p.got != p.want {
			t.Fatalf("list drift: got %q want %q", p.got, p.want)
		}
	}
	for _, p := range []struct{ got, want string }{
		{string(ActionAlways), "always"},
		{string(ActionNever), "never"},
		{string(ActionUnknown), "unknown"},
	} {
		if p.got != p.want {
			t.Fatalf("action drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"openat", "open"}); got != `["openat","open"]` {
		t.Fatalf("got %q", got)
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("-w /etc/passwd -p wa -k identity\n"))
	b := HashContents([]byte("-w /etc/passwd -p wa -k identity\n"))
	if a != b || len(a) != 64 {
		t.Fatal("non-deterministic")
	}
}

func TestIsSensitivePathTarget(t *testing.T) {
	for _, p := range []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/pam.d",
		"/var/log/wtmp", "/sbin/auditctl",
	} {
		if !IsSensitivePathTarget(p) {
			t.Fatalf("%q must be flagged sensitive", p)
		}
	}
	for _, p := range []string{
		"/tmp/x", "/home/alice/.bashrc", "",
	} {
		if IsSensitivePathTarget(p) {
			t.Fatalf("%q must NOT be flagged sensitive", p)
		}
	}
}

func TestIsSelfDestructiveSyscallExclude(t *testing.T) {
	// Exclude audit_control on exit list = T1562.006 indicator.
	if !IsSelfDestructiveSyscallExclude(
		ActionNever, ListExit, []string{"audit_control"},
	) {
		t.Fatal("never+exit+audit_control must flag self-destructive")
	}
	// Always allow → not self-destructive.
	if IsSelfDestructiveSyscallExclude(
		ActionAlways, ListExit, []string{"audit_control"},
	) {
		t.Fatal("always must NOT flag self-destructive")
	}
	// Never+exit on a benign syscall is not self-destructive.
	if IsSelfDestructiveSyscallExclude(
		ActionNever, ListExit, []string{"openat"},
	) {
		t.Fatal("openat exclusion is not audit-suppression")
	}
}

// -- parser ---------------------------------------------------------------

func TestParseFileWatchTypical(t *testing.T) {
	body := []byte("-w /etc/passwd -p wa -k identity\n")
	got := Parse(body, "/etc/audit/rules.d/10-base.rules")
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	r := got[0]
	if r.RuleKind != RuleKindFileWatch {
		t.Fatalf("kind=%q", r.RuleKind)
	}
	if r.Path != "/etc/passwd" {
		t.Fatalf("path=%q", r.Path)
	}
	if r.Perm != "wa" {
		t.Fatalf("perm=%q", r.Perm)
	}
	if r.Key != "identity" {
		t.Fatalf("key=%q", r.Key)
	}
	if !r.IsSensitivePathWatch {
		t.Fatal("/etc/passwd must flag is_sensitive_path_watch")
	}
	if r.FileHash == "" {
		t.Fatal("file_hash missing")
	}
}

func TestParseSyscallTypical(t *testing.T) {
	body := []byte(`-a always,exit -F arch=b64 -S openat,open -F auid>=1000 -F auid!=unset -k file_access
`)
	got := Parse(body, "x.rules")
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	r := got[0]
	if r.RuleKind != RuleKindSyscall {
		t.Fatalf("kind=%q", r.RuleKind)
	}
	if r.Action != ActionAlways || r.List != ListExit {
		t.Fatalf("action/list = %q/%q", r.Action, r.List)
	}
	if r.Arch != "b64" {
		t.Fatalf("arch=%q", r.Arch)
	}
	if len(r.Syscalls) != 2 {
		t.Fatalf("syscalls=%v", r.Syscalls)
	}
	if len(r.Filters) < 3 { // arch + 2 auid filters
		t.Fatalf("filters=%v", r.Filters)
	}
	if r.Key != "file_access" {
		t.Fatalf("key=%q", r.Key)
	}
	if r.IsSelfDestructive {
		t.Fatal("openat watch is not self-destructive")
	}
}

func TestParseSelfDestructiveExcludeFlagged(t *testing.T) {
	body := []byte("-a never,exit -F arch=b64 -S audit_control -k evade\n")
	got := Parse(body, "x.rules")
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if !got[0].IsSelfDestructive {
		t.Fatal("never+audit_control must flag self-destructive (T1562.006)")
	}
}

func TestParseControlImmutable(t *testing.T) {
	body := []byte("-e 2\n")
	got := Parse(body, "x.rules")
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if !got[0].IsImmutable {
		t.Fatal("-e 2 must flag IsImmutable")
	}
	if got[0].RuleKind != RuleKindControl {
		t.Fatalf("kind=%q", got[0].RuleKind)
	}
}

func TestParseControlBacklog(t *testing.T) {
	body := []byte("-b 8192\n-f 1\n-D\n")
	got := Parse(body, "x.rules")
	if len(got) != 3 {
		t.Fatalf("len=%d", len(got))
	}
	for _, r := range got {
		if r.RuleKind != RuleKindControl {
			t.Fatalf("kind=%q", r.RuleKind)
		}
		if r.IsImmutable {
			t.Fatal("only -e 2 must set IsImmutable")
		}
	}
}

func TestParseCommentsAndBlanksIgnored(t *testing.T) {
	body := []byte(`# CIS rule
# Another comment

-w /etc/passwd -p wa -k identity
   # indented comment
`)
	got := Parse(body, "x.rules")
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
}

func TestParseContinuationLineMerged(t *testing.T) {
	body := []byte("-a always,exit \\\n  -F arch=b64 \\\n  -S openat -k continuation_test\n")
	got := Parse(body, "x.rules")
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Key != "continuation_test" {
		t.Fatalf("key=%q (continuation merge broken)", got[0].Key)
	}
	if !strings.Contains(got[0].RawLine, "-S openat") {
		t.Fatalf("raw_line=%q", got[0].RawLine)
	}
}

func TestParseHonoursMaxRulesCeiling(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < MaxRules+50; i++ {
		sb.WriteString("-w /etc/passwd -p wa -k identity\n")
	}
	got := Parse([]byte(sb.String()), "x.rules")
	if len(got) > MaxRules {
		t.Fatalf("got %d > MaxRules %d", len(got), MaxRules)
	}
}

// -- collector ------------------------------------------------------------

func TestFileCollectorWalksMainAndDropIns(t *testing.T) {
	tmp := t.TempDir()
	main := filepath.Join(tmp, "audit.rules")
	rulesDir := filepath.Join(tmp, "rules.d")
	must(t, os.MkdirAll(rulesDir, 0o755))
	mustWrite(t, main, "-e 2\n")
	mustWrite(t, filepath.Join(rulesDir, "10-base.rules"),
		"-w /etc/passwd -p wa -k identity\n")
	mustWrite(t, filepath.Join(rulesDir, "99-evade.rules"),
		"-a never,exit -F arch=b64 -S audit_control -k evade\n")
	mustWrite(t, filepath.Join(rulesDir, "ignored.bak"),
		"-w /tmp/evil -p w\n") // wrong suffix → must be skipped

	c := &fileCollector{
		mainFile: main,
		rulesDir: rulesDir,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 1 control + 1 file-watch + 1 syscall = 3.
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}

	var sawImmutable, sawSensitive, sawEvade bool
	for _, r := range got {
		if r.IsImmutable {
			sawImmutable = true
		}
		if r.IsSensitivePathWatch {
			sawSensitive = true
		}
		if r.IsSelfDestructive {
			sawEvade = true
		}
	}
	if !sawImmutable {
		t.Fatal("immutable flag must propagate from main file")
	}
	if !sawSensitive {
		t.Fatal("/etc/passwd watch must surface as sensitive")
	}
	if !sawEvade {
		t.Fatal("audit_control exclusion must surface as self-destructive")
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		mainFile: "/nope",
		rulesDir: "/nope-dir",
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

func TestSortRulesDeterministic(t *testing.T) {
	in := []Rule{
		{FilePath: "/etc/audit/rules.d/zzz.rules", LineNo: 1},
		{FilePath: "/etc/audit/audit.rules", LineNo: 5},
		{FilePath: "/etc/audit/audit.rules", LineNo: 2},
	}
	SortRules(in)
	if in[0].FilePath != "/etc/audit/audit.rules" || in[0].LineNo != 2 {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].FilePath != "/etc/audit/rules.d/zzz.rules" {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers -------------------------------------------------------------

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
