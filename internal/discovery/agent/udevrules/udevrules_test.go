package udevrules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedScopeStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ScopeAdmin), "admin"},
		{string(ScopeVendor), "vendor"},
		{string(ScopeRuntime), "runtime"},
		{string(ScopeUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("scope drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{
		`SUBSYSTEM=="usb"`,
		`ACTION=="add"`,
	}); got != `["SUBSYSTEM==\"usb\"","ACTION==\"add\""]` {
		t.Fatalf("got %q", got)
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte(`SUBSYSTEM=="usb", ACTION=="add"`))
	b := HashContents([]byte(`SUBSYSTEM=="usb", ACTION=="add"`))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsCriticalSubsystem(t *testing.T) {
	for _, s := range []string{
		"usb", "block", "net", "input",
		"tty", "bluetooth", "sound",
	} {
		if !IsCriticalSubsystem(s) {
			t.Fatalf("%q must be critical", s)
		}
	}
	for _, s := range []string{"power_supply", "thermal", "", "leds"} {
		if IsCriticalSubsystem(s) {
			t.Fatalf("%q must NOT be critical", s)
		}
	}
}

func TestIsDangerousRunPath(t *testing.T) {
	for _, cmd := range []string{
		"/tmp/x",
		"/var/tmp/something",
		"/home/attacker/payload",
		"/dev/shm/payload",
		"/run/user/1000/x",
		"/bin/sh -c '/tmp/evil'",
		"/usr/bin/env python /home/alice/x.py",
	} {
		if !IsDangerousRunPath(cmd) {
			t.Fatalf("%q must flag dangerous", cmd)
		}
	}
	for _, cmd := range []string{
		"/usr/local/bin/x",
		"/usr/sbin/y",
		"/bin/sh -c 'logger udev fired'",
		"",
	} {
		if IsDangerousRunPath(cmd) {
			t.Fatalf("%q must NOT flag dangerous", cmd)
		}
	}
}

func TestIsWorldWritableMode(t *testing.T) {
	// World-write set.
	for _, m := range []string{"0666", "666", "0226", "0006", "0777"} {
		if !IsWorldWritableMode(m) {
			t.Fatalf("%q must flag world-writable", m)
		}
	}
	// Not world-writable.
	for _, m := range []string{"0660", "0640", "0600", "0444", "0", ""} {
		if IsWorldWritableMode(m) {
			t.Fatalf("%q must NOT flag world-writable", m)
		}
	}
}

func TestAnnotateSecurityCriticalAndDangerous(t *testing.T) {
	r := Rule{
		Subsystem:  "usb",
		HasRun:     true,
		RunCommand: "/tmp/evil-payload",
		ModeValue:  "0666",
	}
	AnnotateSecurity(&r)
	if !r.IsCriticalSubsystem {
		t.Fatal("usb subsystem must flag critical")
	}
	if !r.IsDangerousRun {
		t.Fatal("/tmp RUN+= must flag dangerous")
	}
	if !r.IsWorldWritableMode {
		t.Fatal("0666 must flag world-writable")
	}
}

func TestAnnotateSecurityRunInSafePath(t *testing.T) {
	r := Rule{
		Subsystem:  "block",
		HasRun:     true,
		RunCommand: "/usr/local/bin/probe",
		ModeValue:  "0660",
	}
	AnnotateSecurity(&r)
	if !r.IsCriticalSubsystem {
		t.Fatal("block must flag critical")
	}
	if r.IsDangerousRun {
		t.Fatal("/usr/local/bin must NOT flag dangerous")
	}
	if r.IsWorldWritableMode {
		t.Fatal("0660 is safe")
	}
}

// -- Parse end-to-end ------------------------------------------------

func TestParseTypicalUSBRule(t *testing.T) {
	body := []byte(`# Sample USB rule
SUBSYSTEM=="usb", ACTION=="add", ATTR{idVendor}=="0bda", \
    ATTR{idProduct}=="8153", RUN+="/usr/local/bin/usb-add.sh"
`)
	got := Parse(body, "/etc/udev/rules.d/99-usb.rules", ScopeAdmin)
	if len(got) != 1 {
		t.Fatalf("len=%d, want 1 (continuation merged): %+v", len(got), got)
	}
	r := got[0]
	if r.Subsystem != "usb" {
		t.Fatalf("subsystem=%q", r.Subsystem)
	}
	if r.Action != "add" {
		t.Fatalf("action=%q", r.Action)
	}
	if !r.HasRun {
		t.Fatal("HasRun must be true")
	}
	if r.RunCommand != "/usr/local/bin/usb-add.sh" {
		t.Fatalf("run_command=%q", r.RunCommand)
	}
	if !r.IsCriticalSubsystem {
		t.Fatal("usb subsystem must flag critical")
	}
	if r.IsDangerousRun {
		t.Fatal("/usr/local/bin is safe")
	}
	if r.FileHash == "" {
		t.Fatal("file_hash missing")
	}
}

func TestParseRuleWithDangerousRun(t *testing.T) {
	body := []byte(`SUBSYSTEM=="usb", ACTION=="add", RUN+="/tmp/attacker.sh"`)
	got := Parse(body, "x.rules", ScopeAdmin)
	if len(got) != 1 {
		t.Fatal("len")
	}
	if !got[0].IsDangerousRun {
		t.Fatal("RUN to /tmp must flag dangerous")
	}
}

func TestParseRuleWithWorldWritableMode(t *testing.T) {
	body := []byte(`SUBSYSTEM=="block", KERNEL=="sd*", MODE="0666", GROUP="disk"`)
	got := Parse(body, "x.rules", ScopeAdmin)
	if len(got) != 1 {
		t.Fatal("len")
	}
	r := got[0]
	if r.ModeValue != "0666" {
		t.Fatalf("mode=%q", r.ModeValue)
	}
	if r.GroupName != "disk" {
		t.Fatalf("group=%q", r.GroupName)
	}
	if !r.IsWorldWritableMode {
		t.Fatal("0666 must flag world-writable")
	}
	if !r.IsCriticalSubsystem {
		t.Fatal("block must flag critical")
	}
}

func TestParseRuleAttrAndEnvKeys(t *testing.T) {
	body := []byte(`SUBSYSTEM=="usb", ATTR{idVendor}=="0bda", ENV{ID_FS_LABEL}=="MYUSB", SYMLINK+="my-usb"`)
	got := Parse(body, "x.rules", ScopeAdmin)
	if len(got) != 1 {
		t.Fatal("len")
	}
	r := got[0]
	// Match keys: SUBSYSTEM + ATTR + ENV = 3.
	if len(r.MatchKeys) != 3 {
		t.Fatalf("match_keys=%v (want 3)", r.MatchKeys)
	}
	// Action keys: SYMLINK+= = 1.
	if len(r.ActionKeys) != 1 {
		t.Fatalf("action_keys=%v (want 1)", r.ActionKeys)
	}
	if !strings.Contains(r.MatchKeys[1], "ATTR{idVendor}") {
		t.Fatalf("ATTR key not preserved: %v", r.MatchKeys)
	}
}

func TestParseRuleImportProgram(t *testing.T) {
	body := []byte(`SUBSYSTEM=="block", IMPORT{program}="/usr/sbin/blkid"`)
	got := Parse(body, "x.rules", ScopeAdmin)
	if len(got) != 1 {
		t.Fatal("len")
	}
	if !got[0].HasImport {
		t.Fatal("IMPORT{program}= must flag HasImport")
	}
}

func TestParseRuleCommentAndBlankSkipped(t *testing.T) {
	body := []byte(`# comment 1

# comment 2
SUBSYSTEM=="usb", ACTION=="add", RUN+="/usr/local/bin/x"
`)
	got := Parse(body, "x.rules", ScopeAdmin)
	if len(got) != 1 {
		t.Fatalf("len=%d (comments/blanks must be skipped)", len(got))
	}
}

func TestParseRuleQuotedCommaNotASplitter(t *testing.T) {
	body := []byte(`SUBSYSTEM=="usb", ACTION=="add", RUN+="/bin/sh -c 'echo a,b'"`)
	got := Parse(body, "x.rules", ScopeAdmin)
	if len(got) != 1 {
		t.Fatalf("len=%d (comma inside quoted RUN must not split)", len(got))
	}
	if !strings.Contains(got[0].RunCommand, "echo a,b") {
		t.Fatalf("run_command lost quoted comma: %q", got[0].RunCommand)
	}
}

func TestParseRuleMaxCeiling(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < MaxRules+50; i++ {
		sb.WriteString(`SUBSYSTEM=="net", ACTION=="add"` + "\n")
	}
	got := Parse([]byte(sb.String()), "x.rules", ScopeAdmin)
	if len(got) > MaxRules {
		t.Fatalf("got %d > MaxRules %d", len(got), MaxRules)
	}
}

func TestSplitKeyOpValueOperatorPrecedence(t *testing.T) {
	// `==` must not be split as `=`.
	k, op, v, ok := splitKeyOpValue(`KERNEL=="sd*"`)
	if !ok {
		t.Fatal("split failed")
	}
	if op != "==" || k != "KERNEL" || v != "sd*" {
		t.Fatalf("k=%q op=%q v=%q", k, op, v)
	}
	// `+=` must not be split as `=`.
	k, op, v, ok = splitKeyOpValue(`RUN+="/usr/local/bin/x"`)
	if !ok {
		t.Fatal("split failed on +=")
	}
	if op != "+=" || k != "RUN" || v != "/usr/local/bin/x" {
		t.Fatalf("k=%q op=%q v=%q", k, op, v)
	}
	// Brace attribute keys.
	k, op, _, _ = splitKeyOpValue(`ATTR{idVendor}=="0bda"`)
	if k != "ATTR{idVendor}" || op != "==" {
		t.Fatalf("k=%q op=%q (brace-attr must survive)", k, op)
	}
}

// -- collector end-to-end --------------------------------------------

func TestFileCollectorWalksAdminRuntimeVendor(t *testing.T) {
	tmp := t.TempDir()
	admin := filepath.Join(tmp, "admin")
	runtime := filepath.Join(tmp, "runtime")
	vendor := filepath.Join(tmp, "vendor")
	for _, d := range []string{admin, runtime, vendor} {
		must(t, os.MkdirAll(d, 0o755))
	}
	mustWrite(t, filepath.Join(admin, "99-local.rules"),
		`SUBSYSTEM=="usb", ACTION=="add", RUN+="/tmp/evil"`)
	mustWrite(t, filepath.Join(runtime, "00-rt.rules"),
		`SUBSYSTEM=="net", KERNEL=="wlan*", MODE="0660"`)
	mustWrite(t, filepath.Join(vendor, "70-pci.rules"),
		`SUBSYSTEM=="block", KERNEL=="sd*", MODE="0666"`)
	mustWrite(t, filepath.Join(admin, "ignored.bak"),
		`SUBSYSTEM=="usb", RUN+="/should/be/skipped"`)

	c := &fileCollector{
		adminDir:   admin,
		runtimeDir: runtime,
		vendorDirs: []string{vendor},
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 1 admin + 1 runtime + 1 vendor = 3 (.bak skipped).
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}
	// Verify the admin /tmp RUN+= surfaced as dangerous.
	var sawDangerous, sawWorldWrite bool
	for _, r := range got {
		if r.Scope == ScopeAdmin && r.IsDangerousRun {
			sawDangerous = true
		}
		if r.Scope == ScopeVendor && r.IsWorldWritableMode {
			sawWorldWrite = true
		}
	}
	if !sawDangerous {
		t.Fatal("dangerous run flag did not propagate")
	}
	if !sawWorldWrite {
		t.Fatal("world-writable flag did not propagate")
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		adminDir:   "/nope",
		runtimeDir: "/nope",
		vendorDirs: []string{"/nope", "/also-nope"},
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

func TestSortRulesDeterministic(t *testing.T) {
	in := []Rule{
		{FilePath: "/etc/udev/rules.d/zzz.rules", LineNo: 1},
		{FilePath: "/etc/udev/rules.d/aaa.rules", LineNo: 5},
		{FilePath: "/etc/udev/rules.d/aaa.rules", LineNo: 2},
	}
	SortRules(in)
	if in[0].FilePath != "/etc/udev/rules.d/aaa.rules" || in[0].LineNo != 2 {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].FilePath != "/etc/udev/rules.d/zzz.rules" {
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
