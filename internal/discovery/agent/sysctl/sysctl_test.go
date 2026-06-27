package sysctl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceEtcSysctlConf), "etc-sysctl-conf"},
		{string(SourceEtcSysctlD), "etc-sysctl-d"},
		{string(SourceUsrLibSysctlD), "usr-lib-sysctl-d"},
		{string(SourceRunSysctlD), "run-sysctl-d"},
		{string(SourceProcSys), "proc-sys"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("kernel.kptr_restrict = 2\n"))
	b := HashContents([]byte("kernel.kptr_restrict = 2\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestNormalizeKey(t *testing.T) {
	cases := map[string]string{
		"kernel.kptr_restrict":        "kernel.kptr_restrict",
		"kernel/kptr_restrict":        "kernel.kptr_restrict",
		" kernel/yama/ptrace_scope ":  "kernel.yama.ptrace_scope",
		"net/ipv4/conf/all/rp_filter": "net.ipv4.conf.all.rp_filter",
	}
	for in, want := range cases {
		if got := NormalizeKey(in); got != want {
			t.Fatalf("NormalizeKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSecurityBaselineCoverage(t *testing.T) {
	must := []string{
		"kernel.dmesg_restrict",
		"kernel.kptr_restrict",
		"kernel.yama.ptrace_scope",
		"fs.protected_symlinks",
		"fs.protected_hardlinks",
		"net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.all.accept_redirects",
		"net.ipv4.tcp_syncookies",
		"net.ipv6.conf.all.accept_redirects",
	}
	base := SecurityBaseline()
	for _, k := range must {
		if _, ok := base[k]; !ok {
			t.Fatalf("baseline missing critical key %q", k)
		}
	}
}

func TestIsBaselineViolation(t *testing.T) {
	// Baseline expects kernel.kptr_restrict=2; anything else is a violation.
	if !IsBaselineViolation("kernel.kptr_restrict", "0") {
		t.Fatal("kptr_restrict=0 must violate")
	}
	if !IsBaselineViolation("kernel.kptr_restrict", "1") {
		t.Fatal("kptr_restrict=1 must violate (baseline expects 2)")
	}
	if IsBaselineViolation("kernel.kptr_restrict", "2") {
		t.Fatal("kptr_restrict=2 must NOT violate")
	}
	// Non-baseline keys never violate.
	if IsBaselineViolation("vm.nr_hugepages", "1024") {
		t.Fatal("non-baseline key must NOT violate")
	}
}

func TestAnnotateSecurityFlagsCriticalAndViolation(t *testing.T) {
	s := Setting{Key: "kernel.kptr_restrict", CurrentValue: "0"}
	AnnotateSecurity(&s)
	if !s.IsSecurityCritical {
		t.Fatal("kptr_restrict must be critical")
	}
	if !s.IsBaselineViolation {
		t.Fatal("0 must violate baseline of 2")
	}
	if s.ExpectedValue != "2" {
		t.Fatalf("expected_value=%q", s.ExpectedValue)
	}

	// Non-critical key.
	s = Setting{Key: "vm.swappiness", CurrentValue: "10"}
	AnnotateSecurity(&s)
	if s.IsSecurityCritical || s.IsBaselineViolation {
		t.Fatalf("non-critical wrong flags: %+v", s)
	}
	if s.ExpectedValue != "" {
		t.Fatalf("expected_value should be empty for non-baseline: %q",
			s.ExpectedValue)
	}

	// Slash form normalises to dot form.
	s = Setting{Key: "kernel/kptr_restrict", CurrentValue: "2"}
	AnnotateSecurity(&s)
	if s.Key != "kernel.kptr_restrict" {
		t.Fatalf("normalised key=%q", s.Key)
	}
	if s.IsBaselineViolation {
		t.Fatal("2 must NOT violate")
	}
}

// -- parser ---------------------------------------------------------------

func TestParseTypical(t *testing.T) {
	body := []byte(`# CIS baseline
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_symlinks=1
vm.swappiness = 10

; semi comment
-net.ipv4.conf.all.rp_filter = 1
`)
	got := Parse(body, SourceEtcSysctlConf, "/etc/sysctl.conf")
	if len(got) != 5 {
		t.Fatalf("len=%d, want 5: %+v", len(got), got)
	}

	keys := map[string]Setting{}
	for _, s := range got {
		keys[s.Key] = s
	}
	if !keys["kernel.kptr_restrict"].IsSecurityCritical {
		t.Fatal("kptr_restrict must be critical")
	}
	if keys["kernel.kptr_restrict"].IsBaselineViolation {
		t.Fatal("kptr=2 must NOT violate")
	}
	if keys["vm.swappiness"].IsSecurityCritical {
		t.Fatal("vm.swappiness must NOT be critical")
	}
	// The "-" prefix line must still record as net.ipv4.conf.all.rp_filter=1.
	if keys["net.ipv4.conf.all.rp_filter"].CurrentValue != "1" {
		t.Fatalf("rp_filter value=%q",
			keys["net.ipv4.conf.all.rp_filter"].CurrentValue)
	}
	for _, s := range got {
		if s.FileHash == "" {
			t.Fatalf("file_hash missing on %+v", s)
		}
	}
}

func TestParseFlagsViolation(t *testing.T) {
	body := []byte("kernel.kptr_restrict = 0\n")
	got := Parse(body, SourceEtcSysctlConf, "/etc/sysctl.conf")
	if len(got) != 1 {
		t.Fatal("len")
	}
	if !got[0].IsBaselineViolation {
		t.Fatal("kptr=0 must flag IsBaselineViolation")
	}
}

func TestParseHandlesCRLF(t *testing.T) {
	body := []byte("kernel.dmesg_restrict = 1\r\nfs.suid_dumpable = 0\r\n")
	got := Parse(body, SourceEtcSysctlConf, "/etc/sysctl.conf")
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
	if strings.Contains(got[0].CurrentValue, "\r") {
		t.Fatalf("CR leaked into value: %q", got[0].CurrentValue)
	}
}

func TestParseMaxSettingsCeiling(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < MaxSettings+50; i++ {
		sb.WriteString("vm.foo = 1\n")
	}
	got := Parse([]byte(sb.String()), SourceEtcSysctlConf, "x")
	if len(got) > MaxSettings {
		t.Fatalf("got %d > MaxSettings %d", len(got), MaxSettings)
	}
}

// -- collector end-to-end -------------------------------------------------

func TestFileCollectorWalksAllSources(t *testing.T) {
	tmp := t.TempDir()
	sysctlConf := filepath.Join(tmp, "sysctl.conf")
	etcD := filepath.Join(tmp, "etc-sysctl.d")
	libD := filepath.Join(tmp, "lib-sysctl.d")
	runD := filepath.Join(tmp, "run-sysctl.d")
	for _, d := range []string{etcD, libD, runD} {
		must(t, os.MkdirAll(d, 0o755))
	}

	mustWrite(t, sysctlConf, "kernel.kptr_restrict = 2\n")
	mustWrite(t, filepath.Join(etcD, "10-cis.conf"),
		"kernel.dmesg_restrict = 1\nfs.suid_dumpable = 0\n")
	mustWrite(t, filepath.Join(libD, "50-default.conf"),
		"net.ipv4.tcp_syncookies = 1\n")
	mustWrite(t, filepath.Join(runD, "99-runtime.conf"),
		"kernel.unprivileged_bpf_disabled = 1\n")
	// Wrong suffix - must be skipped.
	mustWrite(t, filepath.Join(etcD, "00-ignore.bak"),
		"kernel.dmesg_restrict = 0\n")

	c := &fileCollector{
		sysctlConf: sysctlConf,
		dropInDirs: []dropInSource{
			{etcD, SourceEtcSysctlD},
			{libD, SourceUsrLibSysctlD},
			{runD, SourceRunSysctlD},
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 1 conf + 2 etc-d + 1 lib-d + 1 run-d = 5.
	if len(got) != 5 {
		t.Fatalf("want 5, got %d: %+v", len(got), got)
	}
	for _, s := range got {
		if s.IsBaselineViolation {
			t.Fatalf("none should violate (all set to baseline): %+v", s)
		}
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		sysctlConf: "/nope",
		dropInDirs: []dropInSource{{"/nope-dir", SourceEtcSysctlD}},
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

func TestEnrichWithProcSysFlagsDrift(t *testing.T) {
	// Disk says kptr_restrict=2 but /proc says 0 (attacker wrote
	// directly to /proc/sys). Drift must flag.
	tmp := t.TempDir()
	confFile := filepath.Join(tmp, "sysctl.conf")
	mustWrite(t, confFile, "kernel.kptr_restrict = 2\n")

	c := &fileCollector{
		sysctlConf:    confFile,
		dropInDirs:    nil,
		procSys:       "/fake/proc/sys",
		enableProcSys: true,
		readDir:       os.ReadDir,
		readFile: func(p string) ([]byte, error) {
			if p == confFile {
				return os.ReadFile(p)
			}
			// fake /proc/sys/<key>
			if strings.HasSuffix(p, "kernel/kptr_restrict") {
				return []byte("0\n"), nil
			}
			return nil, errors.New("not exposed")
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// At minimum: the configured kptr_restrict row must be marked drift.
	var kptr Setting
	for _, s := range got {
		if s.Key == "kernel.kptr_restrict" && s.Source == SourceEtcSysctlConf {
			kptr = s
		}
	}
	if !kptr.IsDriftFromDisk {
		t.Fatalf("kptr_restrict configured=2 vs /proc=0 must flag drift; got %+v", kptr)
	}
}

func TestEnrichWithProcSysFillsBaselineGaps(t *testing.T) {
	// Disk says nothing about fs.protected_symlinks but /proc says 1.
	// The enricher should emit a proc-sys-sourced row so the baseline
	// audit has something to assert against.
	tmp := t.TempDir()
	confFile := filepath.Join(tmp, "sysctl.conf")
	mustWrite(t, confFile, "kernel.kptr_restrict = 2\n")

	exposed := map[string]string{
		"fs/protected_symlinks":       "1",
		"kernel/kptr_restrict":        "2",
		"kernel/dmesg_restrict":       "0", // violation
		"net/ipv4/conf/all/rp_filter": "1",
	}
	c := &fileCollector{
		sysctlConf:    confFile,
		procSys:       "/fake/proc/sys",
		enableProcSys: true,
		readDir:       os.ReadDir,
		readFile: func(p string) ([]byte, error) {
			if p == confFile {
				return os.ReadFile(p)
			}
			for suffix, value := range exposed {
				if strings.HasSuffix(p, suffix) {
					return []byte(value + "\n"), nil
				}
			}
			return nil, errors.New("not exposed")
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// We need to find proc-sys-sourced rows for the baseline keys.
	var (
		dmesgDrift  bool
		symlinkProc bool
	)
	for _, s := range got {
		if s.Source != SourceProcSys {
			continue
		}
		if s.Key == "kernel.dmesg_restrict" {
			dmesgDrift = s.IsBaselineViolation
		}
		if s.Key == "fs.protected_symlinks" {
			symlinkProc = !s.IsBaselineViolation
		}
	}
	if !dmesgDrift {
		t.Fatal("/proc/sys says dmesg_restrict=0 (violation); must be flagged")
	}
	if !symlinkProc {
		t.Fatal("/proc/sys says protected_symlinks=1; must NOT violate")
	}
}

func TestSortSettingsDeterministic(t *testing.T) {
	in := []Setting{
		{Source: SourceEtcSysctlD, Key: "zzz"},
		{Source: SourceEtcSysctlConf, Key: "vm.swappiness"},
		{Source: SourceEtcSysctlConf, Key: "kernel.foo"},
	}
	SortSettings(in)
	if in[0].Source != SourceEtcSysctlConf || in[0].Key != "kernel.foo" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].Source != SourceEtcSysctlD {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers --------------------------------------------------------------

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
