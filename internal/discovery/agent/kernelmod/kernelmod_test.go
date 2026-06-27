package kernelmod

import (
	"strings"
	"testing"
)

// TestPinnedSourceStrings prevents drift between the Go const values
// and the SQLite CHECK constraint on host_kernel_modules.source.
func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct {
		got, want string
	}{
		{string(SourceLinuxProcModules), "linux-proc-modules"},
		{string(SourceLinuxSysfs), "linux-sysfs"},
		{string(SourceMacOSKextstat), "macos-kextstat"},
		{string(SourceWindowsSCM), "windows-scm"},
		{string(SourceFreeBSDKldstat), "freebsd-kldstat"},
		{string(SourceOpenBSDModstat), "openbsd-modstat"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestPinnedStateStrings(t *testing.T) {
	pairs := []struct {
		got, want string
	}{
		{string(StateLive), "live"},
		{string(StateLoading), "loading"},
		{string(StateUnloading), "unloading"},
		{string(StateUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("state enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestEncodeStringListEmpty(t *testing.T) {
	if got := EncodeStringList(nil); got != "[]" {
		t.Fatalf("nil = %q", got)
	}
	if got := EncodeStringList([]string{"a", "b"}); got != `["a","b"]` {
		t.Fatalf("two-elem = %q", got)
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("ELF...\x00modinfo..."))
	b := HashContents([]byte("ELF...\x00modinfo..."))
	if a != b {
		t.Fatal("not deterministic")
	}
	if len(a) != 64 {
		t.Fatalf("not sha256: %d chars", len(a))
	}
}

func TestIsTaintingFlag(t *testing.T) {
	// Letters that DO affect kernel integrity.
	for _, c := range []byte{'E', 'F', 'O', 'R', 'U'} {
		if !IsTaintingFlag(c) {
			t.Fatalf("%c must be tainting", c)
		}
	}
	// Letters that DO NOT affect kernel integrity (license-only).
	for _, c := range []byte{'P', 'G', 'W', ' ', 0} {
		if IsTaintingFlag(c) {
			t.Fatalf("%c must NOT be tainting", c)
		}
	}
}

func TestHasTaintingFlag(t *testing.T) {
	cases := map[string]bool{
		"":      false,
		"P":     false, // proprietary only
		"O":     true,  // out-of-tree
		"PE":    true,  // unsigned wins
		"POE":   true,
		"GPL":   false, // G + P + L (L is not in our set)
		"FORCE": true,  // F is tainting
	}
	for in, want := range cases {
		if got := HasTaintingFlag(in); got != want {
			t.Fatalf("HasTaintingFlag(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsInTreePathAndIsOutOfTreePath(t *testing.T) {
	in := []string{
		"/lib/modules/6.6.0/kernel/drivers/net/e1000.ko",
		"/usr/lib/modules/6.6.0/extra/zfs.ko",
		"/run/booted-system/kernel-modules/lib/modules/6.1/kernel/x.ko",
		"", // empty path = unknown but assumed in-tree
	}
	for _, p := range in {
		if !IsInTreePath(p) {
			t.Fatalf("%q must be in-tree", p)
		}
		if IsOutOfTreePath(p) && p != "" {
			t.Fatalf("%q must NOT be out-of-tree", p)
		}
	}
	out := []string{
		"/tmp/rootkit.ko",
		"/var/lib/attacker/persist.ko",
		"/opt/extra/custom.ko",
		"/home/user/myhack.ko",
	}
	for _, p := range out {
		if IsInTreePath(p) {
			t.Fatalf("%q must NOT be in-tree", p)
		}
		if !IsOutOfTreePath(p) {
			t.Fatalf("%q must be out-of-tree", p)
		}
	}
}

// -- parser ----------------------------------------------------------

func TestParseProcModulesGoldenLine(t *testing.T) {
	// loop's load_address is "(no instrumentation)" verbatim on
	// CONFIG_KALLSYMS=n kernels; the address column simply isn't a
	// hex value there.
	body := []byte(`zfs 4194304 12 zcommon,znvpair,zavl,icp,zlua,zunicode, Live 0xffffffffc1234567 (POE)
xfs 1605632 1 - Live 0xffffffffc1100000
nf_conntrack 196608 4 nf_nat,nf_log_ipv4, Live 0xffffffffc0500000
loop 32768 0 - Live (no instrumentation)
`)
	got := ParseProcModules(body)
	if len(got) != 4 {
		t.Fatalf("len=%d, want 4: %+v", len(got), got)
	}

	zfs := got[0]
	if zfs.Name != "zfs" {
		t.Fatalf("name=%q", zfs.Name)
	}
	if zfs.SizeBytes != 4194304 {
		t.Fatalf("size=%d", zfs.SizeBytes)
	}
	if zfs.Refcount != 12 {
		t.Fatalf("refcount=%d", zfs.Refcount)
	}
	if len(zfs.UsedBy) != 6 {
		t.Fatalf("used_by=%v (want 6)", zfs.UsedBy)
	}
	if zfs.State != StateLive {
		t.Fatalf("state=%q", zfs.State)
	}
	if zfs.LoadAddress != "0xffffffffc1234567" {
		t.Fatalf("load_address=%q", zfs.LoadAddress)
	}
	if zfs.Taints != "POE" {
		t.Fatalf("taints=%q", zfs.Taints)
	}
	if !zfs.IsTainting {
		t.Fatal("POE contains O+E — must be tainting")
	}

	xfs := got[1]
	if xfs.UsedBy != nil {
		t.Fatalf("xfs has refcount=1 but no used_by; got %v", xfs.UsedBy)
	}
	if xfs.Taints != "" {
		t.Fatalf("xfs.taints=%q (want empty)", xfs.Taints)
	}
	if xfs.IsTainting {
		t.Fatal("xfs has no taint flags")
	}

	loop := got[3]
	if loop.LoadAddress != "" {
		// "(no instrumentation)" kernels don't expose the address.
		t.Fatalf("loop.load_address=%q (CONFIG_KALLSYMS=n kernel — expected empty)",
			loop.LoadAddress)
	}
}

func TestParseProcModulesMalformedLineSkipped(t *testing.T) {
	body := []byte("only_two_fields here\nzfs 4194304 12 - Live 0x0\n")
	got := ParseProcModules(body)
	if len(got) != 1 || got[0].Name != "zfs" {
		t.Fatalf("malformed line should be skipped: %+v", got)
	}
}

func TestParseProcModulesHonoursMaxModules(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < MaxModules+50; i++ {
		sb.WriteString("mod_x 1024 0 - Live 0x0\n")
	}
	got := ParseProcModules([]byte(sb.String()))
	if len(got) > MaxModules {
		t.Fatalf("got %d > MaxModules %d", len(got), MaxModules)
	}
}

func TestNormalizeState(t *testing.T) {
	if normalizeState("Live") != StateLive {
		t.Fatal("Live")
	}
	if normalizeState("LOADING") != StateLoading {
		t.Fatal("LOADING")
	}
	if normalizeState("unloading") != StateUnloading {
		t.Fatal("unloading")
	}
	if normalizeState("ghost") != StateUnknown {
		t.Fatal("unknown")
	}
}

// -- MergeSysfs ------------------------------------------------------

func TestMergeSysfsPopulatesAndFlags(t *testing.T) {
	mods := []Module{
		{Name: "zfs", Source: SourceLinuxProcModules},
		{Name: "xfs", Source: SourceLinuxProcModules},
		{Name: "rootkit", Source: SourceLinuxProcModules},
	}
	sysfs := map[string]SysfsExtras{
		"zfs": {
			FilePath:         "/lib/modules/6.6.0/extra/zfs.ko",
			Version:          "2.2.6-1",
			Signer:           "CN=ZFSOnLinux Build,O=OpenZFS",
			SignatureChecked: true,
			Taints:           "POE",
		},
		"xfs": {
			FilePath:         "/lib/modules/6.6.0/kernel/fs/xfs/xfs.ko",
			SignatureChecked: true,
		},
		"rootkit": {
			FilePath:         "/tmp/.cache/.persist.ko",
			SignatureChecked: true,
		},
	}
	got := MergeSysfs(mods, sysfs)

	if got[0].Version != "2.2.6-1" {
		t.Fatalf("zfs.version=%q", got[0].Version)
	}
	if got[0].Signer == "" || got[0].IsUnsigned {
		t.Fatalf("zfs signed → IsUnsigned must be false; got signer=%q is_unsigned=%v",
			got[0].Signer, got[0].IsUnsigned)
	}
	if !got[0].IsTainting {
		t.Fatal("zfs POE → must remain tainting after merge")
	}
	if got[0].IsOutOfTree {
		t.Fatal("/lib/modules/... is in-tree even though path is under /extra/")
	}

	if got[1].Signer != "" || !got[1].IsUnsigned {
		t.Fatalf("xfs SignatureChecked + empty Signer → IsUnsigned must be true; got %+v",
			got[1])
	}

	if !got[2].IsOutOfTree {
		t.Fatalf("rootkit at /tmp must flag out-of-tree (T1547.006): %+v", got[2])
	}
	if !got[2].IsUnsigned {
		t.Fatal("rootkit with no signer → IsUnsigned")
	}
}

func TestMergeSysfsUnknownNameIgnored(t *testing.T) {
	mods := []Module{{Name: "zfs", Source: SourceLinuxProcModules}}
	sysfs := map[string]SysfsExtras{"different_module": {FilePath: "/x"}}
	got := MergeSysfs(mods, sysfs)
	if got[0].FilePath != "" {
		t.Fatalf("unrelated sysfs entry must not bleed: %+v", got[0])
	}
}

// -- SortModules -----------------------------------------------------

func TestSortModulesDeterministic(t *testing.T) {
	in := []Module{
		{Name: "zfs", Source: SourceLinuxProcModules},
		{Name: "abc", Source: SourceLinuxProcModules},
		{Name: "xfs", Source: SourceMacOSKextstat},
	}
	SortModules(in)
	if in[0].Name != "abc" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].Source != SourceMacOSKextstat {
		t.Fatalf("last=%+v", in[2])
	}
}
