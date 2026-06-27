package kernelcmdline

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceProcCmdline), "proc-cmdline"},
		{string(SourceGrubDefault), "grub-default"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPinnedFindingCategoryStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(FindingKASLRDisabled), "kaslr-disabled"},
		{string(FindingCPUMitigationDisabled), "cpu-mitigation-disabled"},
		{string(FindingMACDisabled), "mac-disabled"},
		{string(FindingAuditDisabled), "audit-disabled"},
		{string(FindingModuleSigningOff), "module-signing-off"},
		{string(FindingInitOverride), "init-override"},
		{string(FindingLSMDisabled), "lsm-disabled"},
		{string(FindingUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("category drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("BOOT_IMAGE=/vmlinuz root=UUID=abc ro\n"))
	b := HashContents([]byte("BOOT_IMAGE=/vmlinuz root=UUID=abc ro\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestClassifyParameterCPUMitigations(t *testing.T) {
	for _, c := range []struct {
		key, value string
		wantCat    FindingCategory
		wantViol   bool
	}{
		{"mitigations", "off", FindingCPUMitigationDisabled, true},
		{"mitigations", "auto,nosmt", "", false},
		{"nopti", "", FindingCPUMitigationDisabled, true},
		{"nospectre_v2", "", FindingCPUMitigationDisabled, true},
		{"noibrs", "", FindingCPUMitigationDisabled, true},
		{"spectre_v2", "off", FindingCPUMitigationDisabled, true},
		{"spectre_v2", "on", "", false},
		{"l1tf", "off", FindingCPUMitigationDisabled, true},
		{"mds", "full,nosmt", FindingCPUMitigationDisabled, true},
		{"mds", "full", "", false},
	} {
		cat, _, viol := ClassifyParameter(c.key, c.value)
		if cat != c.wantCat {
			t.Fatalf("%s=%q: cat=%q, want %q", c.key, c.value, cat, c.wantCat)
		}
		if viol != c.wantViol {
			t.Fatalf("%s=%q: viol=%v, want %v", c.key, c.value, viol, c.wantViol)
		}
	}
}

func TestClassifyParameterMACAndAudit(t *testing.T) {
	cases := []struct {
		key, value string
		wantCat    FindingCategory
		wantViol   bool
	}{
		{"selinux", "0", FindingMACDisabled, true},
		{"selinux", "1", "", false},
		{"enforcing", "0", FindingMACDisabled, true},
		{"apparmor", "0", FindingMACDisabled, true},
		{"audit", "0", FindingAuditDisabled, true},
		{"audit", "1", "", false},
		{"module.sig_enforce", "0", FindingModuleSigningOff, true},
		{"module.sig_enforce", "1", "", false},
	}
	for _, c := range cases {
		cat, _, viol := ClassifyParameter(c.key, c.value)
		if cat != c.wantCat || viol != c.wantViol {
			t.Fatalf("%s=%q: cat=%q/viol=%v, want %q/%v",
				c.key, c.value, cat, viol, c.wantCat, c.wantViol)
		}
	}
}

func TestClassifyParameterInitOverride(t *testing.T) {
	cat, crit, viol := ClassifyParameter("init", "/bin/bash")
	if cat != FindingInitOverride || !crit || !viol {
		t.Fatalf("init=/bin/bash must flag init-override: cat=%q crit=%v viol=%v",
			cat, crit, viol)
	}
	// Empty value: not flagged.
	cat, _, viol = ClassifyParameter("init", "")
	if cat != "" || viol {
		t.Fatal("empty init= must NOT flag")
	}
}

func TestClassifyParameterLSMList(t *testing.T) {
	// Missing apparmor → violation.
	cat, _, viol := ClassifyParameter("lsm", "lockdown,yama,capability")
	if cat != FindingLSMDisabled || !viol {
		t.Fatalf("missing apparmor must flag lsm-disabled: cat=%q viol=%v", cat, viol)
	}
	// Complete set → no violation.
	cat, _, viol = ClassifyParameter("lsm",
		"lockdown,capability,landlock,yama,apparmor,bpf")
	if cat != "" || viol {
		t.Fatalf("complete LSM list must NOT flag: cat=%q viol=%v", cat, viol)
	}
}

func TestClassifyParameterKASLR(t *testing.T) {
	cat, _, viol := ClassifyParameter("nokaslr", "")
	if cat != FindingKASLRDisabled || !viol {
		t.Fatal("nokaslr must flag kaslr-disabled")
	}
	cat, _, viol = ClassifyParameter("kaslr", "")
	if cat != "" || viol {
		t.Fatal("kaslr (default-on) must NOT flag")
	}
}

func TestClassifyParameterUnknown(t *testing.T) {
	cat, crit, viol := ClassifyParameter("ro", "")
	if cat != "" || crit || viol {
		t.Fatalf("ro is neutral: cat=%q crit=%v viol=%v", cat, crit, viol)
	}
	cat, crit, viol = ClassifyParameter("root", "UUID=abc")
	if cat != "" || crit || viol {
		t.Fatalf("root= is neutral: cat=%q", cat)
	}
}

func TestAnnotateSecurity(t *testing.T) {
	p := Param{Key: "mitigations", Value: "off"}
	AnnotateSecurity(&p)
	if !p.IsSecurityCritical || !p.IsBaselineViolation {
		t.Fatalf("flags: %+v", p)
	}
	if p.FindingCategory != FindingCPUMitigationDisabled {
		t.Fatalf("category=%q", p.FindingCategory)
	}
}

// -- ParseProcCmdline --------------------------------------------------

func TestParseProcCmdlineTypical(t *testing.T) {
	body := []byte("BOOT_IMAGE=/vmlinuz-6.6.0 root=UUID=abc ro quiet splash mitigations=off audit=0\n")
	got := ParseProcCmdline(body, "/proc/cmdline")
	// 7 tokens.
	if len(got) != 7 {
		t.Fatalf("len=%d, want 7: %+v", len(got), got)
	}
	byKey := map[string]Param{}
	for _, p := range got {
		byKey[p.Key] = p
	}
	if !byKey["mitigations"].IsBaselineViolation {
		t.Fatal("mitigations=off must violate")
	}
	if !byKey["audit"].IsBaselineViolation {
		t.Fatal("audit=0 must violate")
	}
	if byKey["quiet"].HasValue || byKey["quiet"].IsSecurityCritical {
		t.Fatalf("quiet is a benign flag: %+v", byKey["quiet"])
	}
	if !byKey["BOOT_IMAGE"].HasValue {
		t.Fatal("BOOT_IMAGE must have value")
	}
	if byKey["BOOT_IMAGE"].Value != "/vmlinuz-6.6.0" {
		t.Fatalf("BOOT_IMAGE value=%q", byKey["BOOT_IMAGE"].Value)
	}
	for _, p := range got {
		if p.FileHash == "" {
			t.Fatalf("file_hash missing on %+v", p)
		}
	}
}

func TestParseProcCmdlineQuotedValue(t *testing.T) {
	body := []byte(`module.parm="a b c" root=UUID=x`)
	got := ParseProcCmdline(body, "/proc/cmdline")
	if len(got) != 2 {
		t.Fatalf("len=%d: %+v", len(got), got)
	}
	if got[0].Value != "a b c" {
		t.Fatalf("quoted value not preserved: %q", got[0].Value)
	}
}

func TestParseProcCmdlineEmpty(t *testing.T) {
	if got := ParseProcCmdline([]byte(""), "/proc/cmdline"); len(got) != 0 {
		t.Fatalf("empty input: %+v", got)
	}
	if got := ParseProcCmdline([]byte("\n\n"), "/proc/cmdline"); len(got) != 0 {
		t.Fatalf("whitespace-only input: %+v", got)
	}
}

func TestParseProcCmdlineInitOverride(t *testing.T) {
	body := []byte("ro init=/bin/bash root=UUID=x")
	got := ParseProcCmdline(body, "/proc/cmdline")
	var initParam Param
	for _, p := range got {
		if p.Key == "init" {
			initParam = p
		}
	}
	if !initParam.IsBaselineViolation {
		t.Fatal("init=/bin/bash must violate")
	}
	if initParam.FindingCategory != FindingInitOverride {
		t.Fatalf("category=%q", initParam.FindingCategory)
	}
}

// -- ParseGrubDefault --------------------------------------------------

func TestParseGrubDefaultTypical(t *testing.T) {
	body := []byte(`# /etc/default/grub
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash mitigations=off"
GRUB_CMDLINE_LINUX="audit=1"
GRUB_DISABLE_RECOVERY="true"
`)
	got := ParseGrubDefault(body, "/etc/default/grub")
	// 3 tokens from default + 1 from linux = 4.
	if len(got) != 4 {
		t.Fatalf("len=%d, want 4: %+v", len(got), got)
	}
	var mitigations, audit Param
	for _, p := range got {
		if p.Key == "mitigations" {
			mitigations = p
		}
		if p.Key == "audit" {
			audit = p
		}
	}
	if !mitigations.IsBaselineViolation {
		t.Fatal("mitigations=off in grub must violate")
	}
	if audit.IsBaselineViolation {
		t.Fatal("audit=1 in grub must NOT violate")
	}
	for _, p := range got {
		if p.Source != SourceGrubDefault {
			t.Fatalf("source=%q", p.Source)
		}
	}
}

func TestParseGrubDefaultIgnoresOtherKeys(t *testing.T) {
	body := []byte("GRUB_DEFAULT=0\nGRUB_TIMEOUT=5\n")
	if got := ParseGrubDefault(body, "x"); len(got) != 0 {
		t.Fatalf("non-CMDLINE keys must be ignored: %+v", got)
	}
}

// -- collector + drift annotation --------------------------------------

func TestFileCollectorDetectsDrift(t *testing.T) {
	tmp := t.TempDir()
	procCmd := filepath.Join(tmp, "cmdline")
	grub := filepath.Join(tmp, "grub")
	// Live cmdline says mitigations=off; grub says mitigations=auto.
	// That's drift: the bootloader was edited but update-grub wasn't
	// re-run, OR somebody booted with manual edits.
	mustWrite(t, procCmd, "BOOT_IMAGE=/vmlinuz mitigations=off audit=1\n")
	mustWrite(t, grub,
		"GRUB_CMDLINE_LINUX_DEFAULT=\"mitigations=auto audit=1\"\n")

	c := &fileCollector{
		procCmdline: procCmd,
		grubDefault: grub,
		readFile:    os.ReadFile,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var live, configured Param
	for _, p := range got {
		if p.Source == SourceProcCmdline && p.Key == "mitigations" {
			live = p
		}
		if p.Source == SourceGrubDefault && p.Key == "mitigations" {
			configured = p
		}
	}
	if !live.IsDriftFromDisk {
		t.Fatalf("live mitigations=off vs configured mitigations=auto must flag drift; got %+v", live)
	}
	if configured.IsDriftFromDisk {
		t.Fatal("configured row must NOT flag drift (only proc-cmdline rows do)")
	}
}

func TestFileCollectorDoesNotFlagDriftWhenGrubMissing(t *testing.T) {
	tmp := t.TempDir()
	procCmd := filepath.Join(tmp, "cmdline")
	mustWrite(t, procCmd, "mitigations=off\n")

	c := &fileCollector{
		procCmdline: procCmd,
		grubDefault: "/nope",
		readFile: func(p string) ([]byte, error) {
			if p == procCmd {
				return os.ReadFile(p)
			}
			return nil, errors.New("missing")
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got {
		if p.IsDriftFromDisk {
			t.Fatalf("missing grub must NOT trigger drift: %+v", p)
		}
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		procCmdline: "/nope",
		grubDefault: "/nope",
		readFile:    os.ReadFile,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortParamsDeterministic(t *testing.T) {
	in := []Param{
		{Source: SourceGrubDefault, Key: "zzz"},
		{Source: SourceProcCmdline, Key: "audit", Value: "1"},
		{Source: SourceProcCmdline, Key: "audit", Value: "0"},
	}
	SortParams(in)
	if in[0].Source != SourceGrubDefault || in[0].Key != "zzz" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].Value != "1" {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers ----------------------------------------------------------

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
