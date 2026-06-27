package macpolicies

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedSubsystemStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SubsystemSELinux), "selinux"},
		{string(SubsystemAppArmor), "apparmor"},
		{string(SubsystemTomoyo), "tomoyo"},
		{string(SubsystemSmack), "smack"},
		{string(SubsystemYama), "yama"},
		{string(SubsystemLandlock), "landlock"},
		{string(SubsystemBPFLSM), "bpf-lsm"},
		{string(SubsystemLSMList), "lsm-list"},
		{string(SubsystemUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("subsystem drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestPinnedModeStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ModeEnforcing), "enforcing"},
		{string(ModePermissive), "permissive"},
		{string(ModeDisabled), "disabled"},
		{string(ModeComplain), "complain"},
		{string(ModeKill), "kill"},
		{string(ModeEnabled), "enabled"},
		{string(ModeAudit), "audit"},
		{string(ModeUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("mode drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("SELINUX=enforcing\n"))
	b := HashContents([]byte("SELINUX=enforcing\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestNormalizeSELinuxMode(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Mode
	}{
		{"enforcing", ModeEnforcing},
		{"ENFORCING", ModeEnforcing},
		{"permissive", ModePermissive},
		{"disabled", ModeDisabled},
		{"garbage", ModeUnknown},
		{"", ModeUnknown},
	} {
		if got := NormalizeSELinuxMode(c.in); got != c.want {
			t.Fatalf("NormalizeSELinuxMode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeAppArmorMode(t *testing.T) {
	if NormalizeAppArmorMode(nil) != ModeEnforcing {
		t.Fatal("empty flags default to enforcing")
	}
	if NormalizeAppArmorMode([]string{"complain"}) != ModeComplain {
		t.Fatal("complain flag")
	}
	if NormalizeAppArmorMode([]string{"audit", "kill"}) != ModeKill {
		t.Fatal("kill wins over audit")
	}
}

func TestIsEnforcingMode(t *testing.T) {
	for _, m := range []Mode{ModeEnforcing, ModeKill} {
		if !IsEnforcingMode(m) {
			t.Fatalf("%q must be enforcing", m)
		}
	}
	for _, m := range []Mode{
		ModeComplain, ModePermissive, ModeDisabled,
		ModeAudit, ModeUnknown,
	} {
		if IsEnforcingMode(m) {
			t.Fatalf("%q must NOT be enforcing", m)
		}
	}
}

func TestAnnotateSecurity(t *testing.T) {
	p := Policy{Mode: ModeEnforcing}
	AnnotateSecurity(&p)
	if !p.IsEnforcing || !p.IsLoaded {
		t.Fatalf("enforcing flags: %+v", p)
	}

	p = Policy{Mode: ModePermissive}
	AnnotateSecurity(&p)
	if p.IsEnforcing || !p.IsLoaded {
		t.Fatalf("permissive flags: %+v", p)
	}

	p = Policy{Mode: ModeDisabled}
	AnnotateSecurity(&p)
	if p.IsEnforcing || p.IsLoaded {
		t.Fatalf("disabled flags: %+v", p)
	}
}

// -- ParseSELinuxConfig ------------------------------------------------

func TestParseSELinuxConfigEnforcing(t *testing.T) {
	body := []byte(`# /etc/selinux/config
SELINUX=enforcing
SELINUXTYPE=targeted
`)
	got := ParseSELinuxConfig(body, "/etc/selinux/config")
	if len(got) != 1 {
		t.Fatalf("len=%d, want 1", len(got))
	}
	p := got[0]
	if p.Subsystem != SubsystemSELinux {
		t.Fatalf("subsystem=%q", p.Subsystem)
	}
	if p.Mode != ModeEnforcing {
		t.Fatalf("mode=%q", p.Mode)
	}
	if !p.IsEnforcing {
		t.Fatal("is_enforcing must be true")
	}
	if p.PolicyType != "targeted" {
		t.Fatalf("policy_type=%q", p.PolicyType)
	}
	if p.FileHash == "" {
		t.Fatal("file_hash missing")
	}
}

func TestParseSELinuxConfigPermissive(t *testing.T) {
	body := []byte("SELINUX=permissive\nSELINUXTYPE=targeted\n")
	got := ParseSELinuxConfig(body, "/etc/selinux/config")
	if got[0].Mode != ModePermissive {
		t.Fatalf("mode=%q", got[0].Mode)
	}
	if got[0].IsEnforcing {
		t.Fatal("permissive must NOT flag is_enforcing")
	}
}

func TestParseSELinuxConfigDisabled(t *testing.T) {
	body := []byte("SELINUX=disabled\n")
	got := ParseSELinuxConfig(body, "/etc/selinux/config")
	if got[0].IsLoaded {
		t.Fatal("disabled must NOT flag is_loaded")
	}
}

func TestParseSELinuxConfigMissingDirective(t *testing.T) {
	body := []byte("# only comments\n")
	got := ParseSELinuxConfig(body, "/etc/selinux/config")
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Mode != ModeUnknown {
		t.Fatalf("mode=%q (no SELINUX= → unknown)", got[0].Mode)
	}
}

// -- ParseAppArmorProfile ----------------------------------------------

func TestParseAppArmorProfileEnforce(t *testing.T) {
	body := []byte(`#include <tunables/global>
profile firefox /usr/bin/firefox {
  #include <abstractions/base>
  /etc/passwd r,
}
`)
	got := ParseAppArmorProfile(body, "/etc/apparmor.d/usr.bin.firefox")
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	p := got[0]
	if p.Subsystem != SubsystemAppArmor {
		t.Fatalf("subsystem=%q", p.Subsystem)
	}
	if p.ProfileName != "firefox" {
		t.Fatalf("name=%q", p.ProfileName)
	}
	if p.TargetPath != "/usr/bin/firefox" {
		t.Fatalf("target=%q", p.TargetPath)
	}
	if p.Mode != ModeEnforcing {
		t.Fatalf("default mode must be enforcing; got %q", p.Mode)
	}
	if !p.IsEnforcing {
		t.Fatal("is_enforcing must be true for default profile")
	}
}

func TestParseAppArmorProfileComplain(t *testing.T) {
	body := []byte(`profile slack /usr/bin/slack flags=(complain) {
  /etc/passwd r,
}
`)
	got := ParseAppArmorProfile(body, "/etc/apparmor.d/usr.bin.slack")
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Mode != ModeComplain {
		t.Fatalf("mode=%q", got[0].Mode)
	}
	if got[0].IsEnforcing {
		t.Fatal("complain must NOT flag is_enforcing")
	}
}

func TestParseAppArmorProfileLegacyForm(t *testing.T) {
	body := []byte(`/usr/sbin/cupsd {
  /etc/passwd r,
}
`)
	got := ParseAppArmorProfile(body, "/etc/apparmor.d/usr.sbin.cupsd")
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].ProfileName != "/usr/sbin/cupsd" {
		t.Fatalf("legacy form name=%q", got[0].ProfileName)
	}
	if got[0].TargetPath != "/usr/sbin/cupsd" {
		t.Fatalf("target=%q", got[0].TargetPath)
	}
}

func TestParseAppArmorProfileSkipsIncludesAndAbi(t *testing.T) {
	body := []byte(`abi <abi/3.0>,
#include <tunables/global>
abi <abi/3.0>,
profile firefox /usr/bin/firefox {
  /etc/passwd r,
}
`)
	got := ParseAppArmorProfile(body, "x")
	if len(got) != 1 {
		t.Fatalf("len=%d (abi+include must be skipped): %+v", len(got), got)
	}
}

// -- ParseLSMList -------------------------------------------------------

func TestParseLSMListTypical(t *testing.T) {
	body := []byte("lockdown,capability,landlock,yama,apparmor,bpf\n")
	got := ParseLSMList(body, "/sys/kernel/security/lsm")
	if len(got) != 6 {
		t.Fatalf("len=%d, want 6", len(got))
	}
	names := map[string]bool{}
	for _, p := range got {
		if p.Subsystem != SubsystemLSMList {
			t.Fatalf("subsystem=%q", p.Subsystem)
		}
		if p.Mode != ModeEnabled {
			t.Fatalf("mode=%q", p.Mode)
		}
		if !p.IsLoaded {
			t.Fatal("lsm-list rows must flag is_loaded")
		}
		names[p.ProfileName] = true
	}
	for _, want := range []string{"apparmor", "yama", "lockdown", "bpf"} {
		if !names[want] {
			t.Fatalf("LSM %q missing", want)
		}
	}
}

// -- collector end-to-end ---------------------------------------------

func TestFileCollectorWalksAllSources(t *testing.T) {
	tmp := t.TempDir()
	selinux := filepath.Join(tmp, "selinux.conf")
	apparmor := filepath.Join(tmp, "apparmor.d")
	lsmFile := filepath.Join(tmp, "lsm")
	must(t, os.MkdirAll(apparmor, 0o755))
	mustWrite(t, selinux, "SELINUX=permissive\nSELINUXTYPE=targeted\n")
	mustWrite(t, filepath.Join(apparmor, "usr.bin.firefox"),
		"profile firefox /usr/bin/firefox {\n  /etc/passwd r,\n}\n")
	mustWrite(t, filepath.Join(apparmor, "usr.bin.slack"),
		"profile slack /usr/bin/slack flags=(complain) {\n  /etc/passwd r,\n}\n")
	mustWrite(t, filepath.Join(apparmor, "ignored.bak"),
		"profile ignored /etc/x flags=(complain) {\n}\n")
	mustWrite(t, lsmFile, "lockdown,capability,yama,apparmor,bpf\n")

	c := &fileCollector{
		selinuxConf: selinux,
		apparmorDir: apparmor,
		lsmListPath: lsmFile,
		readFile:    os.ReadFile,
		readDir:     os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 1 selinux + 2 apparmor + 5 LSMs = 8.
	if len(got) != 8 {
		t.Fatalf("want 8, got %d: %+v", len(got), got)
	}

	var (
		sawPermissive  bool
		sawComplain    bool
		sawApparmorLSM bool
	)
	for _, p := range got {
		if p.Subsystem == SubsystemSELinux && p.Mode == ModePermissive {
			sawPermissive = true
		}
		if p.Subsystem == SubsystemAppArmor && p.ProfileName == "slack" &&
			p.Mode == ModeComplain {
			sawComplain = true
		}
		if p.Subsystem == SubsystemLSMList && p.ProfileName == "apparmor" {
			sawApparmorLSM = true
		}
	}
	if !sawPermissive {
		t.Fatal("SELinux permissive must propagate")
	}
	if !sawComplain {
		t.Fatal("AppArmor complain profile must propagate")
	}
	if !sawApparmorLSM {
		t.Fatal("LSM list must include apparmor")
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		selinuxConf: "/nope",
		apparmorDir: "/nope",
		lsmListPath: "/nope",
		readFile:    os.ReadFile,
		readDir:     os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortPoliciesDeterministic(t *testing.T) {
	in := []Policy{
		{Subsystem: SubsystemLSMList, ProfileName: "yama"},
		{Subsystem: SubsystemAppArmor, ProfileName: "firefox"},
		{Subsystem: SubsystemAppArmor, ProfileName: "atom"},
	}
	SortPolicies(in)
	if in[0].Subsystem != SubsystemAppArmor || in[0].ProfileName != "atom" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].Subsystem != SubsystemLSMList {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers -----------------------------------------------------------

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
