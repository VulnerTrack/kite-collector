package audit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// declaredEvidenceRe pins the env-exposure-001 evidence format documented in
// RFC-0153 §5.3 — the vie-side lift parses it, so drift must fail here first.
var declaredEvidenceRe = regexp.MustCompile(
	`^ENV\[[A-Za-z_][A-Za-z0-9_]*\]=<redacted> declared secret ` +
		`exposed in process:\S+ \(PID \d+\) hash:[0-9a-f]{16}$`)

func serverMachine() model.Machine {
	return model.Machine{ID: uuid.New(), MachineType: model.MachineTypeServer}
}

// writeFakeProc creates procRoot/<pid>/{comm,environ} for one fake process.
func writeFakeProc(t *testing.T, procRoot string, pid int, comm string, env []string) {
	t.Helper()
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	environ := strings.Join(env, "\x00") + "\x00"
	if err := os.WriteFile(filepath.Join(dir, "environ"), []byte(environ), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakePID returns a PID guaranteed not to be the test process itself.
func fakePID() int {
	pid := 4242
	if pid == os.Getpid() {
		pid++
	}
	return pid
}

// RFC-0153 R5: an opaque value in a declared name is flagged even though it
// matches none of the secretPatterns (the value-pattern blindness this
// feature closes).
func TestProcessEnvSecrets_DeclaredNameFlagged(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("auditor is linux-only")
	}
	procRoot := t.TempDir()
	writeFakeProc(t, procRoot, fakePID(), "nginx",
		[]string{"KITE_JAMF_PASSWORD=hunter2hunter2", "LANG=C"})

	p := NewProcessEnvSecrets(ProcessEnvSecretsConfig{
		ProcRoot:               procRoot,
		DeclaredSecretEnvNames: []string{"KITE_JAMF_PASSWORD"},
	})
	findings, err := p.Audit(context.Background(), serverMachine())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.CheckID != declaredEnvCheckID {
		t.Errorf("CheckID = %q, want %q", f.CheckID, declaredEnvCheckID)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("Severity = %v, want high", f.Severity)
	}
	if !declaredEvidenceRe.MatchString(f.Evidence) {
		t.Errorf("evidence drifted from RFC-0153 format: %q", f.Evidence)
	}
	if strings.Contains(f.Evidence, "hunter2") {
		t.Errorf("evidence leaks the secret value (R7): %q", f.Evidence)
	}
}

// RFC-0153 R6: deny prefixes suppress pattern scanning, never the declared
// check — explicit declaration beats prefix noise filtering.
func TestProcessEnvSecrets_DeclaredBeatsDenyPrefix(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("auditor is linux-only")
	}
	procRoot := t.TempDir()
	// LANG_SECRET is covered by the built-in LANG deny prefix; a GitHub
	// token value would otherwise hit sec-006, so a lone declared finding
	// proves the deny list still gates the pattern loop.
	writeFakeProc(t, procRoot, fakePID(), "cron",
		[]string{"LANG_SECRET=ghp_0123456789012345678901234567890123456789"})

	p := NewProcessEnvSecrets(ProcessEnvSecretsConfig{
		ProcRoot:               procRoot,
		DeclaredSecretEnvNames: []string{"LANG_SECRET"},
	})
	findings, err := p.Audit(context.Background(), serverMachine())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want exactly 1 (declared only): %+v", len(findings), findings)
	}
	if findings[0].CheckID != declaredEnvCheckID {
		t.Errorf("CheckID = %q, want %q", findings[0].CheckID, declaredEnvCheckID)
	}
}

// The agent's own process never self-flags (axiom 7); empty values are not
// exposures.
func TestProcessEnvSecrets_SelfAndEmptyValueSkipped(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("auditor is linux-only")
	}
	procRoot := t.TempDir()
	writeFakeProc(t, procRoot, os.Getpid(), "kite-collector",
		[]string{"KITE_JAMF_PASSWORD=hunter2hunter2"})
	writeFakeProc(t, procRoot, fakePID(), "nginx",
		[]string{"KITE_JAMF_PASSWORD="})

	p := NewProcessEnvSecrets(ProcessEnvSecretsConfig{
		ProcRoot:               procRoot,
		DeclaredSecretEnvNames: []string{"KITE_JAMF_PASSWORD"},
	})
	findings, err := p.Audit(context.Background(), serverMachine())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: %+v", len(findings), findings)
	}
}

// Declared and pattern findings coexist on distinct vars in one process.
func TestProcessEnvSecrets_DeclaredAndPatternCoexist(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("auditor is linux-only")
	}
	procRoot := t.TempDir()
	writeFakeProc(t, procRoot, fakePID(), "app", []string{
		"KITE_NETBOX_TOKEN=opaquevalue123",
		"GH_CRED=ghp_0123456789012345678901234567890123456789",
	})

	p := NewProcessEnvSecrets(ProcessEnvSecretsConfig{
		ProcRoot:               procRoot,
		DeclaredSecretEnvNames: []string{"KITE_NETBOX_TOKEN"},
	})
	findings, err := p.Audit(context.Background(), serverMachine())
	if err != nil {
		t.Fatal(err)
	}
	var declared, pattern int
	for _, f := range findings {
		if f.CheckID == declaredEnvCheckID {
			declared++
		} else {
			pattern++
		}
	}
	if declared != 1 || pattern != 1 {
		t.Fatalf("declared=%d pattern=%d, want 1 and 1: %+v", declared, pattern, findings)
	}
}

// Finding identity is PID-free (4.2 axiom 4): a process restart preserves
// first_seen_at because the deterministic ID ignores the ephemeral PID.
func TestDeclaredEnvFinding_DeterministicPIDFreeID(t *testing.T) {
	machine := serverMachine()
	now := time.Now().UTC()
	a := declaredEnvFinding(machine, 100, "nginx", "KITE_JAMF_PASSWORD", "v1", now)
	b := declaredEnvFinding(machine, 999, "nginx", "KITE_JAMF_PASSWORD", "v2", now)
	if a.ID != b.ID {
		t.Errorf("IDs differ across PIDs/values: %s vs %s", a.ID, b.ID)
	}
	c := declaredEnvFinding(machine, 100, "cron", "KITE_JAMF_PASSWORD", "v1", now)
	if a.ID == c.ID {
		t.Error("IDs must differ across process names")
	}
}

// Edge: an environ larger than the 256 KiB read cap gets its incomplete
// tail entry dropped — complete entries are still detected, but a declared
// name whose entry straddles the cap must not yield a finding with a
// truncated-value hash.
func TestProcessEnvSecrets_TruncatedEnvironDropsPartialTail(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("auditor is linux-only")
	}
	procRoot := t.TempDir()

	// Layout: one complete declared entry up front, filler to just below the
	// cap, then a second declared entry that straddles the cap boundary.
	var env bytes.Buffer
	env.WriteString("KITE_NETBOX_TOKEN=complete-value\x00")
	filler := maxEnvBlockSize - 100 - env.Len()
	env.WriteString("FILLER=" + strings.Repeat("a", filler-8) + "\x00")
	env.WriteString("KITE_JAMF_PASSWORD=" + strings.Repeat("x", 300) + "\x00")
	if env.Len() <= maxEnvBlockSize {
		t.Fatalf("fixture must exceed the cap: %d <= %d", env.Len(), maxEnvBlockSize)
	}

	pid := fakePID()
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte("bloated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "environ"), env.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	p := NewProcessEnvSecrets(ProcessEnvSecretsConfig{
		ProcRoot:               procRoot,
		DeclaredSecretEnvNames: []string{"KITE_NETBOX_TOKEN", "KITE_JAMF_PASSWORD"},
	})
	findings, err := p.Audit(context.Background(), serverMachine())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (complete entry only): %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Evidence, "ENV[KITE_NETBOX_TOKEN]") {
		t.Errorf("finding is not for the complete entry: %q", findings[0].Evidence)
	}
}

func TestDropPartialEnvTail(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"partial tail removed", "A=1\x00B=partia", "A=1\x00"},
		{"complete block unchanged", "A=1\x00B=2\x00", "A=1\x00B=2\x00"},
		{"no NUL at all is one partial entry", "A=partia", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(dropPartialEnvTail([]byte(tc.in)))
			if got != tc.want {
				t.Errorf("dropPartialEnvTail(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// With no declarations the auditor behaves exactly as before RFC-0153.
func TestProcessEnvSecrets_NoDeclarationsNoNewFindings(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("auditor is linux-only")
	}
	procRoot := t.TempDir()
	writeFakeProc(t, procRoot, fakePID(), "nginx",
		[]string{"KITE_JAMF_PASSWORD=hunter2hunter2"})

	p := NewProcessEnvSecrets(ProcessEnvSecretsConfig{ProcRoot: procRoot})
	findings, err := p.Audit(context.Background(), serverMachine())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CheckID == declaredEnvCheckID {
			t.Fatalf("env-exposure-001 without declarations: %+v", f)
		}
	}
}
