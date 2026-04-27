package audit

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func mustWriteFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// fakeProcRoot builds a synthetic /proc tree under tmp. Each entry maps
// pid -> (comm, environ block as NUL-separated KEY=VALUE entries).
func fakeProcRoot(t *testing.T, entries map[string]struct {
	comm    string
	environ string
}) string {
	t.Helper()
	root := t.TempDir()
	for pid, e := range entries {
		dir := filepath.Join(root, pid)
		mustWriteFile(t, filepath.Join(dir, "comm"), e.comm)
		mustWriteFile(t, filepath.Join(dir, "environ"), e.environ)
	}
	return root
}

func serverAsset() model.Asset {
	a := testAsset()
	a.AssetType = model.AssetTypeServer
	return a
}

func TestProcessEnvSecrets_DetectsAWSKey(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process_env_secrets is linux-only")
	}
	root := fakeProcRoot(t, map[string]struct {
		comm    string
		environ string
	}{
		"1234": {
			comm:    "postgres\n",
			environ: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\x00PATH=/usr/bin\x00",
		},
	})
	auditor := NewProcessEnvSecrets(ProcessEnvSecretsConfig{ProcRoot: root})
	findings, err := auditor.Audit(context.Background(), serverAsset())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.CheckID != "sec-001" {
		t.Errorf("expected sec-001, got %s", f.CheckID)
	}
	if f.CWEID != processEnvSecretsCWEID {
		t.Errorf("expected %s, got %s", processEnvSecretsCWEID, f.CWEID)
	}
	if !strings.Contains(f.Evidence, "ENV[AWS_ACCESS_KEY_ID]=<redacted>") {
		t.Errorf("evidence missing redacted env name: %q", f.Evidence)
	}
	if strings.Contains(f.Evidence, "AKIA") {
		t.Errorf("evidence must never contain the secret value: %q", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "process:postgres") {
		t.Errorf("evidence missing process name: %q", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "PID 1234") {
		t.Errorf("evidence missing pid: %q", f.Evidence)
	}
}

func TestProcessEnvSecrets_SkipsKernelThreads(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process_env_secrets is linux-only")
	}
	root := fakeProcRoot(t, map[string]struct {
		comm    string
		environ string
	}{
		"2": {
			// kernel thread: empty comm
			comm:    "",
			environ: "FAKE_KEY=AKIAIOSFODNN7EXAMPLE\x00",
		},
	})
	auditor := NewProcessEnvSecrets(ProcessEnvSecretsConfig{ProcRoot: root})
	findings, err := auditor.Audit(context.Background(), serverAsset())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (kernel thread skipped), got %d", len(findings))
	}
}

func TestProcessEnvSecrets_SkipsSelfPID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process_env_secrets is linux-only")
	}
	selfPID := os.Getpid()
	root := fakeProcRoot(t, map[string]struct {
		comm    string
		environ string
	}{
		// our own pid is intentionally listed — auditor must skip it
		filenameForPID(selfPID): {
			comm:    "kite-collector\n",
			environ: "FAKE_KEY=AKIAIOSFODNN7EXAMPLE\x00",
		},
	})
	auditor := NewProcessEnvSecrets(ProcessEnvSecretsConfig{ProcRoot: root})
	findings, err := auditor.Audit(context.Background(), serverAsset())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (self-pid skipped), got %d", len(findings))
	}
}

func TestProcessEnvSecrets_NonServerAssetReturnsNil(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process_env_secrets is linux-only")
	}
	root := fakeProcRoot(t, nil)
	auditor := NewProcessEnvSecrets(ProcessEnvSecretsConfig{ProcRoot: root})
	a := testAsset()
	a.AssetType = model.AssetTypeContainer

	findings, err := auditor.Audit(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil for non-server asset, got %d", len(findings))
	}
}

func TestProcessEnvSecrets_ProcessFilter(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process_env_secrets is linux-only")
	}
	root := fakeProcRoot(t, map[string]struct {
		comm    string
		environ string
	}{
		"1234": {
			comm:    "postgres\n",
			environ: "PG_KEY=AKIAIOSFODNN7EXAMPLE\x00",
		},
		"5678": {
			comm:    "nginx\n",
			environ: "NGINX_KEY=AKIAIOSFODNN7EXAMPLE\x00",
		},
	})
	auditor := NewProcessEnvSecrets(ProcessEnvSecretsConfig{
		ProcRoot:  root,
		Processes: []string{"postgres"},
	})
	findings, err := auditor.Audit(context.Background(), serverAsset())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (only postgres), got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "process:postgres") {
		t.Errorf("expected postgres finding, got %q", findings[0].Evidence)
	}
}

func TestProcessEnvSecrets_DenyListSkipsCommonNoise(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process_env_secrets is linux-only")
	}
	root := fakeProcRoot(t, map[string]struct {
		comm    string
		environ string
	}{
		"1234": {
			comm:    "node\n",
			environ: "PATH=/AKIAIOSFODNN7EXAMPLE/bin\x00",
		},
	})
	auditor := NewProcessEnvSecrets(ProcessEnvSecretsConfig{ProcRoot: root})
	findings, err := auditor.Audit(context.Background(), serverAsset())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (PATH on deny list), got %d", len(findings))
	}
}

func TestProcessEnvSecrets_NoEnvironProducesNoFindings(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process_env_secrets is linux-only")
	}
	root := fakeProcRoot(t, map[string]struct {
		comm    string
		environ string
	}{
		"1234": {comm: "node\n", environ: ""},
	})
	auditor := NewProcessEnvSecrets(ProcessEnvSecretsConfig{ProcRoot: root})
	findings, err := auditor.Audit(context.Background(), serverAsset())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestProcessEnvSecrets_DeterministicID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process_env_secrets is linux-only")
	}
	asset := serverAsset()
	envBlock := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\x00"
	root1 := fakeProcRoot(t, map[string]struct {
		comm    string
		environ string
	}{
		"1234": {comm: "postgres\n", environ: envBlock},
	})
	root2 := fakeProcRoot(t, map[string]struct {
		comm    string
		environ string
	}{
		// same process_name, different pid — IDs should still match
		"5678": {comm: "postgres\n", environ: envBlock},
	})
	a1 := NewProcessEnvSecrets(ProcessEnvSecretsConfig{ProcRoot: root1})
	a2 := NewProcessEnvSecrets(ProcessEnvSecretsConfig{ProcRoot: root2})
	f1, err := a1.Audit(context.Background(), asset)
	if err != nil {
		t.Fatalf("audit 1: %v", err)
	}
	f2, err := a2.Audit(context.Background(), asset)
	if err != nil {
		t.Fatalf("audit 2: %v", err)
	}
	if len(f1) != 1 || len(f2) != 1 {
		t.Fatalf("expected 1 finding each, got %d / %d", len(f1), len(f2))
	}
	if f1[0].ID != f2[0].ID {
		t.Errorf("IDs must be stable across pid changes, got %s vs %s", f1[0].ID, f2[0].ID)
	}
}

func TestProcessEnvSecrets_MaxPIDsCap(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process_env_secrets is linux-only")
	}
	entries := make(map[string]struct {
		comm    string
		environ string
	})
	// Three PIDs, each carrying a unique secret; cap to 1.
	entries["1001"] = struct{ comm, environ string }{
		comm: "p1\n", environ: "K1=AKIAAAAAAAAAAAAAAAAA\x00",
	}
	entries["1002"] = struct{ comm, environ string }{
		comm: "p2\n", environ: "K2=AKIABBBBBBBBBBBBBBBB\x00",
	}
	entries["1003"] = struct{ comm, environ string }{
		comm: "p3\n", environ: "K3=AKIACCCCCCCCCCCCCCCC\x00",
	}
	root := fakeProcRoot(t, entries)
	auditor := NewProcessEnvSecrets(ProcessEnvSecretsConfig{ProcRoot: root, MaxPIDs: 1})
	findings, err := auditor.Audit(context.Background(), serverAsset())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) > 1 {
		t.Errorf("expected at most 1 finding under MaxPIDs=1, got %d", len(findings))
	}
}

func TestPidFromName(t *testing.T) {
	cases := []struct {
		in     string
		pid    int
		wantOK bool
	}{
		{"1234", 1234, true},
		{"0", 0, false},
		{"-1", 0, false},
		{"self", 0, false},
		{"thread-self", 0, false},
		{"123abc", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		pid, ok := pidFromName(c.in)
		if pid != c.pid || ok != c.wantOK {
			t.Errorf("pidFromName(%q) = (%d, %v), want (%d, %v)", c.in, pid, ok, c.pid, c.wantOK)
		}
	}
}

func TestProcessEnvSecrets_Name(t *testing.T) {
	a := NewProcessEnvSecrets(ProcessEnvSecretsConfig{})
	if a.Name() != "process_env_secrets" {
		t.Errorf("Name() = %q", a.Name())
	}
}

func TestScanProcessEnv_DedupesPerPID(t *testing.T) {
	asset := serverAsset()
	now := time.Now().UTC()
	envBytes := []byte("AWS=AKIAIOSFODNN7EXAMPLE\x00AWS=AKIAIOSFODNN7EXAMPLE\x00")
	findings := scanProcessEnv(asset, 1, "redis", envBytes, defaultEnvDenyPrefixes, now)
	if len(findings) != 1 {
		t.Errorf("expected 1 deduplicated finding, got %d", len(findings))
	}
}

func filenameForPID(pid int) string {
	return strconv.Itoa(pid)
}
