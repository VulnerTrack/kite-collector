package audit

import (
	"context"
	"strings"
	"testing"
	"time"

	dockerdisc "github.com/vulnertrack/kite-collector/internal/discovery/docker"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// stubLister implements ContainerEnvLister for tests.
type stubLister struct {
	err  error
	envs []dockerdisc.ContainerEnv
}

func (s *stubLister) ListContainerEnvs(_ context.Context, _ map[string]any) ([]dockerdisc.ContainerEnv, error) {
	return s.envs, s.err
}

func containerAsset(t *testing.T, containerID string) model.Asset {
	t.Helper()
	a := testAsset()
	a.AssetType = model.AssetTypeContainer
	a.Tags = `{"container_id":"` + containerID + `","image":"redis:7"}`
	return a
}

func TestContainerEnvSecrets_DetectsAWSKey(t *testing.T) {
	lister := &stubLister{
		envs: []dockerdisc.ContainerEnv{
			{
				ID:    "abc123def456789",
				Name:  "redis-cache",
				Image: "redis:7",
				State: "running",
				Env: []string{
					"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
					"PATH=/usr/local/bin:/usr/bin",
				},
			},
		},
	}
	auditor := NewContainerEnvSecrets(lister, nil, nil)
	findings, err := auditor.Audit(context.Background(), containerAsset(t, "abc123def456"))
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
	if f.CWEID != containerEnvSecretsCWEID {
		t.Errorf("expected %s, got %s", containerEnvSecretsCWEID, f.CWEID)
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("expected critical, got %s", f.Severity)
	}
	if !strings.Contains(f.Evidence, "ENV[AWS_ACCESS_KEY_ID]=<redacted>") {
		t.Errorf("evidence missing redacted env name: %q", f.Evidence)
	}
	if strings.Contains(f.Evidence, "AKIA") {
		t.Errorf("evidence must never contain the actual secret value: %q", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "hash:") {
		t.Errorf("evidence missing hash prefix: %q", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "container:abc123def456") {
		t.Errorf("evidence missing container ID: %q", f.Evidence)
	}
	if f.Auditor != containerEnvSecretsAuditorName {
		t.Errorf("expected auditor %s, got %s", containerEnvSecretsAuditorName, f.Auditor)
	}
}

func TestContainerEnvSecrets_NonContainerAssetReturnsNil(t *testing.T) {
	lister := &stubLister{}
	auditor := NewContainerEnvSecrets(lister, nil, nil)

	a := testAsset()
	a.AssetType = model.AssetTypeServer

	findings, err := auditor.Audit(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings for non-container asset, got %d", len(findings))
	}
}

func TestContainerEnvSecrets_DenyListSkipped(t *testing.T) {
	// AKIA token in PATH which is on the deny list.
	lister := &stubLister{
		envs: []dockerdisc.ContainerEnv{
			{
				ID:    "abc123def456789",
				Name:  "noisy",
				Image: "redis:7",
				State: "running",
				Env: []string{
					"PATH=/AKIAIOSFODNN7EXAMPLE/bin",
				},
			},
		},
	}
	auditor := NewContainerEnvSecrets(lister, nil, nil)
	findings, err := auditor.Audit(context.Background(), containerAsset(t, "abc123def456"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (PATH in deny list), got %d", len(findings))
	}
}

func TestContainerEnvSecrets_DeterministicID(t *testing.T) {
	lister1 := &stubLister{
		envs: []dockerdisc.ContainerEnv{
			{ID: "abc123def456789", Name: "x", Env: []string{"AWS_KEY=AKIAIOSFODNN7EXAMPLE"}},
		},
	}
	lister2 := &stubLister{
		envs: []dockerdisc.ContainerEnv{
			{ID: "abc123def456789", Name: "x", Env: []string{"AWS_KEY=AKIAIOSFODNN7EXAMPLE"}},
		},
	}
	asset := containerAsset(t, "abc123def456")

	a1 := NewContainerEnvSecrets(lister1, nil, nil)
	f1, err := a1.Audit(context.Background(), asset)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	a2 := NewContainerEnvSecrets(lister2, nil, nil)
	f2, err := a2.Audit(context.Background(), asset)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f1) != 1 || len(f2) != 1 {
		t.Fatalf("expected 1 finding each, got %d / %d", len(f1), len(f2))
	}
	if f1[0].ID != f2[0].ID {
		t.Errorf("finding IDs must be deterministic, got %s vs %s", f1[0].ID, f2[0].ID)
	}
}

func TestContainerEnvSecrets_DedupesSamePatternPerEnvVar(t *testing.T) {
	lister := &stubLister{
		envs: []dockerdisc.ContainerEnv{
			{
				ID:   "abc123def456789",
				Name: "x",
				Env: []string{
					"FIRST=AKIAIOSFODNN7EXAMPLE",
					"FIRST=AKIAIOSFODNN7EXAMPLE", // duplicate (Docker allows)
				},
			},
		},
	}
	auditor := NewContainerEnvSecrets(lister, nil, nil)
	findings, err := auditor.Audit(context.Background(), containerAsset(t, "abc123def456"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 deduplicated finding, got %d", len(findings))
	}
}

func TestContainerEnvSecrets_MissingTagSkips(t *testing.T) {
	lister := &stubLister{
		envs: []dockerdisc.ContainerEnv{{ID: "abc", Env: []string{"AWS=AKIAIOSFODNN7EXAMPLE"}}},
	}
	auditor := NewContainerEnvSecrets(lister, nil, nil)

	a := testAsset()
	a.AssetType = model.AssetTypeContainer
	a.Tags = "" // no tags

	findings, err := auditor.Audit(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil for missing tag, got %d findings", len(findings))
	}
}

func TestContainerEnvSecrets_NoMatchProducesNoFindings(t *testing.T) {
	lister := &stubLister{
		envs: []dockerdisc.ContainerEnv{
			{
				ID:   "abc123def456789",
				Name: "ok",
				Env:  []string{"FOO=bar", "DB_NAME=mydb"},
			},
		},
	}
	auditor := NewContainerEnvSecrets(lister, nil, nil)
	findings, err := auditor.Audit(context.Background(), containerAsset(t, "abc123def456"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestContainerEnvSecrets_NameAndCISControl(t *testing.T) {
	a := NewContainerEnvSecrets(&stubLister{}, nil, nil)
	if a.Name() != "container_env_secrets" {
		t.Errorf("Name() = %q", a.Name())
	}
}

func TestSplitEnvKV(t *testing.T) {
	cases := []struct {
		in        string
		wantName  string
		wantValue string
		wantOK    bool
	}{
		{in: "FOO=bar", wantName: "FOO", wantValue: "bar", wantOK: true},
		{in: "FOO=", wantName: "FOO", wantValue: "", wantOK: true},
		{in: "=bar", wantName: "", wantValue: "", wantOK: false},
		{in: "NOEQUALS", wantName: "", wantValue: "", wantOK: false},
		{in: "PATH=/usr/bin:/bin", wantName: "PATH", wantValue: "/usr/bin:/bin", wantOK: true},
		{in: "X=Y=Z", wantName: "X", wantValue: "Y=Z", wantOK: true},
	}
	for _, c := range cases {
		name, value, ok := splitEnvKV(c.in)
		if ok != c.wantOK || name != c.wantName || value != c.wantValue {
			t.Errorf("splitEnvKV(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.in, name, value, ok, c.wantName, c.wantValue, c.wantOK)
		}
	}
}

func TestMatchesAnyPrefix(t *testing.T) {
	prefixes := []string{"TERM", "LC_"}
	cases := map[string]bool{
		"TERM":          true,
		"TERMINAL_X":    true,
		"LC_ALL":        true,
		"lc_all":        true, // case-insensitive
		"AWS_KEY":       false,
		"":              false,
		"TERM_OVERRIDE": true,
	}
	for in, want := range cases {
		if got := matchesAnyPrefix(in, prefixes); got != want {
			t.Errorf("matchesAnyPrefix(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestExtractContainerIDTag(t *testing.T) {
	tags := `{"container_id":"abc123","image":"redis:7","privileged":false}`
	if got := extractContainerIDTag(tags); got != "abc123" {
		t.Errorf("extractContainerIDTag = %q, want abc123", got)
	}
	if got := extractContainerIDTag(""); got != "" {
		t.Errorf("expected empty for empty tags, got %q", got)
	}
	if got := extractContainerIDTag("not-json"); got != "" {
		t.Errorf("expected empty for malformed tags, got %q", got)
	}
}

func TestScanContainerEnv_RecordsCISControl(t *testing.T) {
	asset := containerAsset(t, "abc123def456")
	env := dockerdisc.ContainerEnv{
		ID:   "abc123def456789",
		Name: "x",
		Env:  []string{"AWS_KEY=AKIAIOSFODNN7EXAMPLE"},
	}
	now := time.Now().UTC()
	findings := scanContainerEnv(asset, env, defaultEnvDenyPrefixes, now)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CISControl != containerEnvSecretsCISControl {
		t.Errorf("expected CIS control %q, got %q",
			containerEnvSecretsCISControl, findings[0].CISControl)
	}
}
