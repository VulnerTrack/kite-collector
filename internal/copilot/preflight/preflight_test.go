package preflight

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCIDRValidCIDR(t *testing.T) {
	c := &CIDRChecker{}
	r := c.Check(context.Background(), "net.scope", "192.168.1.0/24", nil)
	assert.True(t, r.Passed)
}

func TestCIDRMultipleCIDR(t *testing.T) {
	c := &CIDRChecker{}
	r := c.Check(context.Background(), "net.scope", "192.168.1.0/24, 10.0.0.0/8", nil)
	assert.True(t, r.Passed)
	assert.Contains(t, r.Message, "2 valid CIDR")
}

func TestCIDRInvalid(t *testing.T) {
	c := &CIDRChecker{}
	r := c.Check(context.Background(), "net.scope", "not-a-cidr", nil)
	assert.False(t, r.Passed)
	assert.Contains(t, r.Message, "invalid CIDR")
}

func TestCIDREmpty(t *testing.T) {
	c := &CIDRChecker{}
	r := c.Check(context.Background(), "net.scope", "", nil)
	assert.True(t, r.Passed)
}

func TestVPSEnvNoProviders(t *testing.T) {
	c := &VPSEnvChecker{}
	r := c.Check(context.Background(), "vps", []string{}, nil)
	assert.True(t, r.Passed)
}

func TestVPSEnvMissingToken(t *testing.T) {
	c := &VPSEnvChecker{}
	r := c.Check(context.Background(), "vps", []string{"hetzner"}, nil)
	// Unless KITE_HETZNER_TOKEN is set in the test environment, this should fail.
	if r.Passed {
		t.Skip("KITE_HETZNER_TOKEN is set in environment, skipping")
	}
	assert.False(t, r.Passed)
	assert.Contains(t, r.Message, "KITE_HETZNER_TOKEN")
}

func TestMDMNone(t *testing.T) {
	c := &MDMEnvChecker{}
	r := c.Check(context.Background(), "mdm", "none", nil)
	assert.True(t, r.Passed)
}

func TestCMDBNone(t *testing.T) {
	c := &CMDBEnvChecker{}
	r := c.Check(context.Background(), "cmdb", "none", nil)
	assert.True(t, r.Passed)
}

func TestFileExistsNoFile(t *testing.T) {
	c := &FileExistsChecker{}
	r := c.Check(context.Background(), "allowlist", "", nil)
	assert.True(t, r.Passed)
}

func TestFileExistsMissing(t *testing.T) {
	c := &FileExistsChecker{}
	r := c.Check(context.Background(), "allowlist", "/nonexistent/file.yaml", nil)
	assert.False(t, r.Passed)
}

func TestEnrollTokenEmpty(t *testing.T) {
	c := &EnrollChecker{}
	r := c.Check(context.Background(), "enroll", "", nil)
	assert.True(t, r.Passed)
}

func TestEnrollTokenTooShort(t *testing.T) {
	c := &EnrollChecker{}
	r := c.Check(context.Background(), "enroll", "abc", nil)
	assert.False(t, r.Passed)
}

func TestEnrollTokenValid(t *testing.T) {
	c := &EnrollChecker{}
	r := c.Check(context.Background(), "enroll", "a-valid-enrollment-token-12345678", nil)
	assert.True(t, r.Passed)
}

func TestDockerDisabled(t *testing.T) {
	c := &DockerSocketChecker{}
	r := c.Check(context.Background(), "docker", false, nil)
	assert.True(t, r.Passed)
}

func TestTLSConnectEmpty(t *testing.T) {
	c := &TLSConnectChecker{}
	r := c.Check(context.Background(), "endpoint", "", nil)
	assert.True(t, r.Passed)
}

func TestOTELEmpty(t *testing.T) {
	c := &OTELHealthChecker{}
	r := c.Check(context.Background(), "otel", "", nil)
	assert.True(t, r.Passed)
}

func TestRunnerParallel(t *testing.T) {
	logger := slog.Default()
	runner := NewRunner(4, logger)

	specs := []CheckSpec{
		{NodeID: "net.scope", CheckTag: "network:cidr:parse", Value: "10.0.0.0/8"},
		{NodeID: "docker", CheckTag: "docker:socket:probe", Value: false},
		{NodeID: "enroll", CheckTag: "endpoint:enroll", Value: ""},
		{NodeID: "file", CheckTag: "file:exists", Value: ""},
	}

	results := runner.Run(context.Background(), specs)
	require.Len(t, results, 4)
	for _, r := range results {
		assert.True(t, r.Passed, "check %s should pass", r.Check)
	}
}

func TestRunnerUnknownChecker(t *testing.T) {
	logger := slog.Default()
	runner := NewRunner(4, logger)

	specs := []CheckSpec{
		{NodeID: "x", CheckTag: "unknown:checker", Value: "test"},
	}
	results := runner.Run(context.Background(), specs)
	require.Len(t, results, 1)
	assert.False(t, results[0].Passed)
	assert.Contains(t, results[0].Message, "no checker registered")
}

func TestSummary(t *testing.T) {
	results := []CheckResult{
		{Passed: true},
		{Passed: true},
		{Passed: false},
	}
	passed, failed := Summary(results)
	assert.Equal(t, 2, passed)
	assert.Equal(t, 1, failed)
}

// mockChecker is a test-only checker with configurable behavior.
type mockChecker struct {
	result CheckResult
}

func (m *mockChecker) Check(_ context.Context, _ string, _ any, _ map[string]any) CheckResult {
	return m.result
}

func TestRunnerCustomChecker(t *testing.T) {
	logger := slog.Default()
	runner := NewRunner(4, logger)
	runner.Register("custom:check", &mockChecker{
		result: CheckResult{Passed: true, Message: "custom OK"},
	})

	specs := []CheckSpec{
		{NodeID: "custom", CheckTag: "custom:check", Value: "test"},
	}
	results := runner.Run(context.Background(), specs)
	require.Len(t, results, 1)
	assert.True(t, results[0].Passed)
	assert.Equal(t, "custom OK", results[0].Message)
}
