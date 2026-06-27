package preflight

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAsEnabled(t *testing.T) {
	cases := []struct {
		in   any
		name string
		want bool
	}{
		{name: "nil", in: nil, want: false},
		{name: "bool true", in: true, want: true},
		{name: "bool false", in: false, want: false},
		{name: "string true", in: "true", want: true},
		{name: "string True", in: "True", want: true},
		{name: "string yes", in: "yes", want: true},
		{name: "string 1", in: "1", want: true},
		{name: "string false", in: "false", want: false},
		{name: "string empty", in: "", want: false},
		{name: "int", in: 1, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, asEnabled(tc.in))
		})
	}
}

func TestCloudDNSRoute53_Disabled(t *testing.T) {
	c := &CloudDNSRoute53EnvChecker{}
	r := c.Check(context.Background(), "n", false, nil)
	assert.True(t, r.Passed)
	assert.Contains(t, r.Message, "disabled")
}

func TestCloudDNSRoute53_MissingEnv(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	c := &CloudDNSRoute53EnvChecker{}
	r := c.Check(context.Background(), "n", true, nil)
	assert.False(t, r.Passed)
	assert.Contains(t, r.Message, "AWS_ACCESS_KEY_ID")
	assert.Contains(t, r.Message, "AWS_SECRET_ACCESS_KEY")
	assert.Contains(t, r.Hint, "AmazonRoute53ReadOnlyAccess")
}

func TestCloudDNSRoute53_AllSet(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIA0000000000000000")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	c := &CloudDNSRoute53EnvChecker{}
	r := c.Check(context.Background(), "n", true, nil)
	assert.True(t, r.Passed)
}

func TestCloudDNSCloudflare_MissingToken(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "")
	c := &CloudDNSCloudflareEnvChecker{}
	r := c.Check(context.Background(), "n", "true", nil)
	assert.False(t, r.Passed)
	assert.Contains(t, r.Message, "CF_API_TOKEN")
	assert.Contains(t, r.Hint, "Zone:Read")
}

func TestCloudDNSCloudflare_TokenSet(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "abc123")
	c := &CloudDNSCloudflareEnvChecker{}
	r := c.Check(context.Background(), "n", true, nil)
	assert.True(t, r.Passed)
}

func TestCloudDNSAzure_PartialMissing(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000")
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_CLIENT_SECRET", "")
	c := &CloudDNSAzureEnvChecker{}
	r := c.Check(context.Background(), "n", true, nil)
	assert.False(t, r.Passed)
	assert.Contains(t, r.Message, "AZURE_CLIENT_ID")
	assert.Contains(t, r.Message, "AZURE_CLIENT_SECRET")
	assert.NotContains(t, r.Message, "AZURE_TENANT_ID")
}

func TestCloudDNSGCP_MissingEnv(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	c := &CloudDNSGCPEnvChecker{}
	r := c.Check(context.Background(), "n", true, nil)
	assert.False(t, r.Passed)
	assert.Contains(t, r.Message, "GOOGLE_APPLICATION_CREDENTIALS")
}

func TestCloudDNSGCP_PathMissing(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/path/key.json")
	c := &CloudDNSGCPEnvChecker{}
	r := c.Check(context.Background(), "n", true, nil)
	assert.False(t, r.Passed)
	assert.Contains(t, r.Message, "not readable")
}

func TestCloudDNSGCP_ValidPath(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.json")
	require_writeFile(t, keyPath, []byte(`{"type": "service_account"}`))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)
	c := &CloudDNSGCPEnvChecker{}
	r := c.Check(context.Background(), "n", true, nil)
	assert.True(t, r.Passed)
}

// require_writeFile is a tiny helper kept private to this test file —
// avoids pulling in os.WriteFile boilerplate at every call site.
func require_writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
