package connectorkit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnabled(t *testing.T) {
	assert.True(t, Enabled(map[string]any{"enabled": true}))
	assert.False(t, Enabled(map[string]any{"enabled": false}))
	assert.False(t, Enabled(map[string]any{}), "missing key defaults to disabled")
	assert.False(t, Enabled(map[string]any{"enabled": "true"}), "wrong type is not enabled")
	assert.False(t, Enabled(nil), "nil config is disabled")
}

func TestEnabled_F3_DisabledDespiteCredentials(t *testing.T) {
	// Finding F3 regression: a source with enabled:false must stay disabled
	// even when credential fields are present in the merged config — the exact
	// scenario where credential env vars (merged into cfg by engine.go) were
	// previously sufficient to trigger discovery despite enabled:false. Every
	// connector calls Enabled(cfg) as its first line, so this single gate
	// protects all nine MDM/CMDB sources.
	cfg := map[string]any{
		"enabled":       false,
		"api_url":       "https://jamf.example.com",
		"instance_url":  "https://acme.service-now.com",
		"username":      "svc",
		"password":      "secret",
		"token":         "tok",
		"api_key":       "key",
		"client_secret": "cs",
	}
	assert.False(t, Enabled(cfg), "enabled:false must win regardless of credentials present")
}

func TestLoadCredentials(t *testing.T) {
	cfg := map[string]any{
		"api_url":       "https://api.example.com",
		"instance_url":  "https://acme.service-now.com",
		"username":      "svc",
		"password":      "pw",
		"token":         "tok",
		"api_key":       "key",
		"tenant_id":     "ten",
		"client_id":     "cid",
		"client_secret": "cs",
		"table":         "cmdb_ci_server",
		"site_id":       "site-123",
	}
	c := LoadCredentials(cfg)
	assert.Equal(t, "https://api.example.com", c.APIURL)
	assert.Equal(t, "https://acme.service-now.com", c.InstanceURL)
	assert.Equal(t, "svc", c.Username)
	assert.Equal(t, "pw", c.Password)
	assert.Equal(t, "tok", c.Token)
	assert.Equal(t, "key", c.APIKey)
	assert.Equal(t, "ten", c.TenantID)
	assert.Equal(t, "cid", c.ClientID)
	assert.Equal(t, "cs", c.ClientSecret)
	assert.Equal(t, "cmdb_ci_server", c.Table)
	assert.Equal(t, "site-123", c.SiteID)
}

func TestLoadCredentials_Empty(t *testing.T) {
	c := LoadCredentials(map[string]any{})
	assert.Empty(t, c.APIURL)
	assert.Empty(t, c.Password)
	assert.Empty(t, c.APIKey)

	// Non-string values are ignored rather than panicking.
	c = LoadCredentials(map[string]any{"api_url": 42, "password": true})
	assert.Empty(t, c.APIURL)
	assert.Empty(t, c.Password)
}

func TestCredentialsZero(t *testing.T) {
	// Secrets are loaded (and cloned onto the heap) so Zero can safely
	// overwrite their backing memory without faulting on read-only literals.
	c := LoadCredentials(map[string]any{
		"password":      "super-secret",
		"token":         "bearer-token",
		"api_key":       "api-key-value",
		"client_secret": "client-secret-value",
	})
	require.Equal(t, "super-secret", c.Password)

	c.Zero()

	assert.Empty(t, c.Password)
	assert.Empty(t, c.Token)
	assert.Empty(t, c.APIKey)
	assert.Empty(t, c.ClientSecret)
}
