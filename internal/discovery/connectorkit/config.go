// Package connectorkit provides the shared hardening scaffold every REST-based
// MDM/CMDB discovery connector is built on: the enabled gate (F3), credential
// loading with post-auth zeroing (R1), SSRF/TLS-validated HTTP clients (R3),
// labelled pagination guarding (R1), and code-derived security-posture
// introspection (ConnectorSecurityProfile, 4.1.4). It wraps internal/safenet
// so that a connector written against connectorkit is hardened by construction
// rather than by retrofit.
package connectorkit

import (
	"strings"

	"github.com/vulnertrack/kite-collector/internal/safenet"
)

// Enabled reports whether cfg["enabled"] is explicitly true. Every connector
// built on connectorkit MUST call this before any network call — it closes the
// enabled:false bypass where credential env vars alone were sufficient to
// trigger discovery (Finding F3, R2).
func Enabled(cfg map[string]any) bool {
	v, ok := cfg["enabled"].(bool)
	return ok && v
}

// Credentials holds every credential-bearing field the MDM/CMDB, Entra, and
// Cloud DNS connectors need. Secret fields (Password, Token, APIKey,
// ClientSecret, SecretAccessKey, SessionToken) are heap-cloned by
// LoadCredentials so Zero can safely overwrite their backing memory.
//
// The AWS-shaped fields (AccessKeyID, SecretAccessKey, SessionToken) are
// additive (RFC-0137 R2): they default to the zero value, so the ten existing
// MDM/CMDB consumers that never populate them are unaffected. Route53 loads its
// IAM credentials through these so it gains the same single Zero() call site the
// other connectors already have. AccessKeyID is a public identifier (like
// Username/ClientID) and is intentionally not zeroed; the secret and session
// keys are.
type Credentials struct {
	APIURL          string
	InstanceURL     string
	Username        string
	Password        string
	Token           string
	APIKey          string
	TenantID        string
	ClientID        string
	ClientSecret    string
	Table           string
	SiteID          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// LoadCredentials extracts the known credential fields from cfg, which is
// populated from SourceConfig (R4) with a fallback to the legacy sourceEnvVars
// map in engine.go for backward compatibility. Secret-bearing values are cloned
// onto the heap so a later Zero cannot fault on read-only literal memory.
func LoadCredentials(cfg map[string]any) Credentials {
	return Credentials{
		APIURL:          cfgString(cfg, "api_url"),
		InstanceURL:     cfgString(cfg, "instance_url"),
		Username:        cfgString(cfg, "username"),
		Password:        cfgSecret(cfg, "password"),
		Token:           cfgSecret(cfg, "token"),
		APIKey:          cfgSecret(cfg, "api_key"),
		TenantID:        cfgString(cfg, "tenant_id"),
		ClientID:        cfgString(cfg, "client_id"),
		ClientSecret:    cfgSecret(cfg, "client_secret"),
		Table:           cfgString(cfg, "table"),
		SiteID:          cfgString(cfg, "site_id"),
		AccessKeyID:     cfgString(cfg, "access_key_id"),
		SecretAccessKey: cfgSecret(cfg, "secret_access_key"),
		SessionToken:    cfgSecret(cfg, "session_token"),
	}
}

// Zero overwrites every secret-bearing field via safenet.ZeroString. Every
// connector calls this via defer immediately after loading credentials (R1), so
// plaintext secrets do not linger in process memory past the discovery call.
func (c *Credentials) Zero() {
	safenet.ZeroString(&c.Password)
	safenet.ZeroString(&c.Token)
	safenet.ZeroString(&c.APIKey)
	safenet.ZeroString(&c.ClientSecret)
	safenet.ZeroString(&c.SecretAccessKey)
	safenet.ZeroString(&c.SessionToken)
}

// cfgString reads a plain (non-secret) string value from cfg, empty if absent.
func cfgString(cfg map[string]any, key string) string {
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}

// cfgSecret reads a secret string value and clones it so the returned string
// owns independent heap memory. safenet.ZeroString mutates its argument's
// backing array in place and fatally crashes on read-only literal memory, so a
// clone here is the required companion to Zero.
func cfgSecret(cfg map[string]any, key string) string {
	if v, ok := cfg[key].(string); ok && v != "" {
		return strings.Clone(v)
	}
	return ""
}
