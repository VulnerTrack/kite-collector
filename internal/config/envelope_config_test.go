package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func envelopeConfig(enc EncryptionConfig) *Config {
	c := &Config{}
	c.Streaming.OTLP.Endpoint = "https://otel.example.com"
	c.Streaming.OTLP.Encryption = enc
	return c
}

// TestEnvelope_DisabledIsInert: a checkout with no encryption block, or
// with enabled:false and stray fields, validates and sends plain OTLP.
func TestEnvelope_DisabledIsInert(t *testing.T) {
	require.NoError(t, envelopeConfig(EncryptionConfig{}).validate())
	require.NoError(t, envelopeConfig(EncryptionConfig{
		Enabled:   false,
		Algorithm: "RSA-OAEP", // ignored while disabled
	}).validate())
}

// TestEnvelope_EnabledRequiresReceiverKeyURL: turning encryption on without
// saying whose key to encrypt to cannot work, so it fails at load rather
// than at the first batch.
func TestEnvelope_EnabledRequiresReceiverKeyURL(t *testing.T) {
	err := envelopeConfig(EncryptionConfig{Enabled: true}).validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "streaming.otlp.encryption.server_jwk_url is required")

	for _, bad := range []string{"not a url", "ftp://keys.example.com/jwks.json", "/relative/jwks.json"} {
		err := envelopeConfig(EncryptionConfig{Enabled: true, ServerJWKURL: bad}).validate()
		require.Error(t, err, bad)
		assert.Contains(t, err.Error(), "must be an http(s) URL", bad)
	}

	require.NoError(t, envelopeConfig(EncryptionConfig{
		Enabled:      true,
		ServerJWKURL: "https://otel.example.com/.well-known/jwks.json",
	}).validate())
}

// TestEnvelope_RejectsUnsupportedSuite: config that names a different JOSE
// suite is refused instead of being silently downgraded to the one we
// implement.
func TestEnvelope_RejectsUnsupportedSuite(t *testing.T) {
	base := EncryptionConfig{Enabled: true, ServerJWKURL: "https://k.example.com/jwks.json"}

	ok := base
	ok.Algorithm = EnvelopeKeyAlgorithm
	ok.ContentEncryption = EnvelopeContentEncryption
	require.NoError(t, envelopeConfig(ok).validate())

	badAlg := base
	badAlg.Algorithm = "RSA-OAEP-256"
	err := envelopeConfig(badAlg).validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "algorithm")

	badEnc := base
	badEnc.ContentEncryption = "A128CBC-HS256"
	err = envelopeConfig(badEnc).validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "content_encryption")
}

// TestEnvelope_EndpointsValidatedToo: the RFC-0072 endpoints[] lane shares
// the block and the same rules.
func TestEnvelope_EndpointsValidatedToo(t *testing.T) {
	c := &Config{}
	c.Endpoints = []EndpointConfig{{
		Name:       "fleet",
		Address:    "fleet.example.com:443",
		Encryption: EncryptionConfig{Enabled: true},
	}}
	err := c.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endpoints[0].encryption.server_jwk_url")
}

func signingConfig(sig SigningConfig, enc EncryptionConfig) *Config {
	c := envelopeConfig(enc)
	c.Streaming.OTLP.Signing = sig
	return c
}

// TestSigning_StandaloneIsValid: signing needs nothing but a credential,
// which is why it can ship on before the platform can decrypt anything.
func TestSigning_StandaloneIsValid(t *testing.T) {
	require.NoError(t, signingConfig(SigningConfig{Enabled: true}, EncryptionConfig{}).validate())
	require.NoError(t, signingConfig(SigningConfig{Enabled: true, OmitCertificateChain: true}, EncryptionConfig{}).validate())
	require.NoError(t, signingConfig(SigningConfig{}, EncryptionConfig{}).validate())
}

// TestSigning_RejectsDoubleProtection: the envelope already signs its
// inner payload. Enabling both would produce two signatures meaning two
// different things, so the config is refused instead of one silently
// winning.
func TestSigning_RejectsDoubleProtection(t *testing.T) {
	err := signingConfig(
		SigningConfig{Enabled: true},
		EncryptionConfig{Enabled: true, ServerJWKURL: "https://otel.example.com/.well-known/jwks.json"},
	).validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
	assert.Contains(t, err.Error(), "streaming.otlp.signing.enabled")
	assert.Contains(t, err.Error(), "streaming.otlp.encryption.enabled")
}

// A disabled signing block never conflicts, so an operator can leave it in
// the file while running the envelope.
func TestSigning_DisabledDoesNotConflict(t *testing.T) {
	require.NoError(t, signingConfig(
		SigningConfig{Enabled: false, OmitCertificateChain: true},
		EncryptionConfig{Enabled: true, ServerJWKURL: "https://otel.example.com/.well-known/jwks.json"},
	).validate())
}

// A mapstructure tag typo is invisible at compile time and silently drops
// the value — which here would mean an operator turns signing on and gets
// unsigned telemetry. Decode the real YAML shape rather than trusting the
// struct.
func TestLoad_DecodesOTLPSigningKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kite-collector.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
streaming:
  otlp:
    endpoint: https://otel.example.com
    tls:
      enabled: true
      cert_file: /var/lib/kite-collector/agent.pem
      key_file: /var/lib/kite-collector/agent-key.pem
    signing:
      enabled: true
      omit_certificate_chain: true
`), 0o600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.True(t, cfg.Streaming.OTLP.Signing.Enabled)
	assert.True(t, cfg.Streaming.OTLP.Signing.OmitCertificateChain)
}
