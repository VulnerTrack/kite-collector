package connectorkit

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// RFC-0153 R2: secret fields resolve through their "<key>_env" companion at
// LoadCredentials time, under the same clone-and-zero contract as direct
// values.

func TestLoadCredentials_EnvIndirection(t *testing.T) {
	t.Setenv("TEST_KITE_PW", "env-pw")
	t.Setenv("TEST_KITE_TOKEN", "env-tok")
	t.Setenv("TEST_KITE_KEY", "env-key")
	t.Setenv("TEST_KITE_CS", "env-cs")

	c := LoadCredentials(map[string]any{
		"password_env":      "TEST_KITE_PW",
		"token_env":         "TEST_KITE_TOKEN",
		"api_key_env":       "TEST_KITE_KEY",
		"client_secret_env": "TEST_KITE_CS",
	})
	assert.Equal(t, "env-pw", c.Password)
	assert.Equal(t, "env-tok", c.Token)
	assert.Equal(t, "env-key", c.APIKey)
	assert.Equal(t, "env-cs", c.ClientSecret)
}

func TestLoadCredentials_DirectValueWinsOverEnvIndirection(t *testing.T) {
	t.Setenv("TEST_KITE_PW", "env-pw")
	c := LoadCredentials(map[string]any{
		"password":     "direct-pw",
		"password_env": "TEST_KITE_PW",
	})
	assert.Equal(t, "direct-pw", c.Password, "direct value has precedence (R3)")
}

func TestLoadCredentials_UnsetEnvVarResolvesEmpty(t *testing.T) {
	c := LoadCredentials(map[string]any{
		"password_env": "TEST_KITE_DEFINITELY_UNSET_VAR",
	})
	assert.Empty(t, c.Password, "unset var keeps the graceful missing-credential skip")
}

func TestLoadCredentials_EnvIndirectionAWSFields(t *testing.T) {
	// The companion lookup is map-driven, so the AWS-shaped secret fields
	// (RFC-0137) get indirection for free.
	t.Setenv("TEST_KITE_SAK", "env-sak")
	t.Setenv("TEST_KITE_ST", "env-st")
	c := LoadCredentials(map[string]any{
		"secret_access_key_env": "TEST_KITE_SAK",
		"session_token_env":     "TEST_KITE_ST",
	})
	assert.Equal(t, "env-sak", c.SecretAccessKey)
	assert.Equal(t, "env-st", c.SessionToken)
}

func TestZero_SafeOnEnvResolvedValues(t *testing.T) {
	// Zero must not fault on env-resolved strings (they are cloned off the
	// runtime's cached environment copy) and must not corrupt subsequent
	// os.Getenv reads of the same variable.
	t.Setenv("TEST_KITE_PW", "env-pw")
	c := LoadCredentials(map[string]any{"password_env": "TEST_KITE_PW"})
	c.Zero()
	assert.Empty(t, c.Password)
	assert.Equal(t, "env-pw", os.Getenv("TEST_KITE_PW"),
		"zeroing the clone must not scribble on the cached env value")
}

func TestLoadCredentials_NonSecretFieldsHaveNoIndirection(t *testing.T) {
	// Only secret fields consult companions: a username_env key is ignored
	// by design (usernames are not secret material).
	t.Setenv("TEST_KITE_USER", "env-user")
	c := LoadCredentials(map[string]any{"username_env": "TEST_KITE_USER"})
	assert.Empty(t, c.Username)
}
