package connectorkit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureLogs swaps the default slog logger for a JSON buffer for the
// duration of the test and returns a fetcher for the decoded records.
func captureLogs(t *testing.T) func() []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return func() []map[string]any {
		var recs []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) == nil {
				recs = append(recs, m)
			}
		}
		return recs
	}
}

func logsWithCode(recs []map[string]any, code LogCode) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if r["code"] == string(code) {
			out = append(out, r)
		}
	}
	return out
}

// Happy path: a cleanly-injected secret resolves with zero diagnostics.
func TestEnvResolution_HappyPath_NoWarnings(t *testing.T) {
	logs := captureLogs(t)
	t.Setenv("TEST_KITE_CLEAN_PW", "s3cret-value")

	c := LoadCredentials(map[string]any{"password_env": "TEST_KITE_CLEAN_PW"})

	assert.Equal(t, "s3cret-value", c.Password)
	assert.Empty(t, logsWithCode(logs(), LogCodeEnvUnresolved))
	assert.Empty(t, logsWithCode(logs(), LogCodeEnvWhitespace))
}

// Warning state: the deployment forgot to inject the declared variable.
func TestEnvResolution_UnsetVarWarnsUnresolved(t *testing.T) {
	logs := captureLogs(t)

	c := LoadCredentials(map[string]any{"password_env": "TEST_KITE_NEVER_SET_PW"})

	assert.Empty(t, c.Password, "unresolved keeps the graceful missing-credential skip")
	warns := logsWithCode(logs(), LogCodeEnvUnresolved)
	require.Len(t, warns, 1)
	assert.Equal(t, "unset", warns[0]["reason"])
	assert.Equal(t, "password", warns[0]["field"])
	assert.Equal(t, "TEST_KITE_NEVER_SET_PW", warns[0]["env_var"])
}

// Warning state: the variable exists but is empty — a different injection
// bug than unset (e.g. an empty secret-store entry), so the reason differs.
func TestEnvResolution_SetButEmptyWarnsWithDistinctReason(t *testing.T) {
	logs := captureLogs(t)
	t.Setenv("TEST_KITE_EMPTY_PW", "")

	c := LoadCredentials(map[string]any{"password_env": "TEST_KITE_EMPTY_PW"})

	assert.Empty(t, c.Password)
	warns := logsWithCode(logs(), LogCodeEnvUnresolved)
	require.Len(t, warns, 1)
	assert.Equal(t, "set_but_empty", warns[0]["reason"])
}

// Warning state: the classic trailing-newline-from-file bug. The value is
// used verbatim (trimming a secret is not safe) but the warning names the
// injection pipeline as the suspect for the coming auth failure.
func TestEnvResolution_TrailingNewlineWarnsAndKeepsValueVerbatim(t *testing.T) {
	logs := captureLogs(t)
	t.Setenv("TEST_KITE_NL_PW", "s3cret\n")

	c := LoadCredentials(map[string]any{"password_env": "TEST_KITE_NL_PW"})

	assert.Equal(t, "s3cret\n", c.Password, "value must be verbatim, never trimmed")
	warns := logsWithCode(logs(), LogCodeEnvWhitespace)
	require.Len(t, warns, 1)
	assert.Equal(t, "TEST_KITE_NL_PW", warns[0]["env_var"])
	for _, r := range warns {
		for _, v := range r {
			if s, ok := v.(string); ok {
				assert.NotContains(t, s, "s3cret", "warning must never carry the value")
			}
		}
	}
}

// Edge: interior whitespace is legitimate secret content — no warning.
func TestEnvResolution_InteriorWhitespaceNoWarning(t *testing.T) {
	logs := captureLogs(t)
	t.Setenv("TEST_KITE_SPACE_PW", "pass word")

	c := LoadCredentials(map[string]any{"password_env": "TEST_KITE_SPACE_PW"})

	assert.Equal(t, "pass word", c.Password)
	assert.Empty(t, logsWithCode(logs(), LogCodeEnvWhitespace))
}

// Edge: a whitespace-only value is technically non-empty, so it resolves
// verbatim with the whitespace warning — not the unresolved one.
func TestEnvResolution_WhitespaceOnlyValueResolvesWithWarning(t *testing.T) {
	logs := captureLogs(t)
	t.Setenv("TEST_KITE_WS_PW", "  ")

	c := LoadCredentials(map[string]any{"password_env": "TEST_KITE_WS_PW"})

	assert.Equal(t, "  ", c.Password)
	assert.Len(t, logsWithCode(logs(), LogCodeEnvWhitespace), 1)
	assert.Empty(t, logsWithCode(logs(), LogCodeEnvUnresolved))
}

// Edge: when the direct value wins precedence, the companion is never
// consulted — no misleading unresolved warning for a var that is irrelevant.
func TestEnvResolution_DirectValueSkipsResolutionAndWarnings(t *testing.T) {
	logs := captureLogs(t)

	c := LoadCredentials(map[string]any{
		"password":     "direct",
		"password_env": "TEST_KITE_NEVER_SET_PW",
	})

	assert.Equal(t, "direct", c.Password)
	assert.Empty(t, logsWithCode(logs(), LogCodeEnvUnresolved))
}

// Edge: a non-string companion value (YAML type mistake that bypassed
// config validation, e.g. a hand-built map) is ignored without panic or
// spurious warnings.
func TestEnvResolution_NonStringCompanionIgnored(t *testing.T) {
	logs := captureLogs(t)

	c := LoadCredentials(map[string]any{"password_env": 12345})

	assert.Empty(t, c.Password)
	assert.Empty(t, logsWithCode(logs(), LogCodeEnvUnresolved))
}
