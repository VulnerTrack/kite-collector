package engine

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/vulnertrack/kite-collector/internal/config"
)

// captureEngineLogs swaps the default slog logger for a JSON buffer for the
// duration of the test and returns a fetcher for records carrying code.
func captureEngineLogs(t *testing.T) func(code LogCode) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return func(code LogCode) []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) == nil && m["code"] == string(code) {
				out = append(out, m)
			}
		}
		return out
	}
}

// RFC-0153 R3 precedence: inline YAML value > declared *_env indirection >
// legacy well-known env var. These tests pin the total order over the
// extracted map builder.

func TestBuildSourceConfigMap_InlineWinsOverLegacyEnv(t *testing.T) {
	t.Setenv("KITE_JAMF_PASSWORD", "from-legacy-env")
	m := buildSourceConfigMap("jamf", config.SourceConfig{Password: "inline-pw"})
	if got := m["password"]; got != "inline-pw" {
		t.Errorf("password = %v, want inline-pw (inline wins)", got)
	}
}

func TestBuildSourceConfigMap_DeclaredSuppressesLegacyOverlay(t *testing.T) {
	t.Setenv("KITE_JAMF_PASSWORD", "from-legacy-env")
	m := buildSourceConfigMap("jamf", config.SourceConfig{PasswordEnv: "PROD_JAMF_PW"})
	// Even though the declared var is unset, explicit intent wins: the
	// legacy overlay must not fill the field (RFC-0153 R3).
	if got := m["password"]; got != "" {
		t.Errorf("password = %v, want empty (declared companion suppresses legacy)", got)
	}
	if got := m["password_env"]; got != "PROD_JAMF_PW" {
		t.Errorf("password_env = %v, want PROD_JAMF_PW", got)
	}
}

func TestBuildSourceConfigMap_LegacyFallbackWhenUndeclared(t *testing.T) {
	t.Setenv("KITE_JAMF_PASSWORD", "from-legacy-env")
	m := buildSourceConfigMap("jamf", config.SourceConfig{})
	if got := m["password"]; got != "from-legacy-env" {
		t.Errorf("password = %v, want from-legacy-env (legacy fallback preserved, R8)", got)
	}
}

func TestBuildSourceConfigMap_LegacyOverlayNonSecretUnaffected(t *testing.T) {
	// Non-secret keys have no *_env companion; the overlay behavior for
	// them is bit-for-bit the pre-RFC-0153 one.
	t.Setenv("KITE_JAMF_API_URL", "https://jamf.example.com")
	m := buildSourceConfigMap("jamf", config.SourceConfig{PasswordEnv: "PROD_JAMF_PW"})
	if got := m["api_url"]; got != "https://jamf.example.com" {
		t.Errorf("api_url = %v, want legacy env value", got)
	}
}

func TestBuildSourceConfigMap_CompanionKeysAlwaysPresent(t *testing.T) {
	m := buildSourceConfigMap("netbox", config.SourceConfig{
		TokenEnv:        "T",
		APIKeyEnv:       "K",
		ClientSecretEnv: "S",
	})
	for key, want := range map[string]string{
		"password_env": "", "token_env": "T", "api_key_env": "K", "client_secret_env": "S",
	} {
		if got := m[key]; got != want {
			t.Errorf("%s = %v, want %q", key, got, want)
		}
	}
}

// Warning state: a declared companion that does not resolve while the legacy
// var it suppresses IS present — the one precedence corner an operator
// cannot diagnose from behavior alone.
func TestBuildSourceConfigMap_WarnsWhenDeclaredSuppressesPresentLegacy(t *testing.T) {
	logs := captureEngineLogs(t)
	t.Setenv("KITE_JAMF_PASSWORD", "from-legacy-env")
	// PROD_JAMF_PW is deliberately unset.

	m := buildSourceConfigMap("jamf", config.SourceConfig{PasswordEnv: "PROD_JAMF_PW"})

	if got := m["password"]; got != "" {
		t.Errorf("password = %v, want empty", got)
	}
	warns := logs(LogCodeSourceDeclaredEnvSuppressesLegacy)
	if len(warns) != 1 {
		t.Fatalf("suppression warnings = %d, want 1", len(warns))
	}
	if warns[0]["declared_env_var"] != "PROD_JAMF_PW" || warns[0]["suppressed_env_var"] != "KITE_JAMF_PASSWORD" {
		t.Errorf("warning fields wrong: %v", warns[0])
	}
	for _, v := range warns[0] {
		if s, ok := v.(string); ok && strings.Contains(s, "from-legacy-env") {
			t.Errorf("warning leaks the legacy secret value: %v", warns[0])
		}
	}
}

// Happy path: a resolving declaration suppresses legacy silently — that is
// the documented precedence working as intended, not a diagnosable state.
func TestBuildSourceConfigMap_NoWarnWhenDeclaredResolves(t *testing.T) {
	logs := captureEngineLogs(t)
	t.Setenv("KITE_JAMF_PASSWORD", "from-legacy-env")
	t.Setenv("PROD_JAMF_PW", "from-declared")

	buildSourceConfigMap("jamf", config.SourceConfig{PasswordEnv: "PROD_JAMF_PW"})

	if warns := logs(LogCodeSourceDeclaredEnvSuppressesLegacy); len(warns) != 0 {
		t.Errorf("unexpected suppression warnings: %v", warns)
	}
}

// Edge: nothing was suppressed (legacy absent) — the unresolved declaration
// is connectorkit's warning to raise at load time, not the engine's.
func TestBuildSourceConfigMap_NoWarnWhenLegacyAbsent(t *testing.T) {
	logs := captureEngineLogs(t)

	buildSourceConfigMap("jamf", config.SourceConfig{PasswordEnv: "PROD_JAMF_PW"})

	if warns := logs(LogCodeSourceDeclaredEnvSuppressesLegacy); len(warns) != 0 {
		t.Errorf("unexpected suppression warnings: %v", warns)
	}
}

// RFC-0153 R9: only secret-bearing legacy names feed detection; identifiers
// like api_url and tenant_id must not.
func TestLegacySecretEnvNames(t *testing.T) {
	names := legacySecretEnvNames()
	set := make(map[string]bool, len(names))
	for i, n := range names {
		set[n] = true
		if i > 0 && names[i-1] >= n {
			t.Fatalf("names not sorted/deduplicated: %v", names)
		}
	}
	for _, want := range []string{
		"KITE_JAMF_PASSWORD",
		"KITE_NETBOX_TOKEN",
		"KITE_KANDJI_API_TOKEN",
		"KITE_INTUNE_CLIENT_SECRET",
		"KITE_WORKSPACEONE_API_KEY",
		// The LDAP default applies even when the YAML omits
		// bind_password_env, so it must be in the well-known set.
		"KITE_LDAP_BIND_PASSWORD",
	} {
		if !set[want] {
			t.Errorf("legacySecretEnvNames missing %s", want)
		}
	}
	for _, tooMuch := range []string{
		"KITE_JAMF_API_URL",
		"KITE_INTUNE_TENANT_ID",
		"KITE_SERVICENOW_TABLE",
		"KITE_LANSWEEPER_SITE_ID",
	} {
		if set[tooMuch] {
			t.Errorf("legacySecretEnvNames wrongly includes non-secret %s", tooMuch)
		}
	}
}
