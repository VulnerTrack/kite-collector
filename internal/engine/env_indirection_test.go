package engine

import (
	"testing"

	"github.com/vulnertrack/kite-collector/internal/config"
)

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
