package config

import (
	"os"
	"path/filepath"
	"testing"
)

// RFC-0153 R1: the four *_env indirection fields unmarshal from YAML.
func TestLoad_SecretEnvIndirectionFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
discovery:
  sources:
    jamf:
      enabled: true
      api_url: https://jamf.example.com
      username: svc
      password_env: PROD_JAMF_PW
    netbox:
      enabled: true
      token_env: PROD_NETBOX_TOKEN
    kandji:
      enabled: true
      api_key_env: PROD_KANDJI_KEY
    intune:
      enabled: true
      client_secret_env: PROD_INTUNE_SECRET
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Discovery.Sources["jamf"].PasswordEnv; got != "PROD_JAMF_PW" {
		t.Errorf("PasswordEnv = %q, want PROD_JAMF_PW", got)
	}
	if got := cfg.Discovery.Sources["netbox"].TokenEnv; got != "PROD_NETBOX_TOKEN" {
		t.Errorf("TokenEnv = %q, want PROD_NETBOX_TOKEN", got)
	}
	if got := cfg.Discovery.Sources["kandji"].APIKeyEnv; got != "PROD_KANDJI_KEY" {
		t.Errorf("APIKeyEnv = %q, want PROD_KANDJI_KEY", got)
	}
	if got := cfg.Discovery.Sources["intune"].ClientSecretEnv; got != "PROD_INTUNE_SECRET" {
		t.Errorf("ClientSecretEnv = %q, want PROD_INTUNE_SECRET", got)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate on well-formed names: %v", err)
	}
}

// RFC-0153 R4: a secret value pasted into a *_env field is rejected at
// validation, so it can never persist via scan_runs.ScopeConfig.
func TestValidate_SecretEnvNameShape(t *testing.T) {
	cases := []struct {
		name    string
		envName string
		wantErr bool
	}{
		{"valid upper", "KITE_JAMF_PASSWORD", false},
		{"valid lower underscore", "_prod_pw", false},
		{"secret with equals", "hunter2=oops", true},
		{"secret with space", "my secret value", true},
		{"secret with symbols", "p@ssw0rd!", true},
		{"leading digit", "1PASSWORD", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Discovery: DiscoveryConfig{Sources: map[string]SourceConfig{
				"jamf": {PasswordEnv: tc.envName},
			}}}
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("Validate(%q) = nil, want error", tc.envName)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate(%q) = %v, want nil", tc.envName, err)
			}
		})
	}
}

// Each of the four fields is validated, not just password_env.
func TestValidate_AllFourEnvFieldsChecked(t *testing.T) {
	bad := "not a name"
	for _, src := range []SourceConfig{
		{PasswordEnv: bad},
		{TokenEnv: bad},
		{APIKeyEnv: bad},
		{ClientSecretEnv: bad},
	} {
		cfg := &Config{Discovery: DiscoveryConfig{Sources: map[string]SourceConfig{"x": src}}}
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate accepted malformed name in %+v", src)
		}
	}
}

// RFC-0153: DeclaredSecretEnvNames is the sorted, deduplicated union of the
// four *_env fields plus bind_password_env; the tunnel auth_token_env is
// excluded (delivered to a provider child by design).
func TestDeclaredSecretEnvNames(t *testing.T) {
	cfg := &Config{
		Discovery: DiscoveryConfig{Sources: map[string]SourceConfig{
			"jamf":   {PasswordEnv: "PROD_JAMF_PW"},
			"netbox": {TokenEnv: "SHARED_TOKEN"},
			"sccm":   {PasswordEnv: "SHARED_TOKEN"}, // duplicate name across sources
			"intune": {ClientSecretEnv: "INTUNE_SECRET", APIKeyEnv: ""},
			"ldap":   {BindPasswordEnv: "KITE_LDAP_BIND_PASSWORD"},
		}},
		Connectivity: ConnectivityConfig{Tunnel: TunnelConfig{
			AuthTokenEnv: "KITE_TUNNEL_AUTH_TOKEN",
		}},
	}
	got := cfg.DeclaredSecretEnvNames()
	want := []string{"INTUNE_SECRET", "KITE_LDAP_BIND_PASSWORD", "PROD_JAMF_PW", "SHARED_TOKEN"}
	if len(got) != len(want) {
		t.Fatalf("DeclaredSecretEnvNames = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("DeclaredSecretEnvNames = %v, want %v", got, want)
		}
	}
}

func TestDeclaredSecretEnvNames_EmptyConfig(t *testing.T) {
	cfg := &Config{}
	if got := cfg.DeclaredSecretEnvNames(); len(got) != 0 {
		t.Errorf("DeclaredSecretEnvNames on empty config = %v, want empty", got)
	}
}
