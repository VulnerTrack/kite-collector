package config

import (
	"os"
	"path/filepath"
	"testing"
)

// api.addr controls the agent's REST API listen address: defaulted, YAML-set,
// env-overridable (KITE_API_ADDR), and empty-in-YAML to disable the server.
func TestLoad_APIAddrDefault(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.API.Addr != ":8080" {
		t.Fatalf("default api.addr = %q, want %q", cfg.API.Addr, ":8080")
	}
}

func TestLoad_APIAddrEnvOverride(t *testing.T) {
	t.Setenv("KITE_API_ADDR", "127.0.0.1:9091")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.API.Addr != "127.0.0.1:9091" {
		t.Fatalf("api.addr with KITE_API_ADDR = %q, want %q", cfg.API.Addr, "127.0.0.1:9091")
	}
}

func TestLoad_APIAddrEmptyInYAMLDisables(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("api:\n  addr: \"\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.API.Addr != "" {
		t.Fatalf("api.addr from empty YAML value = %q, want empty (disabled)", cfg.API.Addr)
	}
}
