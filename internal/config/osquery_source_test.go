package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A mapstructure tag typo is invisible at compile time and silently drops the
// value, so decode the real YAML shape rather than trusting the struct.
func TestLoad_DecodesOsquerySourceKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kite-collector.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
discovery:
  sources:
    osquery:
      enabled: true
      socket: /var/kite-osquery/kite-osquery.em
      yara_sigfile: /etc/osquery/yara/kite.yar
      yara_rules: |
        rule kite_canary { condition: true }
      yara_paths:
        - /usr/local/bin/*
        - /Applications/*
`), 0o600))

	cfg, err := Load(path)
	require.NoError(t, err)

	src, ok := cfg.Discovery.Sources["osquery"]
	require.True(t, ok, "the osquery source block must decode")
	assert.True(t, src.Enabled)
	assert.Equal(t, "/var/kite-osquery/kite-osquery.em", src.Socket)
	assert.Equal(t, "/etc/osquery/yara/kite.yar", src.YaraSigfile)
	assert.Contains(t, src.YaraRules, "kite_canary")
	assert.Equal(t, []string{"/usr/local/bin/*", "/Applications/*"}, src.YaraPaths)
}
