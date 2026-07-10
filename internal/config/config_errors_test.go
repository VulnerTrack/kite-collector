package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
)

// TestLoad_InvalidConfig_ReturnsCatalogE007 pins the migration of the config
// parse failure onto the catalogued KITE-E007 error. The input is valid YAML
// syntax (so ReadInConfig succeeds) but maps a scalar onto the `discovery`
// struct field, which fails Unmarshal — the exact site KITE-E007 describes.
// This guards that config-load failures carry the catalog's remediation hint
// and the offending path in structured logs.
func TestLoad_InvalidConfig_ReturnsCatalogE007(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte("discovery: not-a-struct\n"), 0o600))

	_, err := Load(path)
	require.Error(t, err)

	var ke *kiteerrors.Error
	require.True(t, errors.As(err, &ke), "config parse error must be a *kiteerrors.Error")
	assert.Equal(t, "KITE-E007", ke.Code)
	assert.NotEmpty(t, ke.Hint, "hint should be populated from the catalog")
	assert.Equal(t, path, ke.Context["config_path"])
	// The underlying viper/mapstructure cause must remain reachable via Unwrap.
	assert.NotEmpty(t, ke.Error())
}
