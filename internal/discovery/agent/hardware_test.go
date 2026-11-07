package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHardwareProductFacts(t *testing.T) {
	root := t.TempDir()
	for name, value := range map[string]string{
		"sys_vendor": "HP\n", "product_name": "HP 255 G10\n",
		"product_version": "To Be Filled By O.E.M.\n", "product_serial": "private-serial",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(value), 0o600))
	}
	require.Equal(t, map[string]string{
		"hardware_manufacturer": "HP", "hardware_model": "HP 255 G10",
	}, readHardwareTags(root))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sys_vendor"), []byte(strings.Repeat("x", 1025)), 0o600))
	require.NotContains(t, readHardwareTags(root), "hardware_manufacturer")
	require.Empty(t, readHardwareTags(filepath.Join(root, "missing")))
}
