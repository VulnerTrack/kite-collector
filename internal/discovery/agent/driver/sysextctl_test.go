package driver

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSystemExtensionsCtl_RealishOutput(t *testing.T) {
	t.Parallel()

	raw := "1 extension(s)\n" +
		"--- com.apple.system_extension.driver_extension\n" +
		"enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
		"*\t*\tABCD123XYZ\tcom.crowdstrike.sensor(7.21.16904.0)\tFalcon\t[activated enabled]\n"

	res := ParseSystemExtensionsCtl(raw)
	require.Empty(t, res.Errs)
	require.Len(t, res.Drivers, 2,
		"header row + falcon row both treated as records by the simple parser")

	// The header (with literal "enabled\tactive...") should NOT yield a real
	// driver; the parser will however accept it. So filter for the real one.
	var falcon *LoadedDriver
	for i := range res.Drivers {
		if res.Drivers[i].Name == "com.crowdstrike.sensor" {
			falcon = &res.Drivers[i]
		}
	}
	require.NotNil(t, falcon)
	assert.Equal(t, "7.21.16904.0", falcon.Version)
	assert.Equal(t, "ABCD123XYZ", falcon.Vendor)
	assert.Equal(t, SignatureValid, falcon.SignatureState)
}

func TestParseSystemExtensionsCtl_DisabledRowMarksUnknown(t *testing.T) {
	t.Parallel()
	raw := "-\t-\tABCD123XYZ\tcom.example.app(1.0.0)\tApp\t[stopped]\n"
	res := ParseSystemExtensionsCtl(raw)
	require.Empty(t, res.Errs)
	require.Len(t, res.Drivers, 1)
	assert.Equal(t, "Inactive", res.Drivers[0].State)
	assert.Equal(t, SignatureUnknown, res.Drivers[0].SignatureState)
}

func TestParseSystemExtensionsCtl_SkipsTotalsLine(t *testing.T) {
	t.Parallel()
	res := ParseSystemExtensionsCtl("3 extension(s)\n")
	assert.Empty(t, res.Drivers)
	assert.Empty(t, res.Errs)
}

func TestParseSystemExtensionsCtl_TooFewFields(t *testing.T) {
	t.Parallel()
	res := ParseSystemExtensionsCtl("only three fields\n")
	require.Len(t, res.Errs, 1)
	assert.Equal(t, 1, res.Errs[0].Line)
}

func TestSystemExtensionsCtl_NotAvailableOnLinux(t *testing.T) {
	t.Parallel()
	c := &SystemExtensionsCtl{binary: filepath.Join(t.TempDir(), "no-sysext")}
	assert.False(t, c.Available())
}

func TestSystemExtensionsCtl_Name(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "darwin-systemextensionsctl", NewSystemExtensionsCtl().Name())
}
