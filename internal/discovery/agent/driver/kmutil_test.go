package driver

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKmutilShowloaded_RealishOutput(t *testing.T) {
	t.Parallel()

	raw := "Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>\n" +
		"    1  131 0xffffff8000200000 0x6e1000   0x6e1000   __kernel__ (24.0.0)\n" +
		"   84    0 0xffffff7f81234000 0x10000    0x10000    com.apple.driver.AppleAHCIPort (3.4.4)\n" +
		"   95    1 0xffffff7f8abcd000 0x80000    0x80000    com.nvidia.GeForce (535.183.06)\n"

	res := ParseKmutilShowloaded(raw)
	require.Empty(t, res.Errs)
	require.Len(t, res.Drivers, 3)

	apple := findByName(res.Drivers, "com.apple.driver.AppleAHCIPort")
	require.NotNil(t, apple)
	assert.Equal(t, "3.4.4", apple.Version)
	assert.Equal(t, "Apple", apple.Vendor)

	nvidia := findByName(res.Drivers, "com.nvidia.GeForce")
	require.NotNil(t, nvidia)
	assert.Equal(t, "535.183.06", nvidia.Version)
	assert.Equal(t, "Nvidia", nvidia.Vendor)
}

func TestParseKmutilShowloaded_MalformedLineCaptured(t *testing.T) {
	t.Parallel()
	raw := "broken-line\n   1   2 0xff 0xff 0xff com.apple.foo (1.0)\n"
	res := ParseKmutilShowloaded(raw)
	require.Len(t, res.Errs, 1)
	require.Len(t, res.Drivers, 1)
}

func TestVendorFromBundleID_Cases(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "Apple", vendorFromBundleID("com.apple.driver.AppleAHCIPort"))
	assert.Equal(t, "Nvidia", vendorFromBundleID("com.nvidia.GeForce"))
	assert.Empty(t, vendorFromBundleID("flat"))
}

func TestKmutilShowloaded_NotAvailableOnLinux(t *testing.T) {
	t.Parallel()
	c := &KmutilShowloaded{binary: filepath.Join(t.TempDir(), "no-kmutil")}
	// On non-Darwin runners Available() short-circuits on runtime.GOOS check.
	assert.False(t, c.Available())
}

func TestKmutilShowloaded_Name(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "darwin-kmutil-showloaded", NewKmutilShowloaded().Name())
}

func findByName(drivers []LoadedDriver, name string) *LoadedDriver {
	for i := range drivers {
		if drivers[i].Name == name {
			return &drivers[i]
		}
	}
	return nil
}
