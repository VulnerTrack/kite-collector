package driver

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleKldstatOutput = `Id Refs Address                Size Name
 1   77 0xffffffff80200000 1c5e3a8 kernel
 2    1 0xffffffff81e60000   2e8b8 ums.ko
 3    1 0xffffffff81e90000   1a4f8 nvidia.ko
 4    1 0xffffffff81eb0000    8a40 zfs.ko
 5    1 0xffffffff81ec0000    1234 vboxdrv.ko
`

func TestParseKldstat_ExtractsModuleNames(t *testing.T) {
	t.Parallel()
	res := ParseKldstat(sampleKldstatOutput)
	require.Empty(t, res.Errs)
	require.Len(t, res.Drivers, 5)

	names := make([]string, 0, len(res.Drivers))
	for _, d := range res.Drivers {
		names = append(names, d.Name)
	}
	assert.ElementsMatch(t, []string{
		"kernel", "ums.ko", "nvidia.ko", "zfs.ko", "vboxdrv.ko",
	}, names)
	for _, d := range res.Drivers {
		assert.Equal(t, FrameworkKLD, d.DriverFramework)
		assert.Equal(t, "Live", d.State)
		assert.Equal(t, "live", d.StartMode)
	}
}

func TestParseKldstat_SkipsContainsModulesBlock(t *testing.T) {
	t.Parallel()
	raw := `Id Refs Address                Size Name
 1   77 0xffffffff80200000 1c5e3a8 kernel
Contains modules:
        Id Name
         1 rootbus
         2 nexus
 2    1 0xffffffff81e60000   2e8b8 ums.ko
`
	res := ParseKldstat(raw)
	require.Empty(t, res.Errs)
	require.Len(t, res.Drivers, 2)
}

func TestParseKldstat_RecordsErrorOnNonNumericID(t *testing.T) {
	t.Parallel()
	raw := `XX 1 0xff 1234 garbage.ko
`
	res := ParseKldstat(raw)
	require.Len(t, res.Errs, 1)
	assert.Equal(t, 1, res.Errs[0].Line)
	assert.Empty(t, res.Drivers)
}

func TestParseKldstat_EmptyInputProducesNothing(t *testing.T) {
	t.Parallel()
	res := ParseKldstat("")
	assert.Empty(t, res.Drivers)
	assert.Empty(t, res.Errs)
}

func TestKldstat_NotAvailableOnLinux(t *testing.T) {
	t.Parallel()
	k := &Kldstat{binary: filepath.Join(t.TempDir(), "no-kldstat")}
	assert.False(t, k.Available())
}

func TestKldstat_Name(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "freebsd-kldstat", NewKldstat().Name())
}

func TestIsAllDigits_Cases(t *testing.T) {
	t.Parallel()
	assert.True(t, isAllDigits("12345"))
	assert.True(t, isAllDigits("0"))
	assert.False(t, isAllDigits(""))
	assert.False(t, isAllDigits("12a"))
	assert.False(t, isAllDigits("-1"))
	assert.False(t, isAllDigits("0xff"))
}
