package driver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProcModules_RealFixture(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("testdata", "proc_modules.txt"))
	require.NoError(t, err)

	res := ParseProcModules(string(raw))
	require.NotNil(t, res)
	require.Empty(t, res.Errs, "fixture is well-formed")
	require.Len(t, res.Drivers, 9)

	byName := map[string]LoadedDriver{}
	for _, d := range res.Drivers {
		byName[d.Name] = d
	}

	nvidia := byName["nvidia"]
	assert.Equal(t, "Live", nvidia.State)
	assert.Equal(t, "live", nvidia.StartMode)
	assert.Equal(t, FrameworkLinuxModule, nvidia.DriverFramework)
	assert.ElementsMatch(t, []string{"nvidia_drm", "nvidia_modeset"}, nvidia.Dependencies)

	overlay := byName["overlay"]
	assert.Empty(t, overlay.Dependencies, "used_by '-' yields empty dependency list")

	zfs := byName["zfs"]
	assert.Equal(t, "Live", zfs.State)
	assert.Empty(t, zfs.Dependencies)
}

func TestParseProcModules_MalformedLineRecorded(t *testing.T) {
	t.Parallel()

	raw := "nvidia 56807424 53 - Live 0x000000\nbroken_line_too_short\n"
	res := ParseProcModules(raw)
	assert.Len(t, res.Drivers, 1)
	assert.Len(t, res.Errs, 1)
	assert.Equal(t, 2, res.Errs[0].Line)
	assert.Equal(t, "broken_line_too_short", res.Errs[0].RawLine)
}

func TestParseProcModules_EmptyInput(t *testing.T) {
	t.Parallel()
	res := ParseProcModules("")
	require.NotNil(t, res)
	assert.Empty(t, res.Drivers)
	assert.Empty(t, res.Errs)
}

func TestParseProcModules_DeterministicOrder(t *testing.T) {
	t.Parallel()
	raw := "zfs 1 0 - Live 0\noverlay 1 0 - Live 0\nnvidia 1 0 - Live 0\n"
	res := ParseProcModules(raw)
	require.Len(t, res.Drivers, 3)
	assert.Equal(t, "nvidia", res.Drivers[0].Name)
	assert.Equal(t, "overlay", res.Drivers[1].Name)
	assert.Equal(t, "zfs", res.Drivers[2].Name)
}

func TestProcModules_NotAvailable_OnMissingFile(t *testing.T) {
	t.Parallel()
	c := &ProcModules{procPath: filepath.Join(t.TempDir(), "absent")}
	assert.False(t, c.Available())
}

func TestProcModules_Name(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "linux-procmodules", NewProcModules().Name())
}

func TestSignatureStateFor_Cases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		taint  []string
		name   string
		want   string
		driver LoadedDriver
	}{
		{nil, "signed module, clean kernel", SignatureValid, LoadedDriver{Signer: "kernel-key"}},
		{nil, "unsigned module, clean kernel", SignatureUnknown, LoadedDriver{}},
		{[]string{"E"}, "E flag set, signer present", SignatureValid, LoadedDriver{Signer: "x"}},
		{[]string{"E"}, "E flag set, no signer", SignatureUnsigned, LoadedDriver{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, signatureStateFor(tc.driver, tc.taint))
		})
	}
}
