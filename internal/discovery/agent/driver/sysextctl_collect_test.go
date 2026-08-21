package driver

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
)

// fakeSysextctlScript mimics `systemextensionsctl list` on macOS 13+:
// a totals line, a section header, and tab-separated extension rows.
const fakeSysextctlScript = `if [ "$1" != "list" ]; then
  echo "systemextensionsctl: unknown subcommand" >&2
  exit 1
fi
printf '2 extension(s)\n'
printf -- '--- com.apple.system_extension.network_extension\n'
printf '*\t*\tX9GH5KKB3P\tcom.example.vpn.extension(2.4.1)\tVPN\t[activated enabled]\n'
printf -- '-\t-\tQ2XW7ZZ9AB\tcom.example.dlp.agent(0.9.0)\tDLP\t[terminated waiting to uninstall]\n'
exit 0
`

func TestSysextctlCollect_HappyPath(t *testing.T) {
	bin := writeFakeTool(t, "systemextensionsctl", fakeSysextctlScript)
	collected := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	s := NewSystemExtensionsCtl()
	s.binary = bin
	s.now = func() time.Time { return collected }

	res, err := s.Collect(context.Background())
	require.NoError(t, err)
	require.Empty(t, res.Errs)
	require.Len(t, res.Drivers, 2)

	vpn := findByName(res.Drivers, "com.example.vpn.extension")
	require.NotNil(t, vpn)
	assert.Equal(t, "2.4.1", vpn.Version)
	assert.Equal(t, "X9GH5KKB3P", vpn.Vendor)
	assert.Equal(t, "X9GH5KKB3P", vpn.Signer)
	assert.Equal(t, SignatureValid, vpn.SignatureState)
	assert.Equal(t, "Live", vpn.State)
	assert.Equal(t, collected, vpn.CollectedAt)
	assert.Equal(t, runtime.GOARCH, vpn.Architecture)
	assert.Equal(t, FrameworkDEXT, vpn.DriverFramework)
	assert.Equal(t,
		software.BuildCPE23WithTargetSW("X9GH5KKB3P", "com.example.vpn.extension", "2.4.1", "macos"),
		vpn.CPE23)

	dlp := findByName(res.Drivers, "com.example.dlp.agent")
	require.NotNil(t, dlp)
	assert.Equal(t, "Inactive", dlp.State, "an inactive extension must not report Live")
	assert.Equal(t, SignatureUnknown, dlp.SignatureState)
}

func TestSysextctlCollect_NonZeroExitSurfacesError(t *testing.T) {
	bin := writeFakeTool(t, "systemextensionsctl", `echo "operation not permitted" >&2
exit 1
`)
	s := NewSystemExtensionsCtl()
	s.binary = bin

	res, err := s.Collect(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "systemextensionsctl list: ")
	assert.Contains(t, err.Error(), "operation not permitted")
}

func TestSysextctlCollect_MissingBinary(t *testing.T) {
	t.Parallel()

	s := NewSystemExtensionsCtl()
	s.binary = filepath.Join(t.TempDir(), "no-sysextctl")

	res, err := s.Collect(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
}
