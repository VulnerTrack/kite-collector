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

// fakePnputilScript mimics `pnputil /enum-drivers /format CSV` output.
const fakePnputilScript = `case "$*" in
  */enum-drivers*) ;;
  *)
    echo "Unknown command" >&2
    exit 87
    ;;
esac
cat <<'EOF'
"Published Name","Original Name","Provider Name","Class Name","Class GUID","Driver Version","Signer Name"
"oem42.inf","nvgpu.inf","NVIDIA","Display adapters","{4d36e968-e325-11ce-bfc1-08002be10318}","31.0.15.3623","Microsoft Windows Hardware Compatibility Publisher"
"oem7.inf","rtwlan.inf","Realtek","Network adapters","{4d36e972-e325-11ce-bfc1-08002be10318}","1024.30.701.2021",""
EOF
exit 0
`

func TestPnPUtilCollect_HappyPath(t *testing.T) {
	bin := writeFakeTool(t, "pnputil", fakePnputilScript)
	collected := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	p := NewPnPUtilDrivers()
	p.pnputilPath = bin
	p.now = func() time.Time { return collected }

	res, err := p.Collect(context.Background())
	require.NoError(t, err)
	require.Empty(t, res.Errs)
	require.Len(t, res.Drivers, 2)

	nv := findByName(res.Drivers, "nvgpu.inf")
	require.NotNil(t, nv)
	assert.Equal(t, "nvgpu.inf", nv.DisplayName)
	assert.Equal(t, "oem42.inf", nv.Path, "published name lands in Path")
	assert.Equal(t, "NVIDIA", nv.Vendor)
	assert.Equal(t, "31.0.15.3623", nv.Version)
	assert.Equal(t, "Display adapters", nv.Description)
	assert.Equal(t, FrameworkWDM, nv.DriverFramework)
	assert.Equal(t, SignatureValid, nv.SignatureState)
	assert.Equal(t, "Microsoft Windows Hardware Compatibility Publisher", nv.Signer)
	assert.Equal(t, collected, nv.CollectedAt)
	assert.Equal(t, runtime.GOARCH, nv.Architecture)
	assert.Equal(t,
		software.BuildCPE23WithTargetSW("NVIDIA", "nvgpu.inf", "31.0.15.3623", "windows"),
		nv.CPE23)

	rt := findByName(res.Drivers, "rtwlan.inf")
	require.NotNil(t, rt)
	assert.Equal(t, SignatureUnknown, rt.SignatureState,
		"a row with an empty Signer Name must be classified unknown")
	assert.Empty(t, rt.Signer)
}

func TestPnPUtilCollect_DefaultNowStampsCollectedAt(t *testing.T) {
	bin := writeFakeTool(t, "pnputil", fakePnputilScript)
	p := NewPnPUtilDrivers() // keep the constructor's default clock
	p.pnputilPath = bin

	before := time.Now().UTC()
	res, err := p.Collect(context.Background())
	require.NoError(t, err)
	after := time.Now().UTC()

	require.NotEmpty(t, res.Drivers)
	got := res.Drivers[0].CollectedAt
	assert.False(t, got.Before(before))
	assert.False(t, got.After(after))
}

func TestPnPUtilCollect_NonZeroExitSurfacesError(t *testing.T) {
	bin := writeFakeTool(t, "pnputil", `echo "The parameter is incorrect." >&2
exit 87
`)
	p := NewPnPUtilDrivers()
	p.pnputilPath = bin

	res, err := p.Collect(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "pnputil: ")
	assert.Contains(t, err.Error(), "exit status 87")
	assert.Contains(t, err.Error(), "The parameter is incorrect.")
}

func TestPnPUtilCollect_MissingBinary(t *testing.T) {
	t.Parallel()

	p := NewPnPUtilDrivers()
	p.pnputilPath = filepath.Join(t.TempDir(), "no-pnputil")

	res, err := p.Collect(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestPnPUtilDrivers_AvailableMatchesGOOS(t *testing.T) {
	t.Parallel()

	assert.Equal(t, runtime.GOOS == "windows", NewPnPUtilDrivers().Available(),
		"pnputil is a Windows-only collector")
}
