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

// fakeKldstatScript mimics `kldstat -v` output on a FreeBSD 14 host,
// including the header row and a "Contains modules" sub-block that must be
// skipped rather than parsed as loaded files.
const fakeKldstatScript = `if [ "$1" != "-v" ]; then
  echo "kldstat: illegal option" >&2
  exit 1
fi
cat <<'EOF'
Id Refs Address                Size Name
 1   77 0xffffffff80200000 1c5e3a8 kernel
	Contains modules:
		Id Name
		 1 elf64
 2    1 0xffffffff81e60000   2e8b8 ums.ko
EOF
exit 0
`

func TestKldstatCollect_HappyPath(t *testing.T) {
	bin := writeFakeTool(t, "kldstat", fakeKldstatScript)
	collected := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	k := NewKldstat()
	k.binary = bin
	k.now = func() time.Time { return collected }

	res, err := k.Collect(context.Background())
	require.NoError(t, err)
	require.Empty(t, res.Errs)
	require.Len(t, res.Drivers, 2, "header and Contains-modules sub-rows must not become drivers")

	kernel := findByName(res.Drivers, "kernel")
	require.NotNil(t, kernel)
	assert.Equal(t, collected, kernel.CollectedAt)
	assert.Equal(t, runtime.GOARCH, kernel.Architecture)
	assert.Equal(t, FrameworkKLD, kernel.DriverFramework)
	assert.Equal(t, "Live", kernel.State)
	assert.Equal(t, "live", kernel.StartMode)
	assert.Equal(t,
		software.BuildCPE23WithTargetSW("", "kernel", "", "freebsd"),
		kernel.CPE23,
		"CPE must be built with the freebsd target_sw")

	ums := findByName(res.Drivers, "ums.ko")
	require.NotNil(t, ums)
	assert.Equal(t, collected, ums.CollectedAt)
}

func TestKldstatCollect_DefaultNowStampsCollectedAt(t *testing.T) {
	bin := writeFakeTool(t, "kldstat", fakeKldstatScript)
	k := NewKldstat() // keep the constructor's default clock
	k.binary = bin

	before := time.Now().UTC()
	res, err := k.Collect(context.Background())
	require.NoError(t, err)
	after := time.Now().UTC()

	require.NotEmpty(t, res.Drivers)
	got := res.Drivers[0].CollectedAt
	assert.False(t, got.Before(before), "default clock must be UTC now")
	assert.False(t, got.After(after))
}

func TestKldstatCollect_NonZeroExitSurfacesError(t *testing.T) {
	bin := writeFakeTool(t, "kldstat", `echo "kldstat: can't find file" >&2
exit 1
`)
	k := NewKldstat()
	k.binary = bin

	res, err := k.Collect(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "kldstat: ")
	assert.Contains(t, err.Error(), "exit status 1")
	assert.Contains(t, err.Error(), "can't find file",
		"the tool's stderr must be folded into the error")
}

func TestKldstatCollect_MissingBinary(t *testing.T) {
	t.Parallel()

	k := NewKldstat()
	k.binary = filepath.Join(t.TempDir(), "no-kldstat")

	res, err := k.Collect(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
}
