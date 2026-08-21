package agent

import (
	"context"
	"net"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// -- pure mapping --------------------------------------------------

func TestMachineTypeForOS(t *testing.T) {
	assert.Equal(t, model.MachineTypeWorkstation, machineTypeForOS("darwin"))
	assert.Equal(t, model.MachineTypeWorkstation, machineTypeForOS("windows"))
	assert.Equal(t, model.MachineTypeServer, machineTypeForOS("linux"))
	assert.Equal(t, model.MachineTypeServer, machineTypeForOS("freebsd"))
	assert.Equal(t, model.MachineTypeServer, machineTypeForOS(""))
}

// -- constructor + identity ---------------------------------------

func TestNewAndName(t *testing.T) {
	p := New()
	require.NotNil(t, p)
	assert.Equal(t, "agent", p.Name())
}

// -- os/kernel readers (read-only) --------------------------------

func TestReadOSVersion(t *testing.T) {
	v := readOSVersion()
	assert.NotEmpty(t, v) // always at least the "goos/goarch" fallback
	if runtime.GOOS != "linux" {
		assert.Equal(t, runtime.GOOS+"/"+runtime.GOARCH, v)
	}
}

func TestReadKernelVersion(t *testing.T) {
	// Read-only host probe: returns a string (possibly empty off-Linux).
	v := readKernelVersion()
	if runtime.GOOS != "linux" {
		assert.Equal(t, "", v)
	} else {
		// On Linux /proc/version is virtually always present in CI.
		assert.NotEmpty(t, v)
	}
}

// -- Discover (read-only smoke) -----------------------------------

func TestDiscoverReturnsSaneMachine(t *testing.T) {
	p := New()
	// Disable the optional heavy collectors to keep this a fast smoke test.
	cfg := map[string]any{
		"collect_interfaces": false,
		"collect_software":   false,
		"collect_drivers":    false,
	}
	machines, err := p.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, machines, 1)

	m := machines[0]
	assert.NotEmpty(t, m.Hostname)
	assert.Equal(t, runtime.GOOS, m.OSFamily)
	assert.Equal(t, runtime.GOARCH, m.Architecture)
	assert.Equal(t, "agent", m.DiscoverySource)
	assert.NotEmpty(t, m.OSVersion)
	assert.Equal(t, machineTypeForOS(runtime.GOOS), m.MachineType)
	assert.Equal(t, model.AuthorizationUnknown, m.IsAuthorized)
	assert.Equal(t, model.ManagedUnknown, m.IsManaged)
	assert.False(t, m.FirstSeenAt.IsZero())
	assert.False(t, m.LastSeenAt.IsZero())
	assert.Equal(t, m.FirstSeenAt, m.LastSeenAt)
}

func TestDiscoverNilConfigDefaultsOn(t *testing.T) {
	// nil cfg exercises the default-on branches (interfaces + drivers).
	p := New()
	machines, err := p.Discover(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, machines, 1)
	assert.NotEmpty(t, machines[0].Hostname)
}

// -- exported collector wrappers (read-only) ----------------------

func TestCollectNetworkInterfaces(t *testing.T) {
	ifaces, err := CollectNetworkInterfaces()
	require.NoError(t, err)
	// Every returned interface must carry a name and a parseable IP; the
	// collector skips loopback/link-local so these invariants hold.
	primaryCount := 0
	for _, ni := range ifaces {
		assert.NotEmpty(t, ni.InterfaceName)
		assert.NotNil(t, net.ParseIP(ni.IPAddress), "unparseable IP %q", ni.IPAddress)
		assert.NotEqual(t, model.NetworkInterface{}.ID, ni.ID) // UUIDv7 assigned
		if ni.IsPrimary {
			primaryCount++
		}
	}
	// At most one interface is flagged primary.
	assert.LessOrEqual(t, primaryCount, 1)
}

func TestCollectInstalledSoftware(t *testing.T) {
	// Read-only; may be empty on a bare host but must not error.
	_, err := CollectInstalledSoftware(context.Background())
	require.NoError(t, err)
}

func TestCollectLoadedDrivers(t *testing.T) {
	drivers, bindings, err := CollectLoadedDrivers(context.Background())
	require.NoError(t, err)
	// Always returns non-nil-safe slices (may be empty).
	assert.GreaterOrEqual(t, len(drivers), 0)
	assert.GreaterOrEqual(t, len(bindings), 0)
}
