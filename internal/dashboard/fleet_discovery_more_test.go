package dashboard

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// fleetMachineIP resolution order: literal-IP hostname, the established
// tag keys, then the first IPv4 of overlay_addresses (VPN sources), with
// v6-only fabrics falling back to the first valid address.
func TestFleetMachineIP(t *testing.T) {
	assert.Equal(t, "192.0.2.7",
		fleetMachineIP(model.Machine{Hostname: "192.0.2.7"}),
		"an IP-literal hostname is the IP")

	assert.Equal(t, "10.0.0.5",
		fleetMachineIP(model.Machine{Hostname: "h", Tags: `{"local_ip":"10.0.0.5"}`}))

	assert.Equal(t, "100.85.220.71",
		fleetMachineIP(model.Machine{Hostname: "peer", Tags: `{"overlay_addresses":["fd7a:115c:a1e0::1","100.85.220.71"]}`}),
		"the IPv4 overlay address wins regardless of order")

	assert.Equal(t, "fd7a:115c:a1e0::1",
		fleetMachineIP(model.Machine{Hostname: "peer", Tags: `{"overlay_addresses":["fd7a:115c:a1e0::1"]}`}),
		"v6-only overlays fall back to the first valid address")

	assert.Empty(t,
		fleetMachineIP(model.Machine{Hostname: "peer", Tags: `{"overlay_addresses":["not-an-ip", 42]}`}),
		"junk overlay entries yield nothing")

	assert.Empty(t, fleetMachineIP(model.Machine{Hostname: "h", Tags: `not-json`}))
	assert.Empty(t, fleetMachineIP(model.Machine{Hostname: "h"}))
}

func TestMergeFleetMachine(t *testing.T) {
	dst := model.Machine{
		Hostname: "192.0.2.7", // IP placeholder
		Tags:     `{"a":"1"}`,
	}
	mergeFleetMachine(&dst, model.Machine{
		Hostname:     "real-host",
		OSFamily:     "linux",
		Architecture: "amd64",
		MachineType:  model.MachineTypeServer,
		Tags:         `{"b":"2"}`,
	})
	assert.Equal(t, "real-host", dst.Hostname, "a named host replaces an IP placeholder")
	assert.Equal(t, "linux", dst.OSFamily)
	assert.Equal(t, model.MachineTypeServer, dst.MachineType)
	assert.Contains(t, dst.Tags, `"a":"1"`)
	assert.Contains(t, dst.Tags, `"b":"2"`, "tags merge, not replace")

	// An IP-literal source hostname never overwrites a real name.
	mergeFleetMachine(&dst, model.Machine{Hostname: "10.0.0.9", OSFamily: "windows"})
	assert.Equal(t, "real-host", dst.Hostname)
	assert.Equal(t, "linux", dst.OSFamily, "populated fields are not overwritten")
}

func TestFleetDiscoverySameOrigin(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://127.0.0.1:9090/x", nil)
	assert.True(t, fleetDiscoverySameOrigin(req), "no Origin header is same-origin (curl, htmx)")

	req.Header.Set("Origin", "http://127.0.0.1:9090")
	assert.True(t, fleetDiscoverySameOrigin(req))

	req.Header.Set("Origin", "http://evil.example.com")
	assert.False(t, fleetDiscoverySameOrigin(req))

	req.Header.Set("Origin", "http://127.0.0.1:9090")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	assert.False(t, fleetDiscoverySameOrigin(req), "Sec-Fetch-Site cross-site wins over Origin")

	req.Header.Set("Sec-Fetch-Site", "same-origin")
	assert.True(t, fleetDiscoverySameOrigin(req))
}

func TestSelectFleetLocalNetwork(t *testing.T) {
	_, err := selectFleetLocalNetwork(nil)
	require.Error(t, err, "no candidates is an explicit error")

	got, err := selectFleetLocalNetwork([]fleetLocalNetwork{
		{InterfaceName: "usb0", LocalIP: "10.0.9.2", score: 10},
		{InterfaceName: "eth0", LocalIP: "10.0.0.2", score: 100},
		{InterfaceName: "eth1", LocalIP: "10.0.1.2", score: 100},
	})
	require.NoError(t, err)
	assert.Equal(t, "eth0", got.InterfaceName,
		"highest score wins, name breaks ties deterministically")
}

func TestFleetScanPrefix(t *testing.T) {
	p := fleetScanPrefix(netip.MustParseAddr("10.1.2.3"), 16)
	assert.Equal(t, "10.1.2.0/24", p.String(),
		"a /16 interface clamps to the local /24 — one click must never sweep a /16")

	p = fleetScanPrefix(netip.MustParseAddr("192.168.1.77"), 26)
	assert.Equal(t, "192.168.1.64/26", p.String(), "narrower prefixes stay as-is")
}

func TestIsFleetVirtualInterface(t *testing.T) {
	for _, virtual := range []string{"docker0", "br-abc", "veth12", "tailscale0", "wg0", "virbr0", "lo"} {
		assert.True(t, isFleetVirtualInterface(virtual), virtual)
	}
	for _, physical := range []string{"eth0", "enp3s0", "wlan0", "en0"} {
		assert.False(t, isFleetVirtualInterface(physical), physical)
	}
}

func TestDiscoverFleetControllerMachine(t *testing.T) {
	m, err := discoverFleetControllerMachine(fleetLocalNetwork{LocalIP: "10.0.0.5"})
	require.NoError(t, err)
	assert.NotEmpty(t, m.Hostname)
	assert.Equal(t, "local_controller", m.DiscoverySource)
	assert.Contains(t, m.Tags, `"local_ip":"10.0.0.5"`)
	assert.Equal(t, model.MachineTypeWorkstation, m.MachineType)
}
