package dashboard

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

func TestSelectFleetLocalNetwork_PrefersPhysicalInterface(t *testing.T) {
	selected, err := selectFleetLocalNetwork([]fleetLocalNetwork{
		{InterfaceName: "custom0", LocalIP: "10.0.0.2", CIDR: "10.0.0.0/24", score: 10},
		{InterfaceName: "wlan0", LocalIP: "192.168.1.81", CIDR: "192.168.1.0/24", score: 100},
	})
	require.NoError(t, err)
	assert.Equal(t, "wlan0", selected.InterfaceName)
	assert.Equal(t, "192.168.1.0/24", selected.CIDR)
}

func TestFleetScanPrefix_LimitsBroadNetworkToLocal24(t *testing.T) {
	ip := netip.MustParseAddr("10.20.30.40")
	assert.Equal(t, "10.20.30.0/24", fleetScanPrefix(ip, 16).String())
	assert.Equal(t, "10.20.30.32/27", fleetScanPrefix(ip, 27).String())
}

func TestFleetIPv4Targets_ExcludesControllerAndNetworkAddress(t *testing.T) {
	targets := fleetIPv4Targets("192.0.2.0/30", "192.0.2.1")
	assert.Equal(t, []string{"192.0.2.2"}, targets)
}

func TestInferFleetProtocolOS_UsesStrongProtocolEvidence(t *testing.T) {
	windows := model.Machine{
		DiscoverySource: "wsdiscovery",
		Tags:            `{"wsd_scopes":"http://schemas.microsoft.com/windows/device"}`,
	}
	inferFleetProtocolOS(&windows)
	assert.Equal(t, "windows", windows.OSFamily)
	assert.Equal(t, "amd64", windows.Architecture)

	linux := model.Machine{
		DiscoverySource: "ssdp",
		Tags:            `{"ssdp_server":"Linux/6.8 UPnP/1.0"}`,
	}
	inferFleetProtocolOS(&linux)
	assert.Equal(t, "linux", linux.OSFamily)
	assert.Equal(t, "amd64", linux.Architecture)

	unknown := model.Machine{DiscoverySource: "netbios", Tags: `{"nbns_machine":"NAS"}`}
	inferFleetProtocolOS(&unknown)
	assert.Empty(t, unknown.OSFamily, "NetBIOS can also be Samba and is not conclusive")
}

func TestFleetVirtualInterfaceFilter(t *testing.T) {
	for _, name := range []string{"docker0", "br-abc", "veth123", "virbr0", "tailscale0"} {
		assert.True(t, isFleetVirtualInterface(name), name)
	}
	for _, name := range []string{"eth0", "enp3s0", "wlan0", "wlo1"} {
		assert.False(t, isFleetVirtualInterface(name), name)
	}
}

func TestFleetDiscoveryController_PersistsOnlyFakeScanResults(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	controller := &fleetDiscoveryController{
		detect: func() (fleetLocalNetwork, error) {
			return fleetLocalNetwork{LocalIP: "192.0.2.10", CIDR: "192.0.2.0/29", GatewayIP: "192.0.2.1", InterfaceName: "test0"}, nil
		},
		discover: func(_ context.Context, cfg map[string]any) ([]model.Machine, error) {
			assert.Equal(t, []string{"192.0.2.0/29"}, cfg["scope"])
			assert.Equal(t, true, cfg["infer_os"])
			return []model.Machine{{
				Hostname:        "192.0.2.11",
				MachineType:     model.MachineTypeServer,
				OSFamily:        "windows",
				Architecture:    "amd64",
				DiscoverySource: "network_scan",
				IsAuthorized:    model.AuthorizationUnknown,
				IsManaged:       model.ManagedUnknown,
				FirstSeenAt:     now,
				LastSeenAt:      now,
			}, {
				Hostname:        "192.0.2.1",
				MachineType:     model.MachineTypeServer,
				DiscoverySource: "network_scan",
				FirstSeenAt:     now,
				LastSeenAt:      now,
			}, {
				Hostname:        "192.0.2.10",
				MachineType:     model.MachineTypeServer,
				DiscoverySource: "network_scan",
				IsAuthorized:    model.AuthorizationUnknown,
				IsManaged:       model.ManagedUnknown,
				FirstSeenAt:     now,
				LastSeenAt:      now,
			}}, nil
		},
		localMachine: func(network fleetLocalNetwork) (model.Machine, error) {
			assert.Equal(t, "192.0.2.10", network.LocalIP)
			return model.Machine{
				Hostname: "controller.test", MachineType: model.MachineTypeWorkstation,
				OSFamily: "linux", Architecture: "amd64", DiscoverySource: "local_controller",
				IsAuthorized: model.AuthorizationUnknown, IsManaged: model.ManagedUnknown,
			}, nil
		},
	}

	require.NoError(t, controller.run(context.Background(), st))
	status := controller.snapshot()
	assert.True(t, status.HasRun)
	assert.Equal(t, 2, status.Found)
	assert.Equal(t, 2, status.Inserted)
	machines, err := st.ListMachines(context.Background(), store.MachineFilter{})
	require.NoError(t, err)
	require.Len(t, machines, 2)
	hostnames := []string{machines[0].Hostname, machines[1].Hostname}
	assert.ElementsMatch(t, []string{"192.0.2.11", "controller.test"}, hostnames)
	assert.NotEqual(t, [16]byte{}, [16]byte(machines[0].ID))
}

func TestDiscoverFleetControllerMachine_UsesRuntimeFacts(t *testing.T) {
	machine, err := discoverFleetControllerMachine(fleetLocalNetwork{LocalIP: "192.0.2.10"})
	require.NoError(t, err)
	hostname, err := os.Hostname()
	require.NoError(t, err)
	assert.Equal(t, hostname, machine.Hostname)
	assert.Equal(t, runtime.GOARCH, machine.Architecture)
	assert.Equal(t, "local_controller", machine.DiscoverySource)
	assert.Contains(t, machine.Tags, `"local_ip":"192.0.2.10"`)
}

func TestHandleFleetDiscovery_RejectsCrossSitePost(t *testing.T) {
	controller := &fleetDiscoveryController{}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9090/api/v1/fleet/discover", nil)
	req.Header.Set("Origin", "https://malicious.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()

	handleFleetDiscovery(rec, req, nil, slog.Default(), controller)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}
