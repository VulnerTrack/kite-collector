package vpn

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestGatewayEnumerator_EnvDeclared(t *testing.T) {
	e := newMullvadEnumerator()
	e.getenv = stubEnv(map[string]string{
		"KITE_MULLVAD_RELAYS": "se-got-wg-001.mullvad.net:51820, us-nyc-wg-002.mullvad.net",
	})
	peers, err := e.enumerate(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, peers, 2)

	got, ok := findPeer(peers, byHostname("se-got-wg-001.mullvad.net"))
	require.True(t, ok)
	assert.Equal(t, "mullvad", got.VPNType)
	assert.Equal(t, "se-got-wg-001.mullvad.net:51820", got.Endpoint)
	assert.Equal(t, "gateway", got.Tags["role"])

	// The appliance hint must survive mapping.
	m := got.toMachine(fixedID, fixedNow)
	assert.Equal(t, model.MachineTypeAppliance, m.MachineType)
	assert.Equal(t, "vpn.mullvad", m.DiscoverySource)
}

func TestGatewayEnumerator_NoneConfigured(t *testing.T) {
	e := newGlobalProtectEnumerator()
	e.getenv = func(string) string { return "" }
	peers, err := e.enumerate(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, peers, "nothing configured ⇒ nothing discovered")
}

func TestAnyConnectHostsFromXML(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?>
<AnyConnectProfile>
  <ServerList>
    <HostEntry><HostName>Corp VPN</HostName><HostAddress>vpn.corp.example.com</HostAddress></HostEntry>
    <HostEntry><HostAddress>vpn-dr.corp.example.com</HostAddress></HostEntry>
  </ServerList>
</AnyConnectProfile>`)
	hosts := anyConnectHostsFromXML(xml)
	assert.Equal(t, []string{"Corp VPN", "vpn.corp.example.com", "vpn-dr.corp.example.com"}, hosts)
}

func TestAnyConnect_EnvAndConfigDedup(t *testing.T) {
	e := newAnyConnectEnumerator()
	e.getenv = stubEnv(map[string]string{
		"KITE_ANYCONNECT_GATEWAYS": "vpn.corp.example.com",
	})
	e.readFile = func(path string) ([]byte, error) {
		if path == "/opt/cisco/anyconnect/profile/preferences.xml" {
			return []byte(`<HostAddress>vpn.corp.example.com</HostAddress><HostAddress>vpn2.corp.example.com</HostAddress>`), nil
		}
		return nil, errors.New("not found")
	}
	peers, err := e.enumerate(context.Background(), nil)
	require.NoError(t, err)
	// vpn.corp.example.com appears in both env and config → deduped to one.
	require.Len(t, peers, 2)
	names := []string{peers[0].Hostname, peers[1].Hostname}
	assert.ElementsMatch(t, []string{"vpn.corp.example.com", "vpn2.corp.example.com"}, names)
}

func TestGatewayPeer_HostPortSplit(t *testing.T) {
	assert.Equal(t, "vpn.corp.com", gatewayPeer("globalprotect", "vpn.corp.com:443").Hostname)
	assert.Equal(t, "vpn.corp.com:443", gatewayPeer("globalprotect", "vpn.corp.com:443").Endpoint)
	assert.Equal(t, "vpn.corp.com", gatewayPeer("globalprotect", "vpn.corp.com").Hostname)
}
