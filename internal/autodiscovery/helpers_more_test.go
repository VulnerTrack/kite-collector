package autodiscovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHexNibbleEdges_More(t *testing.T) {
	// /proc/net/route stores 0100A8C0 for 192.168.0.1 (little-endian).
	assert.Equal(t, "192.168.0.1", hexToIP("0100A8C0"))
	assert.Equal(t, "10.0.0.1", hexToIP("0100000A"))
	assert.Equal(t, "", hexToIP("SHORT"), "non-8-char input yields empty")
	assert.Equal(t, "", hexToIP(""))

	assert.EqualValues(t, 0, hexNibble('0'))
	assert.EqualValues(t, 9, hexNibble('9'))
	assert.EqualValues(t, 10, hexNibble('a'))
	assert.EqualValues(t, 15, hexNibble('F'))
	assert.EqualValues(t, 0, hexNibble('z'), "invalid nibbles decay to zero")
}

// The dedup priority ladders are load-bearing: a confirmed port-scan hit
// must outrank a docker guess, and ready beats needs_credentials beats
// detected.
func TestMethodAndStatusPriorityLadders(t *testing.T) {
	assert.Greater(t, methodPriority("port_scan"), methodPriority("docker_container"))
	assert.Greater(t, methodPriority("docker_container"), methodPriority("socket"))
	assert.Greater(t, methodPriority("socket"), methodPriority("env_var"))
	assert.Greater(t, methodPriority("env_var"), methodPriority("carrier-pigeon"))
	assert.Equal(t, 0, methodPriority(""))

	assert.Greater(t, statusPriority("ready"), statusPriority("needs_credentials"))
	assert.Greater(t, statusPriority("needs_credentials"), statusPriority("detected"))
	assert.Greater(t, statusPriority("detected"), statusPriority("unknown"))
}

func TestMatchComposeService_More(t *testing.T) {
	sig := ServiceSignature{Name: "wazuh", DockerNames: []string{"wazuh-manager"}}
	assert.True(t, matchComposeService("wazuh", sig), "exact name match")
	assert.True(t, matchComposeService("WAZUH", sig), "case-insensitive")
	assert.True(t, matchComposeService("prod-wazuh-manager-1", sig), "docker-name substring")
	assert.False(t, matchComposeService("elastic", sig))
}

// composeEndpoint prefers a host-mapped default port, falls back to the
// container name on the first default port, and degrades to the bare
// name when no ports are known.
func TestComposeEndpoint_More(t *testing.T) {
	sig := ServiceSignature{Name: "wazuh", DefaultPorts: []int{55000}, TLS: true}

	mapped := composeContainer{
		Names: []string{"/wazuh-1"},
		Ports: []dockerPortMapping{
			{PrivatePort: 22, PublicPort: 2222},
			{PrivatePort: 55000, PublicPort: 55001},
		},
	}
	assert.Equal(t, "https://127.0.0.1:55001", composeEndpoint(mapped, sig),
		"host-mapped default port wins; 0.0.0.0 maps to loopback")

	bound := mapped
	bound.Ports = []dockerPortMapping{{PrivatePort: 55000, PublicPort: 55001, IP: "10.0.0.9"}}
	assert.Equal(t, "https://10.0.0.9:55001", composeEndpoint(bound, sig),
		"an explicit bind IP is preserved")

	unmapped := composeContainer{Names: []string{"/wazuh-2"}}
	assert.Equal(t, "https://wazuh-2:55000", composeEndpoint(unmapped, sig),
		"no host mapping falls back to container-name:first-default-port")

	nameless := composeContainer{}
	assert.Equal(t, "", composeEndpoint(nameless, sig))
}

func TestBuildEndpoint_More(t *testing.T) {
	assert.Equal(t, "http://h:80", buildEndpoint("h", 80, false))
	assert.Equal(t, "https://h:443", buildEndpoint("h", 443, true))
}
