package osquery

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscover_SavesListeningPortsFromOsquery(t *testing.T) {
	stub := healthyStub()
	stub.responses["listening_ports"] = []map[string]string{
		{"port": "22", "protocol": "6", "address": "0.0.0.0", "pid": "1001", "process": "sshd"},
		{"port": "5432", "protocol": "6", "address": "127.0.0.1", "pid": "2002", "process": "postgres"},
		{"port": "53", "protocol": "17", "address": "0.0.0.0", "pid": "3003", "process": "dnsmasq"},
		{"port": "0", "protocol": "6", "address": "", "pid": "0", "process": ""}, // unix socket → dropped
	}

	// sourceWith supplies an explicit socket in the cfg so socket
	// auto-detection never runs — the stub client answers every query
	// regardless of whether a real osqueryd socket exists on the host
	// (it does not in CI).
	src, cfg := sourceWith(stub)
	machines, err := src.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.NotEmpty(t, machines)

	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(machines[0].Tags), &tags))

	assert.EqualValues(t, 3, tags["listening_port_count"], "the port-0 unix socket is excluded")
	ports, ok := tags["listening_ports"].([]any)
	require.True(t, ok)
	require.Len(t, ports, 3)

	// Spot-check the first entry (sorted by port, so :22/ssh first).
	first := ports[0].(map[string]any)
	assert.EqualValues(t, 22, first["port"])
	assert.Equal(t, "tcp", first["protocol"], "protocol 6 maps to tcp")
	assert.Equal(t, "sshd", first["process"])
	assert.Equal(t, "0.0.0.0", first["address"])

	// The UDP entry keeps its name.
	var sawUDP bool
	for _, p := range ports {
		if m := p.(map[string]any); m["protocol"] == "udp" {
			sawUDP = true
			assert.Equal(t, "dnsmasq", m["process"])
		}
	}
	assert.True(t, sawUDP, "protocol 17 maps to udp")
}
