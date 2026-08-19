package vpn

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const nebulaConfigFixture = `
pki:
  ca: /etc/nebula/ca.crt
static_host_map:
  "192.168.100.1": ["203.0.113.5:4242"]
  "192.168.100.2": ["198.51.100.7:4242", "198.51.100.8:4242"]
lighthouse:
  am_lighthouse: false
  hosts:
    - "192.168.100.1"
`

func TestParseNebulaConfig(t *testing.T) {
	peers, err := parseNebulaConfig([]byte(nebulaConfigFixture))
	require.NoError(t, err)
	require.Len(t, peers, 2)

	lh, ok := findPeer(peers, func(p Peer) bool { return len(p.Addresses) > 0 && p.Addresses[0] == "192.168.100.1" })
	require.True(t, ok)
	assert.Equal(t, "nebula", lh.VPNType)
	assert.Equal(t, true, lh.Tags["is_lighthouse"])
	assert.Equal(t, "203.0.113.5:4242", lh.Endpoint)

	peer, ok := findPeer(peers, func(p Peer) bool { return len(p.Addresses) > 0 && p.Addresses[0] == "192.168.100.2" })
	require.True(t, ok)
	assert.Equal(t, false, peer.Tags["is_lighthouse"])
	assert.Equal(t, []string{"198.51.100.7:4242", "198.51.100.8:4242"}, peer.Tags["underlay_endpoints"])
}

func TestParseNebulaConfig_BadYAML(t *testing.T) {
	_, err := parseNebulaConfig([]byte("static_host_map: [this is: not valid"))
	require.Error(t, err)
}

func TestParseNebulaConfig_NoHosts(t *testing.T) {
	peers, err := parseNebulaConfig([]byte("pki:\n  ca: x\n"))
	require.NoError(t, err)
	assert.Empty(t, peers)
}

func TestNebulaEnumerate(t *testing.T) {
	t.Run("reads first available config", func(t *testing.T) {
		e := newNebulaEnumerator()
		e.getenv = func(string) string { return "" }
		e.readFile = func(path string) ([]byte, error) {
			if path == "/etc/nebula/config.yml" {
				return []byte(nebulaConfigFixture), nil
			}
			return nil, fs.ErrNotExist
		}
		peers, err := e.enumerate(context.Background(), nil)
		require.NoError(t, err)
		assert.Len(t, peers, 2)
	})

	t.Run("env override and permission denied", func(t *testing.T) {
		e := newNebulaEnumerator()
		e.getenv = func(k string) string {
			if k == "KITE_NEBULA_CONFIG" {
				return "/custom/nebula.yml"
			}
			return ""
		}
		var asked string
		e.readFile = func(path string) ([]byte, error) {
			asked = path
			return nil, fs.ErrPermission
		}
		peers, err := e.enumerate(context.Background(), nil)
		require.NoError(t, err, "permission denied is not fatal")
		assert.Nil(t, peers)
		assert.Equal(t, "/custom/nebula.yml", asked, "env override path honoured")
	})

	t.Run("not installed", func(t *testing.T) {
		e := newNebulaEnumerator()
		e.getenv = func(string) string { return "" }
		e.readFile = func(string) ([]byte, error) { return nil, errors.New("no such file") }
		peers, err := e.enumerate(context.Background(), nil)
		require.NoError(t, err)
		assert.Nil(t, peers)
	})
}
