package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ztListPeersFixture = `[
  {"address":"a1b2c3d4e5","role":"LEAF","version":"1.10.6","latency":12,
   "paths":[{"address":"203.0.113.5/9993","active":true,"lastReceive":1755600000000}]},
  {"address":"deadbeef00","role":"MOON","version":"1.12.0","latency":40,
   "paths":[{"address":"198.51.100.7/9993","active":false,"lastReceive":1755590000000}]},
  {"address":"cccccccccc","role":"PLANET","version":"-1.-1.-1","latency":-1,"paths":[]}
]`

func TestPeersFromZTListPeers(t *testing.T) {
	peers, err := peersFromZTListPeers([]byte(ztListPeersFixture))
	require.NoError(t, err)
	require.Len(t, peers, 2, "PLANET root is dropped; LEAF and MOON kept")

	leaf, ok := findPeer(peers, func(p Peer) bool { return p.PublicKey == "a1b2c3d4e5" })
	require.True(t, ok)
	assert.Equal(t, "zerotier", leaf.VPNType)
	assert.Equal(t, "LEAF", leaf.Tags["role"])
	assert.Equal(t, "1.10.6", leaf.OSVersion)
	assert.Equal(t, 12, leaf.Tags["latency_ms"])
	assert.True(t, leaf.Online, "active path ⇒ online")
	assert.Equal(t, "203.0.113.5/9993", leaf.Endpoint)
	assert.Equal(t, time.UnixMilli(1755600000000).UTC(), leaf.LastSeen)

	moon, ok := findPeer(peers, func(p Peer) bool { return p.PublicKey == "deadbeef00" })
	require.True(t, ok)
	assert.False(t, moon.Online, "no active path ⇒ offline")
	assert.Equal(t, "198.51.100.7/9993", moon.Endpoint, "falls back to newest path")

	// The version sentinel -1.-1.-1 must not leak into OSVersion.
	for _, p := range peers {
		assert.NotEqual(t, "-1.-1.-1", p.OSVersion)
	}
}

func TestPeersFromZTListPeers_InvalidJSON(t *testing.T) {
	_, err := peersFromZTListPeers([]byte("{}"))
	require.Error(t, err, "listpeers must be a JSON array")
}

func TestPeersFromZTListPeers_Empty(t *testing.T) {
	peers, err := peersFromZTListPeers([]byte(`[]`))
	require.NoError(t, err)
	assert.Empty(t, peers)
}

func TestZeroTierEnumerate(t *testing.T) {
	e := newZeroTierEnumerator()
	e.lookPath = func(string) (string, error) { return "", errors.New("nope") }
	peers, err := e.enumerate(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, peers)

	e.lookPath = func(string) (string, error) { return "/usr/sbin/zerotier-cli", nil }
	e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		assert.Equal(t, []string{"-j", "listpeers"}, args)
		return []byte(ztListPeersFixture), nil
	}
	peers, err = e.enumerate(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, peers, 2)
}
