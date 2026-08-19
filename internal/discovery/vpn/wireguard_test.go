package vpn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wgDump builds a tab-separated `wg show all dump` document from rows so the
// tabs are unambiguous in the test source.
func wgDump(rows ...[]string) string {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(strings.Join(r, "\t"))
		b.WriteByte('\n')
	}
	return b.String()
}

func TestParseWGDump_HappyAndEdges(t *testing.T) {
	recent := fmt.Sprintf("%d", fixedNow.Add(-time.Minute).Unix())
	stale := fmt.Sprintf("%d", fixedNow.Add(-time.Hour).Unix())

	dump := wgDump(
		// interface (self) line — 5 cols, skipped.
		[]string{"wg0", "PRIVKEY", "SELFPUB", "51820", "off"},
		// live peer with recent handshake.
		[]string{"wg0", "PEER1PUB", "PSK1", "203.0.113.5:51820", "10.0.0.2/32,fd00::2/128", recent, "1000", "2000", "25"},
		// roaming peer: no endpoint, stale handshake → offline.
		[]string{"wg0", "PEER2PUB", "(none)", "(none)", "10.0.0.3/32", stale, "0", "0", "off"},
		// never-connected peer: handshake 0.
		[]string{"wg0", "PEER3PUB", "(none)", "198.51.100.9:51820", "10.0.0.4/32", "0", "0", "0", "off"},
		// second interface.
		[]string{"wg1", "PRIVKEY2", "SELFPUB2", "51821", "off"},
		[]string{"wg1", "PEER4PUB", "(none)", "192.0.2.7:51820", "10.1.0.2/32", recent, "5", "5", "off"},
	)

	peers := parseWGDump(dump, fixedNow)
	require.Len(t, peers, 4, "4 peer lines; both interface lines skipped")

	p1, ok := findPeer(peers, func(p Peer) bool { return p.PublicKey == "PEER1PUB" })
	require.True(t, ok)
	assert.Equal(t, "wireguard", p1.VPNType)
	assert.Equal(t, "203.0.113.5:51820", p1.Endpoint)
	assert.Equal(t, []string{"10.0.0.2", "fd00::2"}, p1.Addresses, "masks stripped, sorted")
	assert.True(t, p1.Online, "recent handshake ⇒ online")
	assert.Equal(t, fixedNow.Add(-time.Minute), p1.LastSeen)
	assert.Equal(t, true, p1.Tags["preshared_key"])
	assert.Equal(t, "wg0", p1.Tags["interface"])

	p2, ok := findPeer(peers, func(p Peer) bool { return p.PublicKey == "PEER2PUB" })
	require.True(t, ok)
	assert.Empty(t, p2.Endpoint, "(none) endpoint dropped")
	assert.False(t, p2.Online, "stale handshake ⇒ offline")
	assert.False(t, p2.LastSeen.IsZero())

	p3, ok := findPeer(peers, func(p Peer) bool { return p.PublicKey == "PEER3PUB" })
	require.True(t, ok)
	assert.True(t, p3.LastSeen.IsZero(), "handshake 0 ⇒ never seen")
	assert.False(t, p3.Online)
	_, hasPSK := p3.Tags["preshared_key"]
	assert.False(t, hasPSK, "(none) PSK ⇒ no preshared_key tag")

	p4, ok := findPeer(peers, func(p Peer) bool { return p.PublicKey == "PEER4PUB" })
	require.True(t, ok)
	assert.Equal(t, "wg1", p4.Tags["interface"], "interface tracked across blocks")
}

func TestParseWGDump_MalformedArity(t *testing.T) {
	dump := wgDump(
		[]string{"wg0", "PRIV", "PUB", "51820", "off"},
		[]string{"garbage", "line"},                                     // 2 cols → skipped
		[]string{"wg0", "PEERPUB", "x", "y", "z", "0", "0", "0", "off"}, // valid peer
	)
	peers := parseWGDump(dump, fixedNow)
	require.Len(t, peers, 1)
	assert.Equal(t, "PEERPUB", peers[0].PublicKey)
}

func TestParseWGDump_Empty(t *testing.T) {
	assert.Empty(t, parseWGDump("", fixedNow))
	assert.Empty(t, parseWGDump("\n\n  \n", fixedNow))
}

func TestWireGuardEnumerate_NotInstalledOrDenied(t *testing.T) {
	e := newWireGuardEnumerator()
	e.lookPath = func(string) (string, error) { return "", errors.New("no wg") }
	peers, err := e.enumerate(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, peers)

	e.lookPath = func(string) (string, error) { return "/usr/bin/wg", nil }
	e.run = func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("permission denied")
	}
	peers, err = e.enumerate(context.Background(), nil)
	require.NoError(t, err, "EPERM degrades to no peers, not a scan failure")
	assert.Nil(t, peers)
}

func TestWireGuardEnumerate_Success(t *testing.T) {
	e := newWireGuardEnumerator()
	e.now = func() time.Time { return fixedNow }
	e.lookPath = func(string) (string, error) { return "/usr/bin/wg", nil }
	e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		assert.Equal(t, []string{"show", "all", "dump"}, args)
		return []byte(wgDump(
			[]string{"wg0", "PRIV", "PUB", "51820", "off"},
			[]string{"wg0", "PEERPUB", "(none)", "203.0.113.5:51820", "10.0.0.2/32", "0", "0", "0", "off"},
		)), nil
	}
	peers, err := e.enumerate(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, peers, 1)
	assert.Equal(t, "203.0.113.5:51820", peers[0].Endpoint)
}
