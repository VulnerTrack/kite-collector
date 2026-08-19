package vpn

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ovpnV1Fixture = `OpenVPN CLIENT LIST
Updated,2026-08-19 12:00:00
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
alice,203.0.113.5:51000,12345,67890,2026-08-19 11:00:00
UNDEF,198.51.100.7:52000,1,2,2026-08-19 11:30:00
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
10.8.0.2,alice,203.0.113.5:51000,2026-08-19 11:59:00
10.8.0.3,UNDEF,198.51.100.7:52000,2026-08-19 11:59:00
GLOBAL STATS
Max bcast/mcast queue length,0
END`

func TestParseOpenVPN_V1(t *testing.T) {
	peers := parseOpenVPNStatus(ovpnV1Fixture)
	require.Len(t, peers, 2)

	alice, ok := findPeer(peers, byHostname("alice"))
	require.True(t, ok)
	assert.Equal(t, "openvpn", alice.VPNType)
	assert.Equal(t, "alice", alice.Owner, "CN becomes owner when no username")
	assert.Equal(t, "203.0.113.5:51000", alice.Endpoint)
	assert.Equal(t, []string{"10.8.0.2"}, alice.Addresses, "overlay joined from routing table")
	assert.True(t, alice.Online, "present in status ⇒ connected")
	assert.False(t, alice.LastSeen.IsZero(), "Connected Since parsed")

	anon, ok := findPeer(peers, byHostname("10.8.0.3"))
	require.True(t, ok, "UNDEF common name falls back to overlay address")
	assert.Empty(t, anon.Owner, "UNDEF is not an owner")
}

func TestParseOpenVPN_V2Comma(t *testing.T) {
	raw := strings.Join([]string{
		"TITLE,OpenVPN 2.5.1",
		"TIME,2026-08-19 12:00:00,1755604800",
		"HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher",
		"CLIENT_LIST,client1,203.0.113.5:51000,10.8.0.2,,12345,67890,2026-08-19 11:00:00,1755601200,bob,0,0,AES-256-GCM",
		"GLOBAL_STATS,Max bcast/mcast queue length,0",
		"END",
	}, "\n")

	peers := parseOpenVPNStatus(raw)
	require.Len(t, peers, 1, "HEADER line is not a client row")
	p := peers[0]
	assert.Equal(t, "client1", p.Hostname)
	assert.Equal(t, "bob", p.Owner, "authenticated username becomes owner")
	assert.Equal(t, "bob", p.Tags["username"])
	assert.Equal(t, "client1", p.Tags["common_name"])
	assert.Equal(t, []string{"10.8.0.2"}, p.Addresses)
	assert.EqualValues(t, 1755601200, p.LastSeen.Unix())
}

func TestParseOpenVPN_V3Tab(t *testing.T) {
	rows := [][]string{
		{"TITLE", "OpenVPN 2.6"},
		{"HEADER", "CLIENT_LIST", "Common Name", "Real Address", "Virtual Address", "Virtual IPv6 Address", "Bytes Received", "Bytes Sent", "Connected Since", "Connected Since (time_t)", "Username", "Client ID", "Peer ID", "Data Channel Cipher"},
		{"CLIENT_LIST", "svc-account", "192.0.2.9:1194", "10.9.0.5", "", "1", "2", "2026-08-19 11:00:00", "1755601200", "carol", "1", "1", "AES-256-GCM"},
		{"END"},
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(strings.Join(r, "\t"))
		b.WriteByte('\n')
	}
	peers := parseOpenVPNStatus(b.String())
	require.Len(t, peers, 1)
	assert.Equal(t, "svc-account", peers[0].Hostname)
	assert.Equal(t, "carol", peers[0].Owner)
	assert.Equal(t, "10.9.0.5", peers[0].Addresses[0])
}

func TestOpenVPNEnumerate_FileSeams(t *testing.T) {
	e := newOpenVPNEnumerator()
	e.getenv = stubEnv(map[string]string{
		"KITE_OPENVPN_STATUS_FILES": "/status/a.log,/status/b.log,/status/c.log",
	})
	e.readFile = func(path string) ([]byte, error) {
		switch path {
		case "/status/a.log":
			return []byte(ovpnV1Fixture), nil
		case "/status/b.log":
			return nil, fs.ErrNotExist // absent → skipped
		default:
			return nil, fs.ErrPermission // root-only → skipped, not fatal
		}
	}
	peers, err := e.enumerate(context.Background(), nil)
	require.NoError(t, err, "a missing or root-only status file must not fail the scan")
	assert.Len(t, peers, 2, "only the readable file contributes")
}

func TestOpenVPNEnumerate_NoFiles(t *testing.T) {
	e := newOpenVPNEnumerator()
	e.getenv = func(string) string { return "" }
	e.readFile = func(string) ([]byte, error) { return nil, fs.ErrNotExist }
	peers, err := e.enumerate(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, peers)
}
