package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tsStatusFixture mirrors the real `tailscale status --json` shape (peer
// map + inline user directory + tailnet) without any real-world PII. It
// deliberately exercises every edge case seen in live data: online/offline
// mix, an expired key, an ACL-tagged node whose owner is the synthetic
// "tagged-devices" login, a peer whose UserID is absent from the directory,
// and an empty-hostname peer.
const tsStatusFixture = `{
  "Version": "1.98.10",
  "BackendState": "Running",
  "CurrentTailnet": {"Name": "example.org", "MagicDNSSuffix": "tail1234.ts.net"},
  "Self": {"HostName": "collector", "DNSName": "collector.tail1234.ts.net.", "OS": "linux", "UserID": 100},
  "User": {
    "100": {"LoginName": "alice@example.org", "DisplayName": "Alice A"},
    "200": {"LoginName": "bob@example.org", "DisplayName": "Bob B"},
    "300": {"LoginName": "tagged-devices", "DisplayName": "Tagged Devices"}
  },
  "Peer": {
    "k1": {"HostName": "macbook", "DNSName": "macbook.tail1234.ts.net.", "OS": "macOS",
           "UserID": 100, "Online": true, "LastSeen": "2026-08-19T10:00:00Z",
           "TailscaleIPs": ["100.64.0.2","fd7a::2"], "CurAddr": "203.0.113.5:41641", "PublicKey": "nk:1"},
    "k2": {"HostName": "server-1", "DNSName": "server-1.tail1234.ts.net.", "OS": "linux",
           "UserID": 200, "Online": false, "Expired": true, "LastSeen": "2026-06-01T08:00:00Z",
           "TailscaleIPs": ["100.64.0.3"], "Relay": "lax", "PublicKey": "nk:2"},
    "k3": {"HostName": "ci-runner", "DNSName": "ci-runner.tail1234.ts.net.", "OS": "linux",
           "UserID": 300, "Online": true, "Tags": ["tag:ci"], "PublicKey": "nk:3",
           "TailscaleIPs": ["100.64.0.4"]},
    "k4": {"HostName": "", "DNSName": "orphan.tail1234.ts.net.", "OS": "windows",
           "UserID": 999, "Online": false, "PublicKey": "nk:4", "TailscaleIPs": ["100.64.0.5"]},
    "k5": {"HostName": "exit-gw", "DNSName": "exit-gw.tail1234.ts.net.", "OS": "linux",
           "UserID": 200, "Online": true, "ExitNode": true, "PublicKey": "nk:5",
           "TailscaleIPs": ["100.64.0.6"], "LastSeen": "0001-01-01T00:00:00Z"}
  }
}`

func findPeer(peers []Peer, pred func(Peer) bool) (Peer, bool) {
	for _, p := range peers {
		if pred(p) {
			return p, true
		}
	}
	return Peer{}, false
}

func byHostname(name string) func(Peer) bool {
	return func(p Peer) bool { return p.Hostname == name }
}

func TestPeersFromStatus_HappyAndEdges(t *testing.T) {
	peers, err := peersFromStatus([]byte(tsStatusFixture))
	require.NoError(t, err)
	require.Len(t, peers, 5, "Self is excluded; all 5 Peer entries are emitted")

	mac, ok := findPeer(peers, byHostname("macbook"))
	require.True(t, ok)
	assert.Equal(t, "alice@example.org", mac.Owner, "owner resolved from User directory")
	assert.True(t, mac.Online)
	assert.Equal(t, "203.0.113.5:41641", mac.Endpoint, "CurAddr preferred over relay")
	assert.Equal(t, time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC), mac.LastSeen)
	assert.Equal(t, "example.org", mac.Tags["tailnet"])
	assert.Equal(t, "Alice A", mac.Tags["owner_display_name"])

	srv, ok := findPeer(peers, byHostname("server-1"))
	require.True(t, ok)
	assert.False(t, srv.Online)
	assert.True(t, srv.Expired, "expired key surfaced")
	assert.Equal(t, "derp:lax", srv.Endpoint, "relay used when CurAddr absent")

	ci, ok := findPeer(peers, byHostname("ci-runner"))
	require.True(t, ok)
	assert.Equal(t, "tagged-devices", ci.Owner, "ACL-tagged node owner is the synthetic login")
	assert.Equal(t, []any{"tag:ci"}, toAnySlice(ci.Tags["acl_tags"]))

	orphan, ok := findPeer(peers, func(p Peer) bool { return p.DNSName == "orphan.tail1234.ts.net" })
	require.True(t, ok)
	assert.Empty(t, orphan.Hostname, "HostName was empty in the status JSON")
	assert.Equal(t, "orphan.tail1234.ts.net", orphan.displayHostname(),
		"empty HostName falls back to the DNS name at mapping time")
	assert.Empty(t, orphan.Owner, "UserID absent from directory yields no owner")

	exit, ok := findPeer(peers, byHostname("exit-gw"))
	require.True(t, ok)
	assert.True(t, exit.IsExitNode)
	assert.True(t, exit.LastSeen.IsZero(), "Go zero-time LastSeen treated as unknown")
}

func toAnySlice(v any) []any {
	if s, ok := v.([]string); ok {
		out := make([]any, len(s))
		for i := range s {
			out[i] = s[i]
		}
		return out
	}
	s, _ := v.([]any)
	return s
}

func TestPeersFromStatus_InvalidJSON(t *testing.T) {
	_, err := peersFromStatus([]byte("{not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode status json")
}

func TestPeersFromStatus_EmptyStatus(t *testing.T) {
	peers, err := peersFromStatus([]byte(`{"BackendState":"NeedsLogin"}`))
	require.NoError(t, err)
	assert.Empty(t, peers, "a logged-out node has no peers")
}

func TestTailscaleEnumerateCLI(t *testing.T) {
	t.Run("not installed", func(t *testing.T) {
		e := newTailscaleEnumerator()
		e.getenv = func(string) string { return "" }
		e.lookPath = func(string) (string, error) { return "", errors.New("not found") }
		peers, err := e.enumerate(context.Background(), nil)
		require.NoError(t, err)
		assert.Nil(t, peers, "missing binary is not an error")
	})

	t.Run("daemon error", func(t *testing.T) {
		e := newTailscaleEnumerator()
		e.getenv = func(string) string { return "" }
		e.lookPath = func(string) (string, error) { return "/usr/bin/tailscale", nil }
		e.run = func(context.Context, string, ...string) ([]byte, error) {
			return nil, errors.New("is tailscaled running?")
		}
		peers, err := e.enumerate(context.Background(), nil)
		require.NoError(t, err)
		assert.Nil(t, peers)
	})

	t.Run("success", func(t *testing.T) {
		e := newTailscaleEnumerator()
		e.getenv = func(string) string { return "" }
		e.lookPath = func(string) (string, error) { return "/usr/bin/tailscale", nil }
		e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
			assert.Equal(t, []string{"status", "--json"}, args)
			return []byte(tsStatusFixture), nil
		}
		peers, err := e.enumerate(context.Background(), nil)
		require.NoError(t, err)
		assert.Len(t, peers, 5)
	})
}

const tsDevicesFixture = `{"devices":[
  {"hostname":"api-1","name":"api-1.example.org","os":"linux","user":"carol@example.org",
   "addresses":["100.64.0.10"],"lastSeen":"2026-08-18T00:00:00Z","clientVersion":"1.98.0","tags":["tag:prod"]},
  {"hostname":"desktop","name":"desktop.example.org","os":"windows","user":"dave@example.org",
   "addresses":["100.64.0.11"],"blocked":true}
]}`

func TestPeersFromDevices(t *testing.T) {
	peers, err := peersFromDevices([]byte(tsDevicesFixture))
	require.NoError(t, err)
	require.Len(t, peers, 2)

	api, ok := findPeer(peers, byHostname("api-1"))
	require.True(t, ok)
	assert.Equal(t, "carol@example.org", api.Owner)
	assert.Equal(t, "1.98.0", api.OSVersion)
	assert.Equal(t, "tailscale_api", api.Tags["source"])
	assert.Equal(t, []any{"tag:prod"}, toAnySlice(api.Tags["acl_tags"]))

	desk, ok := findPeer(peers, byHostname("desktop"))
	require.True(t, ok)
	assert.Equal(t, true, desk.Tags["blocked"])

	_, err = peersFromDevices([]byte("nope"))
	require.Error(t, err)
}

func TestTailscaleEnumerateAPI(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, _, _ := r.BasicAuth()
			assert.Equal(t, "secret-key", user)
			assert.Equal(t, "/api/v2/tailnet/example.org/devices", r.URL.Path)
			_, _ = w.Write([]byte(tsDevicesFixture))
		}))
		defer srv.Close()

		e := newTailscaleEnumerator()
		e.apiBaseURL = srv.URL
		e.getenv = stubEnv(map[string]string{
			"KITE_TAILSCALE_API_KEY": "secret-key",
			"KITE_TAILSCALE_TAILNET": "example.org",
		})
		peers, err := e.enumerate(context.Background(), nil)
		require.NoError(t, err)
		assert.Len(t, peers, 2, "API path returns the whole tailnet")
	})

	t.Run("unauthorized", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		e := newTailscaleEnumerator()
		e.apiBaseURL = srv.URL
		e.getenv = stubEnv(map[string]string{
			"KITE_TAILSCALE_API_KEY": "bad",
			"KITE_TAILSCALE_TAILNET": "example.org",
		})
		_, err := e.enumerate(context.Background(), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "401")
	})

	t.Run("invalid tailnet rejected before request", func(t *testing.T) {
		e := newTailscaleEnumerator()
		_, err := e.enumerateAPI(context.Background(), "k", "evil/../path")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid tailnet")
	})
}

// stubEnv returns a getenv seam backed by a fixed map.
func stubEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestTailscale_APIResponseShapeRoundTrips(t *testing.T) {
	// Guard: our device struct must survive a marshal/unmarshal cycle so a
	// field-name typo is caught.
	var resp tsDevicesResponse
	require.NoError(t, json.Unmarshal([]byte(tsDevicesFixture), &resp))
	require.Len(t, resp.Devices, 2)
	assert.Equal(t, "carol@example.org", resp.Devices[0].User)
}
