package vpn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const nbStatusFixture = `{"peers":{"total":2,"connected":1,"details":[
  {"fqdn":"host-a.netbird.cloud","netbirdIp":"100.92.0.2","publicKey":"pkA","status":"Connected",
   "lastStatusUpdate":"2026-08-19T09:00:00Z","connectionType":"P2P","os":"linux/amd64","version":"0.28.0"},
  {"fqdn":"host-b.netbird.cloud","netbirdIp":"100.92.0.3","publicKey":"pkB","status":"Idle",
   "lastStatusUpdate":"2026-08-18T09:00:00Z","connectionType":"Relayed","os":"Darwin 14.5","version":"0.28.0","relayed":true}
]}}`

func TestPeersFromNBStatus(t *testing.T) {
	peers, err := peersFromNBStatus([]byte(nbStatusFixture))
	require.NoError(t, err)
	require.Len(t, peers, 2)

	a, ok := findPeer(peers, byHostname("host-a"))
	require.True(t, ok, "hostname is the first FQDN label")
	assert.Equal(t, "netbird", a.VPNType)
	assert.Equal(t, "host-a.netbird.cloud", a.DNSName)
	assert.Equal(t, "linux", a.OS)
	assert.Equal(t, "amd64", a.Tags["arch"])
	assert.True(t, a.Online, "Connected ⇒ online")
	assert.Equal(t, []string{"100.92.0.2"}, a.Addresses)
	assert.Equal(t, time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC), a.LastSeen)
	assert.Equal(t, "P2P", a.Tags["connection_type"])

	b, ok := findPeer(peers, byHostname("host-b"))
	require.True(t, ok)
	assert.False(t, b.Online, "Idle ⇒ not online")
	assert.Equal(t, "Darwin", b.OS)
	assert.Equal(t, true, b.Tags["relayed"])
}

func TestPeersFromNBStatus_InvalidJSON(t *testing.T) {
	_, err := peersFromNBStatus([]byte("nope"))
	require.Error(t, err)
}

func TestSplitNetbirdOS(t *testing.T) {
	fam, arch := splitNetbirdOS("linux/amd64")
	assert.Equal(t, "linux", fam)
	assert.Equal(t, "amd64", arch)

	fam, arch = splitNetbirdOS("Darwin 14.5")
	assert.Equal(t, "Darwin", fam)
	assert.Empty(t, arch)

	fam, arch = splitNetbirdOS("")
	assert.Empty(t, fam)
	assert.Empty(t, arch)
}

func TestFirstLabel(t *testing.T) {
	assert.Equal(t, "host", firstLabel("host.example.com"))
	assert.Equal(t, "host", firstLabel("host.example.com."))
	assert.Equal(t, "bare", firstLabel("bare"))
	assert.Equal(t, "", firstLabel(""))
}

const nbAPIPeersFixture = `[
  {"id":"p1","name":"host-a","ip":"100.92.0.2","dns_label":"host-a.netbird.cloud","user_id":"u1",
   "hostname":"host-a","os":"Linux","version":"0.28.0","connected":true,"last_seen":"2026-08-19T09:00:00Z"},
  {"id":"p2","name":"host-b","ip":"100.92.0.3","dns_label":"host-b.netbird.cloud","user_id":"u2",
   "hostname":"","os":"Darwin","version":"0.28.0","connected":false,"last_seen":"2026-08-18T09:00:00Z"}
]`

const nbAPIUsersFixture = `[
  {"id":"u1","email":"alice@example.org","name":"Alice"},
  {"id":"u2","email":"","name":"Bob"}
]`

func TestNetbirdUserEmails(t *testing.T) {
	m := netbirdUserEmails([]byte(nbAPIUsersFixture))
	assert.Equal(t, "alice@example.org", m["u1"])
	assert.Equal(t, "Bob", m["u2"], "falls back to name when email empty")
	assert.Empty(t, netbirdUserEmails([]byte("bad")))
}

func TestPeersFromNBAPI_WithOwners(t *testing.T) {
	owners := netbirdUserEmails([]byte(nbAPIUsersFixture))
	peers, err := peersFromNBAPI([]byte(nbAPIPeersFixture), owners)
	require.NoError(t, err)
	require.Len(t, peers, 2)

	a, ok := findPeer(peers, byHostname("host-a"))
	require.True(t, ok)
	assert.Equal(t, "alice@example.org", a.Owner, "owner resolved from user directory")
	assert.Equal(t, "u1", a.Tags["user_id"])
	assert.Equal(t, "netbird_api", a.Tags["source"])

	b, ok := findPeer(peers, byHostname("host-b"))
	require.True(t, ok, "empty hostname falls back to name")
	assert.Equal(t, "Bob", b.Owner)
}

func TestNetBirdEnumerateAPI(t *testing.T) {
	t.Run("peers plus owner enrichment", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/peers", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Token tok-123", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(nbAPIPeersFixture))
		})
		mux.HandleFunc("/api/users", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(nbAPIUsersFixture))
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		e := newNetBirdEnumerator()
		e.httpClient = srv.Client()
		e.getenv = stubEnv(map[string]string{
			"KITE_NETBIRD_MGMT_URL": srv.URL,
			"KITE_NETBIRD_TOKEN":    "tok-123",
		})
		peers, err := e.enumerate(context.Background(), nil)
		require.NoError(t, err)
		require.Len(t, peers, 2)
		a, ok := findPeer(peers, byHostname("host-a"))
		require.True(t, ok)
		assert.Equal(t, "alice@example.org", a.Owner)
	})

	t.Run("hosts still returned when user directory is forbidden", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/peers", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(nbAPIPeersFixture))
		})
		mux.HandleFunc("/api/users", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		e := newNetBirdEnumerator()
		e.httpClient = srv.Client()
		e.getenv = stubEnv(map[string]string{
			"KITE_NETBIRD_MGMT_URL": srv.URL,
			"KITE_NETBIRD_TOKEN":    "tok-123",
		})
		peers, err := e.enumerate(context.Background(), nil)
		require.NoError(t, err, "a peers-only token still yields hosts")
		require.Len(t, peers, 2)
		a, _ := findPeer(peers, byHostname("host-a"))
		assert.Empty(t, a.Owner, "owner enrichment skipped, host still discovered")
	})

	t.Run("unauthorized peers call errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		e := newNetBirdEnumerator()
		e.httpClient = srv.Client()
		e.getenv = stubEnv(map[string]string{
			"KITE_NETBIRD_MGMT_URL": srv.URL,
			"KITE_NETBIRD_TOKEN":    "bad",
		})
		_, err := e.enumerate(context.Background(), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "401")
	})
}
