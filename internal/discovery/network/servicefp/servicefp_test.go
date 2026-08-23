package servicefp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hostPort(t *testing.T, addr string) (netip.Addr, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	ap, err := netip.ParseAddrPort(net.JoinHostPort(host, portStr))
	require.NoError(t, err)
	return ap.Addr(), ap.Port()
}

func TestIdentify_HTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := hostPort(t, srv.Listener.Addr().String())
	res, ok := New(2*time.Second).Identify(context.Background(), ip, port)
	require.True(t, ok, "fingerprintx should recognise a live HTTP listener")
	assert.Contains(t, res.Protocol, "http")
	assert.Equal(t, "tcp", res.Transport)
}

func TestIdentify_ClosedPortIsUnrecognised(t *testing.T) {
	// Bind then close to obtain a port nothing listens on.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ip, port := hostPort(t, ln.Addr().String())
	require.NoError(t, ln.Close())

	_, ok := New(500*time.Millisecond).Identify(context.Background(), ip, port)
	assert.False(t, ok, "a closed port yields no service, not an error")
}

func TestIdentify_CancelledContextSkips(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, ok := New(time.Second).Identify(ctx, netip.MustParseAddr("127.0.0.1"), 22)
	assert.False(t, ok, "a cancelled context short-circuits before probing")
}
