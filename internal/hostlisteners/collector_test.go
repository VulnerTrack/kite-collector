package hostlisteners

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/listeners"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/servicefp"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

type fakeCollector struct {
	list []listeners.Listener
	err  error
}

func (f fakeCollector) Name() string { return "fake" }
func (f fakeCollector) Collect(context.Context) ([]listeners.Listener, error) {
	return f.list, f.err
}

type fakeFinger struct {
	calls  []string
	result servicefp.Result
	ok     bool
}

func (f *fakeFinger) Identify(_ context.Context, ip netip.Addr, port uint16) (servicefp.Result, bool) {
	f.calls = append(f.calls, fmt.Sprintf("%s:%d", ip, port))
	return f.result, f.ok
}

func seededStore(t *testing.T, discoverySource string) (*sqlite.SQLiteStore, uuid.UUID) {
	t.Helper()
	st, err := sqlite.New(t.TempDir() + "/hl.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })
	id := uuid.Must(uuid.NewV7())
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	require.NoError(t, st.UpsertMachine(context.Background(), model.Machine{
		ID: id, Hostname: "seeded", MachineType: model.MachineTypeServer, OSFamily: "linux",
		DiscoverySource: discoverySource,
		IsAuthorized:    model.AuthorizationUnknown, IsManaged: model.ManagedUnknown,
		FirstSeenAt: now, LastSeenAt: now,
	}))
	return st, id
}

// Happy path with a deterministic fake fingerprinter: TCP ports get the named
// service, UDP is not fingerprinted.
func TestCollectAndStore_FingerprintsTCPOnly(t *testing.T) {
	st, id := seededStore(t, "agent")
	fp := &fakeFinger{result: servicefp.Result{Protocol: "postgresql", Version: "16.2"}, ok: true}
	lc := fakeCollector{list: []listeners.Listener{
		{Protocol: listeners.ProtoTCP, BindAddress: "127.0.0.1", Port: 5432, Exposure: listeners.ExposureLoopback, ProcessName: "postgres", PID: 10},
		{Protocol: listeners.ProtoUDP, BindAddress: "0.0.0.0", Port: 53, Exposure: listeners.ExposureInternet, ProcessName: "dnsmasq", PID: 20},
	}}
	c, ok := New(st, lc, fp, nil)
	require.True(t, ok)
	require.NoError(t, c.CollectAndStore(context.Background()))

	got, err := st.ListHostListeners(context.Background(), id)
	require.NoError(t, err)
	require.Len(t, got, 2)
	byPort := map[uint16]model.HostListener{got[0].Port: got[0], got[1].Port: got[1]}
	assert.Equal(t, "postgresql", byPort[5432].Service, "the TCP port is fingerprinted")
	assert.Equal(t, "16.2", byPort[5432].ServiceVersion)
	assert.Empty(t, byPort[53].Service, "UDP is not fingerprinted")
	assert.Len(t, fp.calls, 1, "only the one TCP port was probed")
	assert.Equal(t, "127.0.0.1:5432", fp.calls[0])
}

// Integration happy path: a real HTTP listener is recognised by the real
// fingerprintx recogniser.
func TestCollectAndStore_RealFingerprintRecognisesHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	ap := netip.MustParseAddrPort(net.JoinHostPort("127.0.0.1", portStr))

	st, id := seededStore(t, "agent")
	lc := fakeCollector{list: []listeners.Listener{
		{Protocol: listeners.ProtoTCP, BindAddress: "127.0.0.1", Port: ap.Port(), Exposure: listeners.ExposureLoopback},
	}}
	c, ok := New(st, lc, servicefp.New(2*time.Second), nil)
	require.True(t, ok)
	require.NoError(t, c.CollectAndStore(context.Background()))

	got, err := st.ListHostListeners(context.Background(), id)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Contains(t, got[0].Service, "http")
}

// Fingerprinting disabled (nil finger): listeners are still saved, no service.
func TestCollectAndStore_FingerprintDisabled(t *testing.T) {
	st, id := seededStore(t, "agent")
	lc := fakeCollector{list: []listeners.Listener{
		{Protocol: listeners.ProtoTCP, BindAddress: "0.0.0.0", Port: 8080, Exposure: listeners.ExposureInternet},
	}}
	c, ok := New(st, lc, nil, nil)
	require.True(t, ok)
	require.NoError(t, c.CollectAndStore(context.Background()))

	got, err := st.ListHostListeners(context.Background(), id)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Empty(t, got[0].Service)
}

// No local machine in the store yet: a quiet no-op, nothing stored.
func TestCollectAndStore_NoLocalMachineIsNoOp(t *testing.T) {
	st, err := sqlite.New(t.TempDir() + "/empty.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	called := false
	lc := fakeCollector{list: []listeners.Listener{{Protocol: listeners.ProtoTCP, BindAddress: "0.0.0.0", Port: 1}}}
	c, ok := New(st, lc, nil, nil)
	require.True(t, ok)
	require.NoError(t, c.CollectAndStore(context.Background()))
	assert.False(t, called)
}

// Error path: the collector failing surfaces an error and stores nothing.
func TestCollectAndStore_CollectorErrorPropagates(t *testing.T) {
	st, id := seededStore(t, "agent")
	c, ok := New(st, fakeCollector{err: errors.New("netlink boom")}, nil, nil)
	require.True(t, ok)

	err := c.CollectAndStore(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "collect listeners")

	got, lerr := st.ListHostListeners(context.Background(), id)
	require.NoError(t, lerr)
	assert.Empty(t, got, "a collector failure stores nothing")
}

func TestFingerprintTarget(t *testing.T) {
	assert.Equal(t, "127.0.0.1", fingerprintTarget("0.0.0.0").String(), "IPv4 wildcard -> loopback")
	assert.Equal(t, "::1", fingerprintTarget("::").String(), "IPv6 wildcard -> loopback")
	assert.Equal(t, "127.0.0.1", fingerprintTarget("").String(), "empty -> loopback")
	assert.Equal(t, "127.0.0.1", fingerprintTarget("not-an-ip").String(), "unparseable -> loopback")
	assert.Equal(t, "10.0.0.5", fingerprintTarget("10.0.0.5").String(), "specific address probed as-is")
}

// New declines a store without HostListenerStore support.
func TestNew_RequiresHostListenerStore(t *testing.T) {
	var notAListenerStore store.Store = stubStore{}
	_, ok := New(notAListenerStore, nil, nil, nil)
	assert.False(t, ok)
}

// stubStore implements store.Store minimally without HostListenerStore.
type stubStore struct{ store.Store }
