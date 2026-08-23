package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func newListenerStore(t *testing.T) (*SQLiteStore, uuid.UUID) {
	t.Helper()
	st, err := New(t.TempDir() + "/hl.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	id := uuid.Must(uuid.NewV7())
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	require.NoError(t, st.UpsertMachine(context.Background(), model.Machine{
		ID: id, Hostname: "hl-host", MachineType: model.MachineTypeServer, OSFamily: "linux",
		DiscoverySource: "agent", IsAuthorized: model.AuthorizationUnknown, IsManaged: model.ManagedUnknown,
		FirstSeenAt: now, LastSeenAt: now,
	}))
	return st, id
}

// Happy path: listeners round-trip with all fields, ordered by port.
func TestReplaceHostListeners_RoundTrip(t *testing.T) {
	st, id := newListenerStore(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

	in := []model.HostListener{
		{
			MachineID: id, Protocol: "tcp", BindAddress: "0.0.0.0", Port: 8080, Exposure: "internet",
			PID: 1234, ProcessName: "python", Service: "http", ServiceVersion: "uvicorn", LastSeenAt: now, CollectedAt: now,
		},
		{
			MachineID: id, Protocol: "tcp", BindAddress: "127.0.0.1", Port: 22, Exposure: "loopback",
			PID: 900, ProcessName: "sshd", Service: "ssh", ServiceVersion: "OpenSSH_9.6", LastSeenAt: now, CollectedAt: now,
		},
	}
	require.NoError(t, st.ReplaceHostListeners(ctx, id, in))

	got, err := st.ListHostListeners(ctx, id)
	require.NoError(t, err)
	require.Len(t, got, 2)
	// Ordered by port: 22 then 8080.
	assert.Equal(t, uint16(22), got[0].Port)
	assert.Equal(t, "ssh", got[0].Service)
	assert.Equal(t, "OpenSSH_9.6", got[0].ServiceVersion)
	assert.EqualValues(t, 900, got[0].PID)
	assert.Equal(t, uint16(8080), got[1].Port)
	assert.Equal(t, "internet", got[1].Exposure)
	assert.Equal(t, "http", got[1].Service)
	assert.NotEqual(t, uuid.Nil, got[0].ID, "a zero ID is filled with a UUIDv7")
}

// Replace semantics: a re-scan replaces the set; stale sockets do not linger.
func TestReplaceHostListeners_ReplacesNotAccumulates(t *testing.T) {
	st, id := newListenerStore(t)
	ctx := context.Background()

	require.NoError(t, st.ReplaceHostListeners(ctx, id, []model.HostListener{
		{MachineID: id, Protocol: "tcp", BindAddress: "0.0.0.0", Port: 8080, Exposure: "internet"},
		{MachineID: id, Protocol: "tcp", BindAddress: "0.0.0.0", Port: 9090, Exposure: "internet"},
	}))
	// Second scan: 8080 gone, 5432 new.
	require.NoError(t, st.ReplaceHostListeners(ctx, id, []model.HostListener{
		{MachineID: id, Protocol: "tcp", BindAddress: "127.0.0.1", Port: 5432, Exposure: "loopback"},
	}))

	got, err := st.ListHostListeners(ctx, id)
	require.NoError(t, err)
	require.Len(t, got, 1, "the previous scan's listeners are replaced, not accumulated")
	assert.Equal(t, uint16(5432), got[0].Port)

	// Empty set clears entirely.
	require.NoError(t, st.ReplaceHostListeners(ctx, id, nil))
	got, err = st.ListHostListeners(ctx, id)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// Edge cases: invalid protocol skipped, empty exposure defaults to unknown,
// pid 0 stored as NULL (read back as 0).
func TestReplaceHostListeners_EdgeCases(t *testing.T) {
	st, id := newListenerStore(t)
	ctx := context.Background()

	require.NoError(t, st.ReplaceHostListeners(ctx, id, []model.HostListener{
		{MachineID: id, Protocol: "sctp", BindAddress: "0.0.0.0", Port: 1}, // invalid protocol -> skipped
		{MachineID: id, Protocol: "", BindAddress: "0.0.0.0", Port: 2},     // empty protocol -> skipped
		{MachineID: id, Protocol: "udp6", BindAddress: "::", Port: 53},     // valid, empty exposure + pid 0
	}))

	got, err := st.ListHostListeners(ctx, id)
	require.NoError(t, err)
	require.Len(t, got, 1, "only the valid-protocol listener is stored")
	assert.Equal(t, "udp6", got[0].Protocol)
	assert.Equal(t, "unknown", got[0].Exposure, "empty exposure defaults to unknown")
	assert.EqualValues(t, 0, got[0].PID)
	assert.Empty(t, got[0].Service, "no fingerprint -> empty service")
}

// Error path: a cancelled context fails the replace before any write.
func TestReplaceHostListeners_CancelledContextErrors(t *testing.T) {
	st, id := newListenerStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := st.ReplaceHostListeners(ctx, id, []model.HostListener{
		{MachineID: id, Protocol: "tcp", BindAddress: "0.0.0.0", Port: 80, Exposure: "internet"},
	})
	require.Error(t, err, "a cancelled context must fail the transaction")
}
