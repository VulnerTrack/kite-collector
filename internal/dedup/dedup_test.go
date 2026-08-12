package dedup

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cloud "github.com/vulnertrack/kite-collector/internal/discovery/cloud"
	entra "github.com/vulnertrack/kite-collector/internal/discovery/entra"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// ---------------------------------------------------------------------------
// In-memory mock store
// ---------------------------------------------------------------------------

type mockStore struct {
	machines map[string]model.Machine // keyed by natural_key
	mu       sync.Mutex
}

func newMockStore() *mockStore {
	return &mockStore{machines: make(map[string]model.Machine)}
}

func (m *mockStore) UpsertMachine(_ context.Context, machine model.Machine) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	machine.ComputeNaturalKey()
	m.machines[machine.NaturalKey] = machine
	return nil
}

func (m *mockStore) UpsertMachines(_ context.Context, machines []model.Machine) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var inserted, updated int
	for i := range machines {
		machines[i].ComputeNaturalKey()
		if _, exists := m.machines[machines[i].NaturalKey]; exists {
			updated++
		} else {
			inserted++
		}
		m.machines[machines[i].NaturalKey] = machines[i]
	}
	return inserted, updated, nil
}

func (m *mockStore) GetMachineByNaturalKey(_ context.Context, key string) (*model.Machine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.machines[key]
	if !ok {
		return nil, nil
	}
	cp := a
	return &cp, nil
}

func (m *mockStore) GetMachinesByNaturalKeys(_ context.Context, keys []string) (map[string]model.Machine, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]model.Machine, len(keys))
	for _, k := range keys {
		if a, ok := m.machines[k]; ok {
			out[k] = a
		}
	}
	return out, nil
}

func (m *mockStore) GetMachineByID(_ context.Context, id uuid.UUID) (*model.Machine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.machines {
		if a.ID == id {
			cp := a
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *mockStore) ListMachines(_ context.Context, _ store.MachineFilter) ([]model.Machine, error) {
	return nil, nil
}

func (m *mockStore) GetStaleMachines(_ context.Context, _ time.Duration) ([]model.Machine, error) {
	return nil, nil
}

func (m *mockStore) InsertEvent(_ context.Context, _ model.MachineEvent) error { return nil }

func (m *mockStore) InsertEvents(_ context.Context, _ []model.MachineEvent) error { return nil }

func (m *mockStore) ListEvents(_ context.Context, _ store.EventFilter) ([]model.MachineEvent, error) {
	return nil, nil
}

func (m *mockStore) CreateScanRun(_ context.Context, _ model.ScanRun) error { return nil }

func (m *mockStore) CompleteScanRun(_ context.Context, _ uuid.UUID, _ model.ScanResult) error {
	return nil
}

func (m *mockStore) GetLatestScanRun(_ context.Context) (*model.ScanRun, error) { return nil, nil }

func (m *mockStore) ListScanRuns(_ context.Context, _ int) ([]model.ScanRun, error) {
	return []model.ScanRun{}, nil
}

func (m *mockStore) GetScanRun(_ context.Context, _ uuid.UUID) (*model.ScanRun, error) {
	return nil, store.ErrNotFound
}

func (m *mockStore) MarkScanCancelRequested(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return store.ErrNotFound
}

func (m *mockStore) UpsertSoftware(_ context.Context, _ uuid.UUID, _ []model.InstalledSoftware) error {
	return nil
}

func (m *mockStore) ListSoftware(_ context.Context, _ uuid.UUID) ([]model.InstalledSoftware, error) {
	return nil, nil
}

func (m *mockStore) InsertFindings(_ context.Context, _ []model.ConfigFinding) error { return nil }

func (m *mockStore) ListFindings(_ context.Context, _ store.FindingFilter) ([]model.ConfigFinding, error) {
	return nil, nil
}

func (m *mockStore) InsertRuntimeIncident(_ context.Context, _ model.RuntimeIncident) error {
	return nil
}

func (m *mockStore) ListRuntimeIncidents(_ context.Context, _ store.IncidentFilter) ([]model.RuntimeIncident, error) {
	return nil, nil
}

func (m *mockStore) RecordHeartbeat(_ context.Context, _ model.ProbeHeartbeat) error {
	return nil
}

func (m *mockStore) ListHeartbeats(_ context.Context, _ store.HeartbeatFilter) ([]model.ProbeHeartbeat, error) {
	return nil, nil
}

func (m *mockStore) Migrate(_ context.Context) error { return nil }

func (m *mockStore) ListContentTables(_ context.Context) ([]store.TableSchema, error) {
	return nil, nil
}

func (m *mockStore) DescribeTable(_ context.Context, _ string) (*store.TableSchema, error) {
	return nil, store.ErrUnknownTable
}

func (m *mockStore) ListRows(_ context.Context, _ store.RowsFilter) ([]store.Row, int64, error) {
	return nil, 0, store.ErrUnknownTable
}

func (m *mockStore) GetRowReport(_ context.Context, _ string, _ map[string]string) (*store.RowReport, error) {
	return nil, store.ErrUnknownTable
}

func (m *mockStore) Close() error { return nil }

func (m *mockStore) UpsertEntraSnapshot(_ context.Context, _ *entra.Snapshot) error {
	return nil
}

func (m *mockStore) UpsertCloudDNSSnapshot(_ context.Context, _ *cloud.DNSSnapshot) error {
	return nil
}

// compile-time check
var _ store.Store = (*mockStore)(nil)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestDedup_NewMachineGetsUUIDv7(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	machines := []model.Machine{
		{Hostname: "new-host", MachineType: model.MachineTypeServer, DiscoverySource: "test"},
	}

	res, err := dd.Deduplicate(ctx, machines)
	require.NoError(t, err)
	require.Len(t, res.Machines, 1)

	assert.NotEqual(t, uuid.Nil, res.Machines[0].ID, "new machine must get a UUID assigned")
	assert.Equal(t, 1, res.NewCount)
	assert.Equal(t, 0, res.UpdatedCount)
}

func TestDedup_ExistingMachinePreservesID(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	// Pre-populate the store with an existing machine.
	existingID := uuid.Must(uuid.NewV7())
	firstSeen := time.Now().UTC().Add(-24 * time.Hour)
	existing := model.Machine{
		ID:              existingID,
		Hostname:        "db-01",
		MachineType:     model.MachineTypeServer,
		DiscoverySource: "network",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      firstSeen,
	}
	existing.ComputeNaturalKey()
	ms.machines[existing.NaturalKey] = existing

	// Re-discover the same machine.
	incoming := []model.Machine{
		{Hostname: "db-01", MachineType: model.MachineTypeServer, DiscoverySource: "network"},
	}

	res, err := dd.Deduplicate(ctx, incoming)
	require.NoError(t, err)
	require.Len(t, res.Machines, 1)

	assert.Equal(t, existingID, res.Machines[0].ID, "existing ID must be preserved")
	assert.Equal(t, 0, res.NewCount)
	assert.Equal(t, 1, res.UpdatedCount)
}

func TestDedup_FirstSeenAtPreservedOnUpdate(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	firstSeen := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	existing := model.Machine{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "app-01",
		MachineType:     model.MachineTypeContainer,
		DiscoverySource: "agent",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      firstSeen,
	}
	existing.ComputeNaturalKey()
	ms.machines[existing.NaturalKey] = existing

	incoming := []model.Machine{
		{Hostname: "app-01", MachineType: model.MachineTypeContainer, DiscoverySource: "agent"},
	}

	res, err := dd.Deduplicate(ctx, incoming)
	require.NoError(t, err)
	require.Len(t, res.Machines, 1)

	assert.Equal(t, firstSeen, res.Machines[0].FirstSeenAt,
		"FirstSeenAt must be preserved from the existing record")
}

func TestDedup_LastSeenAtUpdatedOnRediscovery(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	oldTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	existing := model.Machine{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "app-02",
		MachineType:     model.MachineTypeServer,
		DiscoverySource: "network",
		FirstSeenAt:     oldTime,
		LastSeenAt:      oldTime,
	}
	existing.ComputeNaturalKey()
	ms.machines[existing.NaturalKey] = existing

	beforeDedup := time.Now().UTC()
	incoming := []model.Machine{
		{Hostname: "app-02", MachineType: model.MachineTypeServer, DiscoverySource: "network"},
	}

	res, err := dd.Deduplicate(ctx, incoming)
	require.NoError(t, err)
	require.Len(t, res.Machines, 1)

	assert.True(t, res.Machines[0].LastSeenAt.After(oldTime) || res.Machines[0].LastSeenAt.Equal(beforeDedup),
		"LastSeenAt must be updated to approximately now")
}

func TestDedup_IntraBatchDedup(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	// Two machines with the same hostname+type in one batch
	machines := []model.Machine{
		{Hostname: "dup-host", MachineType: model.MachineTypeWorkstation, DiscoverySource: "src1"},
		{Hostname: "dup-host", MachineType: model.MachineTypeWorkstation, DiscoverySource: "src2"},
	}

	res, err := dd.Deduplicate(ctx, machines)
	require.NoError(t, err)

	assert.Len(t, res.Machines, 1, "duplicate within a batch must be collapsed to one")
	assert.Equal(t, 1, res.NewCount)
	assert.Equal(t, 0, res.UpdatedCount)
}

// TestDedup_IntraBatchMerge_OrderIndependent is the RFC-0151 OQ4 regression:
// a host discovered by two local sources in the same scan must fold to the
// SAME merged machine regardless of the order the sources arrive in, so the
// persisted record (and its MaterialFingerprint) does not flip between scans.
func TestDedup_IntraBatchMerge_OrderIndependent(t *testing.T) {
	ctx := context.Background()

	// Same host, two sources, differing on the volatile OSVersion and on the
	// data each uniquely carries (osquery has Tags, the agent does not).
	agent := model.Machine{
		Hostname: "web01", MachineType: model.MachineTypeServer,
		DiscoverySource: "agent", OSFamily: "linux",
		OSVersion: "Ubuntu 24.04.2 LTS", Architecture: "amd64",
	}
	osq := model.Machine{
		Hostname: "web01", MachineType: model.MachineTypeServer,
		DiscoverySource: "osquery", OSFamily: "linux",
		OSVersion: "Ubuntu 24.04.2 LTS (Noble Numbat)", Architecture: "amd64",
		Tags: `{"osquery_version":"5.15.0"}`,
	}

	fold := func(order []model.Machine) model.Machine {
		dd := New(newMockStore(), nil, WithClock(func() time.Time {
			return time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
		}))
		res, err := dd.Deduplicate(ctx, order)
		require.NoError(t, err)
		require.Len(t, res.Machines, 1, "one host -> one record")
		return res.Machines[0]
	}

	a := fold([]model.Machine{agent, osq})
	b := fold([]model.Machine{osq, agent}) // reversed arrival order

	// Identity aside (random UUID), the material content must be identical
	// regardless of arrival order — that is what stops the per-scan churn.
	assert.Equal(t, a.MaterialFingerprint(), b.MaterialFingerprint(),
		"folded machine must be order-independent")

	// And the deterministic winner is well-defined: osquery sorts after agent,
	// so it wins the last-writer-wins fields; nothing is dropped.
	assert.Equal(t, "Ubuntu 24.04.2 LTS (Noble Numbat)", a.OSVersion,
		"osquery (later source) wins OSVersion deterministically")
	assert.Equal(t, `{"osquery_version":"5.15.0"}`, a.Tags,
		"osquery's Tags must survive the fold, not be dropped")
	assert.Equal(t, "amd64", a.Architecture)
}

// TestDedup_IntraBatchMerge_NoChurnAcrossScans proves the fold is stable
// across repeated scans with shuffled arrival order (the churn symptom).
func TestDedup_IntraBatchMerge_NoChurnAcrossScans(t *testing.T) {
	ctx := context.Background()
	ms := newMockStore()
	clk := func() time.Time { return time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC) }
	dd := New(ms, nil, WithClock(clk))

	agent := model.Machine{
		Hostname: "db01", MachineType: model.MachineTypeServer,
		DiscoverySource: "agent", OSVersion: "Debian GNU/Linux 12",
	}
	osq := model.Machine{
		Hostname: "db01", MachineType: model.MachineTypeServer,
		DiscoverySource: "osquery", OSVersion: "Debian GNU/Linux 12 (bookworm)",
		Tags: `{"osquery_version":"5.15.0"}`,
	}

	batches := [][]model.Machine{{agent, osq}, {osq, agent}, {agent, osq}, {osq, agent}}
	fps := make([]string, 0, len(batches))
	for _, batch := range batches {
		res, err := dd.Deduplicate(ctx, batch)
		require.NoError(t, err)
		require.Len(t, res.Machines, 1)
		// Persist so the next scan's dedup sees it (as production does).
		require.NoError(t, ms.UpsertMachine(ctx, res.Machines[0]))
		fps = append(fps, res.Machines[0].MaterialFingerprint())
	}
	for i := 1; i < len(fps); i++ {
		assert.Equal(t, fps[0], fps[i],
			"fingerprint must not change across scans despite shuffled arrival order (scan %d)", i)
	}
}

func TestDedup_IntraBatchDedup_DifferentTypes(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	// Same hostname but different types are distinct machines
	machines := []model.Machine{
		{Hostname: "host-01", MachineType: model.MachineTypeServer, DiscoverySource: "net"},
		{Hostname: "host-01", MachineType: model.MachineTypeContainer, DiscoverySource: "net"},
	}

	res, err := dd.Deduplicate(ctx, machines)
	require.NoError(t, err)

	assert.Len(t, res.Machines, 2, "same hostname with different types are distinct")
	assert.Equal(t, 2, res.NewCount)
}

func TestDedup_EmptyInput(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	res, err := dd.Deduplicate(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, res.Machines)
	assert.Equal(t, 0, res.NewCount)
	assert.Equal(t, 0, res.UpdatedCount)

	res2, err := dd.Deduplicate(ctx, []model.Machine{})
	require.NoError(t, err)
	assert.Empty(t, res2.Machines)
	assert.Equal(t, 0, res2.NewCount)
	assert.Equal(t, 0, res2.UpdatedCount)
}

func TestDedup_NewMachineFirstSeenEqualsLastSeen(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	machines := []model.Machine{
		{Hostname: "fresh-host", MachineType: model.MachineTypeWorkstation, DiscoverySource: "test"},
	}

	res, err := dd.Deduplicate(ctx, machines)
	require.NoError(t, err)
	require.Len(t, res.Machines, 1)

	assert.Equal(t, res.Machines[0].FirstSeenAt, res.Machines[0].LastSeenAt,
		"for a new machine, FirstSeenAt must equal LastSeenAt")
	assert.False(t, res.Machines[0].FirstSeenAt.IsZero(), "timestamps must not be zero")
}

func TestMergeTagsJSON(t *testing.T) {
	cases := []struct {
		name               string
		existing, incoming string
		wantKeys           map[string]string // key -> expected raw value substring
	}{
		{
			name:     "union of disjoint keys (agent + osquery)",
			existing: `{"software_count":"92"}`,
			incoming: `{"hardware_uuid":"abc","file_events_24h":9}`,
			wantKeys: map[string]string{"software_count": "92", "hardware_uuid": "abc", "file_events_24h": "9"},
		},
		{
			name:     "incoming wins on key conflict",
			existing: `{"osquery_version":"5.14.0"}`,
			incoming: `{"osquery_version":"5.15.0"}`,
			wantKeys: map[string]string{"osquery_version": "5.15.0"},
		},
		{
			name:     "empty existing keeps incoming",
			existing: "",
			incoming: `{"a":"1"}`,
			wantKeys: map[string]string{"a": "1"},
		},
		{
			name:     "null incoming keeps existing",
			existing: `{"a":"1"}`,
			incoming: "null",
			wantKeys: map[string]string{"a": "1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeTagsJSON(tc.existing, tc.incoming)
			var m map[string]json.RawMessage
			require.NoError(t, json.Unmarshal([]byte(got), &m), "merged tags must be valid JSON: %s", got)
			assert.Len(t, m, len(tc.wantKeys), "unexpected key count in %s", got)
			for k, want := range tc.wantKeys {
				require.Contains(t, m, k, "missing key %q in %s", k, got)
				assert.Contains(t, string(m[k]), want, "key %q value in %s", k, got)
			}
		})
	}
}

// TestDedup_UnionsTagsAcrossSources is the end-to-end guard for finding 1:
// the local agent and osquery both discover the same host with DISJOINT tag
// keys. The merge must keep BOTH sets, not overwrite one with the other.
func TestDedup_UnionsTagsAcrossSources(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	existing := model.Machine{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "dual-source-host",
		MachineType:     model.MachineTypeServer,
		DiscoverySource: "agent",
		Tags:            `{"software_count":"92"}`,
		FirstSeenAt:     time.Now().UTC().Add(-time.Hour),
		LastSeenAt:      time.Now().UTC().Add(-time.Hour),
	}
	existing.ComputeNaturalKey()
	ms.machines[existing.NaturalKey] = existing

	incoming := []model.Machine{{
		Hostname:        "dual-source-host",
		MachineType:     model.MachineTypeServer,
		DiscoverySource: "osquery",
		Tags:            `{"hardware_uuid":"03c00218","osquery_version":"5.15.0","file_events_24h":9}`,
	}}

	res, err := dd.Deduplicate(ctx, incoming)
	require.NoError(t, err)
	require.Len(t, res.Machines, 1)

	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(res.Machines[0].Tags), &m))
	// Agent's contribution must survive the osquery merge...
	assert.Contains(t, m, "software_count", "agent tag dropped by osquery merge")
	// ...alongside all of osquery's.
	assert.Contains(t, m, "hardware_uuid")
	assert.Contains(t, m, "osquery_version")
	assert.Contains(t, m, "file_events_24h")
}

func TestDedup_MergesOSInfo(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	existing := model.Machine{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "merge-host",
		MachineType:     model.MachineTypeServer,
		DiscoverySource: "network",
		OSFamily:        "",
		FirstSeenAt:     time.Now().UTC().Add(-time.Hour),
		LastSeenAt:      time.Now().UTC().Add(-time.Hour),
	}
	existing.ComputeNaturalKey()
	ms.machines[existing.NaturalKey] = existing

	incoming := []model.Machine{
		{
			Hostname:        "merge-host",
			MachineType:     model.MachineTypeServer,
			DiscoverySource: "agent",
			OSFamily:        "linux",
			OSVersion:       "6.1",
		},
	}

	res, err := dd.Deduplicate(ctx, incoming)
	require.NoError(t, err)
	require.Len(t, res.Machines, 1)

	assert.Equal(t, "linux", res.Machines[0].OSFamily, "OS family must be merged from incoming")
	assert.Equal(t, "6.1", res.Machines[0].OSVersion, "OS version must be merged from incoming")
}

// TestDedup_Idempotent verifies that running Deduplicate twice with the same
// input produces deterministic counts (NewCount=2 then UpdatedCount=2) and
// preserves machine IDs across runs. Uses a fixed clock for determinism.
func TestDedup_Idempotent(t *testing.T) {
	ms := newMockStore()
	fixedTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	dd := New(ms, nil, WithClock(func() time.Time { return fixedTime }))
	ctx := context.Background()

	machines := []model.Machine{
		{Hostname: "host-a", MachineType: model.MachineTypeServer, DiscoverySource: "test"},
		{Hostname: "host-b", MachineType: model.MachineTypeServer, DiscoverySource: "test"},
	}

	// First pass: both machines are new.
	res1, err := dd.Deduplicate(ctx, machines)
	require.NoError(t, err)
	require.Len(t, res1.Machines, 2)
	assert.Equal(t, 2, res1.NewCount)
	assert.Equal(t, 0, res1.UpdatedCount)

	// Record the IDs + natural keys assigned.
	idByKey := make(map[string]uuid.UUID, 2)
	for _, a := range res1.Machines {
		idByKey[a.NaturalKey] = a.ID
		// Persist into the store so the second pass finds them.
		require.NoError(t, ms.UpsertMachine(ctx, a))
	}

	// Second pass: same inputs (new Machine values, no IDs pre-assigned).
	machines2 := []model.Machine{
		{Hostname: "host-a", MachineType: model.MachineTypeServer, DiscoverySource: "test"},
		{Hostname: "host-b", MachineType: model.MachineTypeServer, DiscoverySource: "test"},
	}
	res2, err := dd.Deduplicate(ctx, machines2)
	require.NoError(t, err)
	require.Len(t, res2.Machines, 2)
	assert.Equal(t, 0, res2.NewCount)
	assert.Equal(t, 2, res2.UpdatedCount)

	// Same IDs must be reused.
	for _, a := range res2.Machines {
		assert.Equal(t, idByKey[a.NaturalKey], a.ID,
			"existing ID must be preserved on re-deduplication")
	}
}
