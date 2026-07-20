package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/classifier"
	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/dedup"
	"github.com/vulnertrack/kite-collector/internal/discovery"
	cloud "github.com/vulnertrack/kite-collector/internal/discovery/cloud"
	entra "github.com/vulnertrack/kite-collector/internal/discovery/entra"
	"github.com/vulnertrack/kite-collector/internal/emitter"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/policy"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// ---------------------------------------------------------------------------
// In-memory mock store for engine tests
// ---------------------------------------------------------------------------

type mockStore struct {
	machines  map[string]model.Machine // keyed by natural_key
	software  map[uuid.UUID][]model.InstalledSoftware
	completed map[uuid.UUID]model.ScanResult
	events    []model.MachineEvent
	incidents []model.RuntimeIncident
	scanRuns  []model.ScanRun
	mu        sync.Mutex
}

func newMockStore() *mockStore {
	return &mockStore{
		machines:  make(map[string]model.Machine),
		software:  make(map[uuid.UUID][]model.InstalledSoftware),
		completed: make(map[uuid.UUID]model.ScanResult),
	}
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

func (m *mockStore) ListMachines(_ context.Context, _ store.MachineFilter) ([]model.Machine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]model.Machine, 0, len(m.machines))
	for _, a := range m.machines {
		result = append(result, a)
	}
	return result, nil
}

func (m *mockStore) GetStaleMachines(_ context.Context, threshold time.Duration) ([]model.Machine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().UTC().Add(-threshold)
	var stale []model.Machine
	for _, a := range m.machines {
		if a.LastSeenAt.Before(cutoff) {
			stale = append(stale, a)
		}
	}
	return stale, nil
}

func (m *mockStore) InsertEvent(_ context.Context, event model.MachineEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockStore) InsertEvents(_ context.Context, events []model.MachineEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, events...)
	return nil
}

func (m *mockStore) ListEvents(_ context.Context, _ store.EventFilter) ([]model.MachineEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]model.MachineEvent, len(m.events))
	copy(cp, m.events)
	return cp, nil
}

func (m *mockStore) CreateScanRun(_ context.Context, run model.ScanRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanRuns = append(m.scanRuns, run)
	return nil
}

func (m *mockStore) CompleteScanRun(_ context.Context, id uuid.UUID, result model.ScanResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.completed[id] = result
	for i := range m.scanRuns {
		if m.scanRuns[i].ID == id {
			m.scanRuns[i].Status = model.ScanStatusCompleted
			now := time.Now().UTC()
			m.scanRuns[i].CompletedAt = &now
			m.scanRuns[i].TotalMachines = result.TotalMachines
			m.scanRuns[i].NewMachines = result.NewMachines
			m.scanRuns[i].UpdatedMachines = result.UpdatedMachines
			m.scanRuns[i].AnalyzedMachines = result.AnalyzedMachines
			m.scanRuns[i].StaleMachines = result.StaleMachines
			m.scanRuns[i].CoveragePercent = result.CoveragePercent
			break
		}
	}
	return nil
}

func (m *mockStore) GetLatestScanRun(_ context.Context) (*model.ScanRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.scanRuns) == 0 {
		return nil, nil
	}
	cp := m.scanRuns[len(m.scanRuns)-1]
	return &cp, nil
}

func (m *mockStore) GetScanRun(_ context.Context, id uuid.UUID) (*model.ScanRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.scanRuns {
		if m.scanRuns[i].ID == id {
			cp := m.scanRuns[i]
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *mockStore) ListScanRuns(_ context.Context, limit int) ([]model.ScanRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 {
		limit = 50
	}
	out := make([]model.ScanRun, 0, len(m.scanRuns))
	// Newest-first: iterate stored slice in reverse (CompleteScanRun appends).
	for i := len(m.scanRuns) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, m.scanRuns[i])
	}
	return out, nil
}

func (m *mockStore) MarkScanCancelRequested(_ context.Context, id uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.scanRuns {
		if m.scanRuns[i].ID == id {
			t := at
			m.scanRuns[i].CancelRequestedAt = &t
			return nil
		}
	}
	return store.ErrNotFound
}

func (m *mockStore) UpsertSoftware(_ context.Context, machineID uuid.UUID, sw []model.InstalledSoftware) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.software[machineID] = sw
	return nil
}

func (m *mockStore) ListSoftware(_ context.Context, machineID uuid.UUID) ([]model.InstalledSoftware, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.software[machineID], nil
}

func (m *mockStore) InsertFindings(_ context.Context, _ []model.ConfigFinding) error {
	return nil
}

func (m *mockStore) ListFindings(_ context.Context, _ store.FindingFilter) ([]model.ConfigFinding, error) {
	return nil, nil
}

func (m *mockStore) InsertRuntimeIncident(_ context.Context, incident model.RuntimeIncident) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.incidents = append(m.incidents, incident)
	return nil
}

func (m *mockStore) ListRuntimeIncidents(_ context.Context, _ store.IncidentFilter) ([]model.RuntimeIncident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]model.RuntimeIncident, len(m.incidents))
	copy(cp, m.incidents)
	return cp, nil
}

// Heartbeat plumbing — these tests don't exercise the observability
// reconciler (engine.identity is never set in these mocks), so the methods
// are no-ops that satisfy the store.Store interface.
func (m *mockStore) RecordHeartbeat(_ context.Context, _ model.ProbeHeartbeat) error {
	return nil
}

func (m *mockStore) ListHeartbeats(_ context.Context, _ store.HeartbeatFilter) ([]model.ProbeHeartbeat, error) {
	return nil, nil
}

func (m *mockStore) Migrate(_ context.Context) error { return nil }
func (m *mockStore) Close() error                    { return nil }

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

func (m *mockStore) UpsertEntraSnapshot(_ context.Context, _ *entra.Snapshot) error {
	return nil
}

func (m *mockStore) UpsertCloudDNSSnapshot(_ context.Context, _ *cloud.DNSSnapshot) error {
	return nil
}

var _ store.Store = (*mockStore)(nil)

// ---------------------------------------------------------------------------
// Mock discovery source
// ---------------------------------------------------------------------------

type mockSource struct {
	name     string
	machines []model.Machine
}

func (s *mockSource) Name() string { return s.name }
func (s *mockSource) Discover(_ context.Context, _ map[string]any) ([]model.Machine, error) {
	return s.machines, nil
}

// ---------------------------------------------------------------------------
// Mock emitter that records emitted events
// ---------------------------------------------------------------------------

type recordingEmitter struct {
	events []model.MachineEvent
	mu     sync.Mutex
}

func (e *recordingEmitter) Emit(_ context.Context, event model.MachineEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
	return nil
}

func (e *recordingEmitter) EmitBatch(_ context.Context, events []model.MachineEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, events...)
	return nil
}

func (e *recordingEmitter) Shutdown(_ context.Context) error { return nil }

var _ emitter.Emitter = (*recordingEmitter)(nil)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestConfig() *config.Config {
	return &config.Config{
		StaleThreshold: "168h",
		Discovery: config.DiscoveryConfig{
			Sources: map[string]config.SourceConfig{
				"test": {
					Enabled: true,
					Scope:   []string{"10.0.0.0/24"},
				},
			},
		},
	}
}

func newTestEngine(st *mockStore, reg *discovery.Registry, em emitter.Emitter) *Engine {
	dd := dedup.New(st, nil)
	auth, _ := classifier.NewAuthorizer("", nil)
	mgr := classifier.NewManager(nil)
	cls := classifier.New(auth, mgr)
	pol := policy.New(nil, 168*time.Hour)
	return New(st, reg, dd, cls, em, pol, nil)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestEngine_FullScanCycle(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		machines: []model.Machine{
			{Hostname: "web-01", MachineType: model.MachineTypeServer, DiscoverySource: "test"},
			{Hostname: "db-01", MachineType: model.MachineTypeServer, DiscoverySource: "test"},
		},
	})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)
	cfg := newTestConfig()

	result, err := eng.Run(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 2, result.NewMachines)
	assert.Equal(t, 0, result.UpdatedMachines)
	assert.Equal(t, 2, result.TotalMachines)
	assert.Greater(t, result.EventsEmitted, 0)
}

func TestEngine_ScanRunCreatedAndCompleted(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		machines: []model.Machine{
			{Hostname: "host-01", MachineType: model.MachineTypeServer, DiscoverySource: "test"},
		},
	})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)
	cfg := newTestConfig()

	_, err := eng.Run(context.Background(), cfg)
	require.NoError(t, err)

	ms.mu.Lock()
	require.Len(t, ms.scanRuns, 1, "exactly one scan run should be created")
	run := ms.scanRuns[0]
	ms.mu.Unlock()

	assert.Equal(t, model.ScanStatusCompleted, run.Status, "scan run must be completed")
	assert.NotNil(t, run.CompletedAt, "completed_at must be set")
}

func TestEngine_NewMachinesGenerateDiscoveredEvents(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		machines: []model.Machine{
			{Hostname: "new-host", MachineType: model.MachineTypeServer, DiscoverySource: "test"},
		},
	})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)
	cfg := newTestConfig()

	_, err := eng.Run(context.Background(), cfg)
	require.NoError(t, err)

	em.mu.Lock()
	defer em.mu.Unlock()

	var discoveredEvents int
	for _, evt := range em.events {
		if evt.EventType == model.EventMachineDiscovered {
			discoveredEvents++
		}
	}
	assert.Equal(t, 1, discoveredEvents, "one MachineDiscovered event expected for a new machine")
}

func TestEngine_UnauthorizedMachinesGenerateEvent(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		machines: []model.Machine{
			{Hostname: "rogue-host", MachineType: model.MachineTypeServer, DiscoverySource: "test"},
		},
	})

	em := &recordingEmitter{}

	// Use a classifier that always returns unauthorized by writing an
	// allowlist file that does not match any discovered machine.
	allowlistPath := filepath.Join(t.TempDir(), "allowlist.yaml")
	err := os.WriteFile(allowlistPath, []byte("machines:\n  - hostname: \"only-this-one\"\n"), 0o644)
	require.NoError(t, err)

	auth, err := classifier.NewAuthorizer(allowlistPath, []string{"hostname"})
	require.NoError(t, err)
	mgr := classifier.NewManager(nil)
	cls := classifier.New(auth, mgr)

	dd := dedup.New(ms, nil)
	pol := policy.New(nil, 168*time.Hour)
	eng := New(ms, reg, dd, cls, em, pol, nil)
	cfg := newTestConfig()

	_, err = eng.Run(context.Background(), cfg)
	require.NoError(t, err)

	em.mu.Lock()
	defer em.mu.Unlock()

	var unauthEvents int
	for _, evt := range em.events {
		if evt.EventType == model.EventUnauthorizedMachineDetected {
			unauthEvents++
		}
	}
	assert.Equal(t, 1, unauthEvents, "one UnauthorizedMachineDetected event expected")
}

func TestEngine_StaleMachinesGenerateNotSeenEvents(t *testing.T) {
	ms := newMockStore()

	// Pre-populate store with a stale machine.
	staleMachine := model.Machine{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "old-server",
		MachineType:     model.MachineTypeServer,
		DiscoverySource: "test",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		FirstSeenAt:     time.Now().UTC().Add(-300 * time.Hour),
		LastSeenAt:      time.Now().UTC().Add(-300 * time.Hour),
	}
	staleMachine.ComputeNaturalKey()
	ms.machines[staleMachine.NaturalKey] = staleMachine

	// Discovery returns only a different machine (the stale one is not rediscovered).
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		machines: []model.Machine{
			{Hostname: "active-server", MachineType: model.MachineTypeServer, DiscoverySource: "test"},
		},
	})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)
	cfg := newTestConfig()

	result, err := eng.Run(context.Background(), cfg)
	require.NoError(t, err)

	assert.Equal(t, 1, result.StaleMachines, "one stale machine should be detected")

	em.mu.Lock()
	defer em.mu.Unlock()

	var notSeenEvents int
	for _, evt := range em.events {
		if evt.EventType == model.EventMachineNotSeen {
			notSeenEvents++
		}
	}
	assert.Equal(t, 1, notSeenEvents, "one MachineNotSeen event expected for the stale machine")
}

// ---------------------------------------------------------------------------
// Slow source for deadline tests
// ---------------------------------------------------------------------------

type slowSource struct {
	name  string
	delay time.Duration
}

func (s *slowSource) Name() string { return s.name }
func (s *slowSource) Discover(ctx context.Context, _ map[string]any) ([]model.Machine, error) {
	select {
	case <-time.After(s.delay):
		return []model.Machine{
			{Hostname: "slow-host", MachineType: model.MachineTypeServer, DiscoverySource: s.name},
		}, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("slow source cancelled: %w", ctx.Err())
	}
}

func TestEngine_ScanDeadlineExceeded(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	reg.Register(&slowSource{name: "test", delay: 5 * time.Second})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)
	cfg := newTestConfig()
	cfg.Safety.ScanDeadline = "50ms" // very short deadline

	result, err := eng.Run(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, string(model.ScanStatusTimedOut), result.Status)
	assert.Equal(t, 1, result.ErrorCount)

	// The breach must record a runtime incident carrying the catalogued
	// KITE-E013 code so downstream tooling can pivot on a stable identifier.
	// Asserting the literal (not the constant) independently pins the value.
	incidents, listErr := ms.ListRuntimeIncidents(context.Background(), store.IncidentFilter{})
	require.NoError(t, listErr)
	require.Len(t, incidents, 1)
	assert.Equal(t, "KITE-E013", incidents[0].ErrorCode)
	assert.Equal(t, model.IncidentTimeoutExceeded, incidents[0].IncidentType)
}

func TestEngine_ScanDeadlineNotExceeded(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		machines: []model.Machine{
			{Hostname: "fast-host", MachineType: model.MachineTypeServer, DiscoverySource: "test"},
		},
	})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)
	cfg := newTestConfig()
	cfg.Safety.ScanDeadline = "30s" // generous deadline

	result, err := eng.Run(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, string(model.ScanStatusCompleted), result.Status)
	assert.Equal(t, 0, result.ErrorCount)
}

func TestEngine_EmitsEventsWithMachineMetadata(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		machines: []model.Machine{
			{
				Hostname:        "web-meta-01",
				MachineType:     model.MachineTypeServer,
				OSFamily:        "linux",
				OSVersion:       "ubuntu-22.04",
				KernelVersion:   "5.15.0-101-generic",
				Architecture:    "amd64",
				Environment:     "production",
				Owner:           "platform-team",
				Criticality:     "high",
				DiscoverySource: "test",
			},
		},
	})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)
	cfg := newTestConfig()

	_, err := eng.Run(context.Background(), cfg)
	require.NoError(t, err)

	em.mu.Lock()
	defer em.mu.Unlock()

	require.NotEmpty(t, em.events, "engine must emit at least one event")
	var found bool
	for _, evt := range em.events {
		if evt.EventType != model.EventMachineDiscovered {
			continue
		}
		found = true
		assert.Equal(t, "web-meta-01", evt.Hostname, "Hostname must be copied from machine")
		assert.Equal(t, model.MachineTypeServer, evt.MachineType, "MachineType must be copied from machine")
		assert.Equal(t, "linux", evt.OSFamily, "OSFamily must be copied from machine")
		assert.Equal(t, "ubuntu-22.04", evt.OSVersion, "OSVersion must be copied from machine")
		assert.Equal(t, "5.15.0-101-generic", evt.KernelVersion, "KernelVersion must be copied from machine")
		assert.Equal(t, "amd64", evt.Architecture, "Architecture must be copied from machine")
		assert.Equal(t, "production", evt.Environment, "Environment must be copied from machine")
		assert.Equal(t, "platform-team", evt.Owner, "Owner must be copied from machine")
		assert.Equal(t, "high", evt.Criticality, "Criticality must be copied from machine")
		assert.Equal(t, "test", evt.DiscoverySource, "DiscoverySource must be copied from machine")
		assert.NotEqual(t, uuid.Nil, evt.MachineID, "MachineID must be set")
	}
	assert.True(t, found, "expected an EventMachineDiscovered event in the emitted batch")
}

func TestEngine_StaleMachineEventsIncludeMachineMetadata(t *testing.T) {
	ms := newMockStore()

	staleMachine := model.Machine{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "stale-meta-host",
		MachineType:     model.MachineTypeWorkstation,
		OSFamily:        "darwin",
		OSVersion:       "14.4",
		Environment:     "staging",
		Owner:           "ops",
		Criticality:     "medium",
		DiscoverySource: "test",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		FirstSeenAt:     time.Now().UTC().Add(-300 * time.Hour),
		LastSeenAt:      time.Now().UTC().Add(-300 * time.Hour),
	}
	staleMachine.ComputeNaturalKey()
	ms.machines[staleMachine.NaturalKey] = staleMachine

	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		machines: []model.Machine{
			{Hostname: "current-host", MachineType: model.MachineTypeServer, DiscoverySource: "test"},
		},
	})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)
	cfg := newTestConfig()

	_, err := eng.Run(context.Background(), cfg)
	require.NoError(t, err)

	em.mu.Lock()
	defer em.mu.Unlock()

	var found bool
	for _, evt := range em.events {
		if evt.EventType != model.EventMachineNotSeen {
			continue
		}
		found = true
		assert.Equal(t, "stale-meta-host", evt.Hostname, "Hostname must be propagated for stale-machine events")
		assert.Equal(t, model.MachineTypeWorkstation, evt.MachineType, "MachineType must be propagated for stale-machine events")
		assert.Equal(t, "darwin", evt.OSFamily, "OSFamily must be propagated for stale-machine events")
		assert.Equal(t, "staging", evt.Environment, "Environment must be propagated for stale-machine events")
		assert.Equal(t, "ops", evt.Owner, "Owner must be propagated for stale-machine events")
		assert.Equal(t, "medium", evt.Criticality, "Criticality must be propagated for stale-machine events")
		assert.Equal(t, "test", evt.DiscoverySource, "DiscoverySource must be propagated for stale-machine events")
		assert.Equal(t, staleMachine.ID, evt.MachineID, "MachineID must reference the stale machine")
	}
	assert.True(t, found, "expected an EventMachineNotSeen event in the emitted batch")
}

// TestEngine_RepeatedScanWithNoChange_EmitsAnalyzedNotUpdated pins the core
// behaviour change of this PR: a rescan that brings no material delta MUST
// produce an MachineAnalyzed event with severity low and the namespaced wire
// name "kite.machine.analyzed". This guards against a regression where the
// engine slips back to the old "FirstSeenAt != LastSeenAt -> Updated" rule.
func TestEngine_RepeatedScanWithNoChange_EmitsAnalyzedNotUpdated(t *testing.T) {
	ms := newMockStore()

	// Pre-seed the machine with FirstSeenAt < LastSeenAt so the merge path
	// in dedup is exercised. Material fields match the discovered copy
	// below, so the engine must treat the rescan as a noise-grade tick.
	existing := model.Machine{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "steady-host",
		MachineType:     model.MachineTypeServer,
		OSVersion:       "ubuntu-22.04",
		DiscoverySource: "test",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		FirstSeenAt:     time.Now().UTC().Add(-72 * time.Hour),
		LastSeenAt:      time.Now().UTC().Add(-72 * time.Hour),
	}
	existing.ComputeNaturalKey()
	ms.machines[existing.NaturalKey] = existing

	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		machines: []model.Machine{
			{
				Hostname:        "steady-host",
				MachineType:     model.MachineTypeServer,
				OSVersion:       "ubuntu-22.04",
				DiscoverySource: "test",
			},
		},
	})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)

	_, err := eng.Run(context.Background(), newTestConfig())
	require.NoError(t, err)

	em.mu.Lock()
	defer em.mu.Unlock()
	require.Len(t, em.events, 1)
	got := em.events[0]
	assert.Equal(t, model.EventMachineAnalyzed, got.EventType)
	assert.Equal(t, model.SeverityLow, got.Severity,
		"Analyzed events must be forced to severity=low (noise-grade)")
	assert.Equal(t, "kite.machine.analyzed", got.EventType.Name(),
		"namespaced wire name must reflect the new event type")
}

// TestEngine_MaterialChange_EmitsUpdated pins the other side of the
// classification: when a material field (here OSVersion) actually moves,
// the engine MUST still emit MachineUpdated so triage gets the signal.
func TestEngine_MaterialChange_EmitsUpdated(t *testing.T) {
	ms := newMockStore()

	existing := model.Machine{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "drift-host",
		MachineType:     model.MachineTypeServer,
		OSVersion:       "ubuntu-22.04",
		DiscoverySource: "test",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		FirstSeenAt:     time.Now().UTC().Add(-72 * time.Hour),
		LastSeenAt:      time.Now().UTC().Add(-72 * time.Hour),
	}
	existing.ComputeNaturalKey()
	ms.machines[existing.NaturalKey] = existing

	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		machines: []model.Machine{
			{
				Hostname:        "drift-host",
				MachineType:     model.MachineTypeServer,
				OSVersion:       "ubuntu-24.04",
				DiscoverySource: "test",
			},
		},
	})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)

	_, err := eng.Run(context.Background(), newTestConfig())
	require.NoError(t, err)

	em.mu.Lock()
	defer em.mu.Unlock()
	require.Len(t, em.events, 1)
	assert.Equal(t, model.EventMachineUpdated, em.events[0].EventType)
}

// TestEngine_FirstSighting_EmitsDiscovered preserves the original
// first-sighting contract: an empty store + a single discovered machine
// yields exactly one MachineDiscovered event, regardless of fingerprint
// logic added in this PR.
func TestEngine_FirstSighting_EmitsDiscovered(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		machines: []model.Machine{
			{Hostname: "fresh-host", MachineType: model.MachineTypeServer, DiscoverySource: "test"},
		},
	})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)

	_, err := eng.Run(context.Background(), newTestConfig())
	require.NoError(t, err)

	em.mu.Lock()
	defer em.mu.Unlock()
	require.Len(t, em.events, 1)
	assert.Equal(t, model.EventMachineDiscovered, em.events[0].EventType)
}

// TestEngine_UnauthorizedOverride_StillAppliesEvenWhenNoMaterialChange
// asserts that the alert-grade override still wins over the new Analyzed
// classification: an unauthorized machine on a no-change tick must still
// emit UnauthorizedMachineDetected, not Analyzed. This is what keeps
// rogue-machine detection loud and per-tick visible.
func TestEngine_UnauthorizedOverride_StillAppliesEvenWhenNoMaterialChange(t *testing.T) {
	ms := newMockStore()

	existing := model.Machine{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "rogue-host",
		MachineType:     model.MachineTypeServer,
		OSVersion:       "ubuntu-22.04",
		DiscoverySource: "test",
		IsAuthorized:    model.AuthorizationUnauthorized,
		IsManaged:       model.ManagedUnknown,
		FirstSeenAt:     time.Now().UTC().Add(-72 * time.Hour),
		LastSeenAt:      time.Now().UTC().Add(-72 * time.Hour),
	}
	existing.ComputeNaturalKey()
	ms.machines[existing.NaturalKey] = existing

	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		machines: []model.Machine{
			{
				Hostname:        "rogue-host",
				MachineType:     model.MachineTypeServer,
				OSVersion:       "ubuntu-22.04",
				DiscoverySource: "test",
			},
		},
	})

	// Use a classifier whose allowlist matches no machine so the merged
	// result remains unauthorized after classification.
	allowlistPath := filepath.Join(t.TempDir(), "allowlist.yaml")
	require.NoError(t, os.WriteFile(allowlistPath, []byte("machines:\n  - hostname: \"only-this-one\"\n"), 0o600))
	auth, err := classifier.NewAuthorizer(allowlistPath, []string{"hostname"})
	require.NoError(t, err)
	cls := classifier.New(auth, classifier.NewManager(nil))

	dd := dedup.New(ms, nil)
	pol := policy.New(nil, 168*time.Hour)
	em := &recordingEmitter{}
	eng := New(ms, reg, dd, cls, em, pol, nil)

	_, err = eng.Run(context.Background(), newTestConfig())
	require.NoError(t, err)

	em.mu.Lock()
	defer em.mu.Unlock()
	require.Len(t, em.events, 1)
	assert.Equal(t, model.EventUnauthorizedMachineDetected, em.events[0].EventType,
		"unauthorized override must still fire on no-change ticks")
}

func TestEngine_EmptyDiscovery(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name:     "test",
		machines: nil,
	})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)
	cfg := newTestConfig()

	result, err := eng.Run(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 0, result.NewMachines)
	assert.Equal(t, 0, result.UpdatedMachines)
	assert.Equal(t, 0, result.EventsEmitted)
}
