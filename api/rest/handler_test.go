package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	scanRun  *model.ScanRun
	software map[uuid.UUID][]model.InstalledSoftware
	machines []model.Machine
	events   []model.MachineEvent
	mu       sync.Mutex
}

func newMockStore() *mockStore {
	return &mockStore{
		software: make(map[uuid.UUID][]model.InstalledSoftware),
	}
}

func (m *mockStore) UpsertMachine(_ context.Context, machine model.Machine) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.machines = append(m.machines, machine)
	return nil
}

func (m *mockStore) UpsertMachines(_ context.Context, machines []model.Machine) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.machines = append(m.machines, machines...)
	return len(machines), 0, nil
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

func (m *mockStore) GetMachineByNaturalKey(_ context.Context, _ string) (*model.Machine, error) {
	return nil, nil
}

func (m *mockStore) GetMachinesByNaturalKeys(_ context.Context, _ []string) (map[string]model.Machine, error) {
	return nil, nil
}

func (m *mockStore) ListMachines(_ context.Context, _ store.MachineFilter) ([]model.Machine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]model.Machine, len(m.machines))
	copy(cp, m.machines)
	return cp, nil
}

func (m *mockStore) GetStaleMachines(_ context.Context, _ time.Duration) ([]model.Machine, error) {
	return nil, nil
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
	m.scanRun = &run
	return nil
}

func (m *mockStore) CompleteScanRun(_ context.Context, _ uuid.UUID, _ model.ScanResult) error {
	return nil
}

func (m *mockStore) GetLatestScanRun(_ context.Context) (*model.ScanRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scanRun == nil {
		return nil, nil
	}
	cp := *m.scanRun
	return &cp, nil
}

func (m *mockStore) GetScanRun(_ context.Context, id uuid.UUID) (*model.ScanRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scanRun == nil || m.scanRun.ID != id {
		return nil, store.ErrNotFound
	}
	cp := *m.scanRun
	return &cp, nil
}

func (m *mockStore) ListScanRuns(_ context.Context, _ int) ([]model.ScanRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scanRun == nil {
		return []model.ScanRun{}, nil
	}
	cp := *m.scanRun
	return []model.ScanRun{cp}, nil
}

func (m *mockStore) MarkScanCancelRequested(_ context.Context, id uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scanRun == nil || m.scanRun.ID != id {
		return store.ErrNotFound
	}
	t := at
	m.scanRun.CancelRequestedAt = &t
	return nil
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
func (m *mockStore) Close() error                    { return nil }

func (m *mockStore) ListContentTables(_ context.Context) ([]store.TableSchema, error) {
	return nil, nil
}

func (m *mockStore) DescribeTable(_ context.Context, _ string) (*store.TableSchema, error) {
	return nil, store.ErrUnknownTable
}

func (m *mockStore) FacetTable(_ context.Context, _ string, _, _ int) ([]store.ColumnFacet, error) {
	return nil, store.ErrUnknownTable
}

func (m *mockStore) ListJoinedRows(_ context.Context, _ store.JoinFilter) ([]store.Row, error) {
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
// Tests
// ---------------------------------------------------------------------------

func TestHealthEndpoint(t *testing.T) {
	ms := newMockStore()
	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "ok", body["status"])
}

func TestListMachines_EmptyStore(t *testing.T) {
	ms := newMockStore()
	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/machines", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Should return an empty JSON array, not null.
	var body []any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Len(t, body, 0)
}

func TestListMachines_ReturnsMachines(t *testing.T) {
	ms := newMockStore()
	now := time.Now().UTC().Truncate(time.Second)
	ms.machines = []model.Machine{
		{
			ID:              uuid.Must(uuid.NewV7()),
			Hostname:        "web-01",
			MachineType:     model.MachineTypeServer,
			IsAuthorized:    model.AuthorizationAuthorized,
			IsManaged:       model.ManagedManaged,
			DiscoverySource: "test",
			FirstSeenAt:     now,
			LastSeenAt:      now,
		},
		{
			ID:              uuid.Must(uuid.NewV7()),
			Hostname:        "db-01",
			MachineType:     model.MachineTypeServer,
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       model.ManagedUnknown,
			DiscoverySource: "test",
			FirstSeenAt:     now,
			LastSeenAt:      now,
		},
	}

	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/machines", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body []map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Len(t, body, 2)
}

func TestGetMachineByID_NotFound(t *testing.T) {
	ms := newMockStore()
	h := New(ms, nil)
	mux := h.Mux()

	unknownID := uuid.Must(uuid.NewV7())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/machines/"+unknownID.String(), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "machine not found", body["error"])
}

func TestGetMachineByID_Found(t *testing.T) {
	ms := newMockStore()
	machineID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Second)
	ms.machines = []model.Machine{
		{
			ID:              machineID,
			Hostname:        "found-host",
			MachineType:     model.MachineTypeServer,
			IsAuthorized:    model.AuthorizationAuthorized,
			IsManaged:       model.ManagedManaged,
			DiscoverySource: "test",
			FirstSeenAt:     now,
			LastSeenAt:      now,
		},
	}

	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/machines/"+machineID.String(), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "found-host", body["hostname"])
}

func TestGetMachineByID_InvalidUUID(t *testing.T) {
	ms := newMockStore()
	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/machines/not-a-uuid", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestListEvents_EmptyStore(t *testing.T) {
	ms := newMockStore()
	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/events", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body []any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Len(t, body, 0)
}

func TestLatestScan_NoScans(t *testing.T) {
	ms := newMockStore()
	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/scans/latest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "no scan runs found", body["error"])
}

func TestLatestScan_ReturnsScan(t *testing.T) {
	ms := newMockStore()
	scanID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Second)
	ms.scanRun = &model.ScanRun{
		ID:        scanID,
		StartedAt: now,
		Status:    model.ScanStatusCompleted,
	}

	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/scans/latest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, scanID.String(), body["id"])
	assert.Equal(t, string(model.ScanStatusCompleted), body["status"])
}

func TestListScans_Empty(t *testing.T) {
	ms := newMockStore()
	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/scans", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body []any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Len(t, body, 0)
}
