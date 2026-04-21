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
	"github.com/vulnertrack/kite-collector/internal/emitter"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/policy"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// ---------------------------------------------------------------------------
// In-memory mock store for engine tests
// ---------------------------------------------------------------------------

type mockStore struct {
	assets    map[string]model.Asset // keyed by natural_key
	software  map[uuid.UUID][]model.InstalledSoftware
	completed map[uuid.UUID]model.ScanResult
	events    []model.AssetEvent
	incidents []model.RuntimeIncident
	scanRuns  []model.ScanRun
	mu        sync.Mutex
}

func newMockStore() *mockStore {
	return &mockStore{
		assets:    make(map[string]model.Asset),
		software:  make(map[uuid.UUID][]model.InstalledSoftware),
		completed: make(map[uuid.UUID]model.ScanResult),
	}
}

func (m *mockStore) UpsertAsset(_ context.Context, asset model.Asset) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	asset.ComputeNaturalKey()
	m.assets[asset.NaturalKey] = asset
	return nil
}

func (m *mockStore) UpsertAssets(_ context.Context, assets []model.Asset) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var inserted, updated int
	for i := range assets {
		assets[i].ComputeNaturalKey()
		if _, exists := m.assets[assets[i].NaturalKey]; exists {
			updated++
		} else {
			inserted++
		}
		m.assets[assets[i].NaturalKey] = assets[i]
	}
	return inserted, updated, nil
}

func (m *mockStore) GetAssetByID(_ context.Context, id uuid.UUID) (*model.Asset, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.assets {
		if a.ID == id {
			cp := a
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *mockStore) GetAssetByNaturalKey(_ context.Context, key string) (*model.Asset, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.assets[key]
	if !ok {
		return nil, nil
	}
	cp := a
	return &cp, nil
}

func (m *mockStore) ListAssets(_ context.Context, _ store.AssetFilter) ([]model.Asset, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]model.Asset, 0, len(m.assets))
	for _, a := range m.assets {
		result = append(result, a)
	}
	return result, nil
}

func (m *mockStore) GetStaleAssets(_ context.Context, threshold time.Duration) ([]model.Asset, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().UTC().Add(-threshold)
	var stale []model.Asset
	for _, a := range m.assets {
		if a.LastSeenAt.Before(cutoff) {
			stale = append(stale, a)
		}
	}
	return stale, nil
}

func (m *mockStore) InsertEvent(_ context.Context, event model.AssetEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockStore) InsertEvents(_ context.Context, events []model.AssetEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, events...)
	return nil
}

func (m *mockStore) ListEvents(_ context.Context, _ store.EventFilter) ([]model.AssetEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]model.AssetEvent, len(m.events))
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
			m.scanRuns[i].TotalAssets = result.TotalAssets
			m.scanRuns[i].NewAssets = result.NewAssets
			m.scanRuns[i].UpdatedAssets = result.UpdatedAssets
			m.scanRuns[i].StaleAssets = result.StaleAssets
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

func (m *mockStore) UpsertSoftware(_ context.Context, assetID uuid.UUID, sw []model.InstalledSoftware) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.software[assetID] = sw
	return nil
}

func (m *mockStore) ListSoftware(_ context.Context, assetID uuid.UUID) ([]model.InstalledSoftware, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.software[assetID], nil
}

func (m *mockStore) InsertFindings(_ context.Context, _ []model.ConfigFinding) error {
	return nil
}

func (m *mockStore) ListFindings(_ context.Context, _ store.FindingFilter) ([]model.ConfigFinding, error) {
	return nil, nil
}

func (m *mockStore) InsertPostureAssessments(_ context.Context, _ []model.PostureAssessment) error {
	return nil
}

func (m *mockStore) ListPostureAssessments(_ context.Context, _ store.PostureFilter) ([]model.PostureAssessment, error) {
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

var _ store.Store = (*mockStore)(nil)

// ---------------------------------------------------------------------------
// Mock discovery source
// ---------------------------------------------------------------------------

type mockSource struct {
	name   string
	assets []model.Asset
}

func (s *mockSource) Name() string { return s.name }
func (s *mockSource) Discover(_ context.Context, _ map[string]any) ([]model.Asset, error) {
	return s.assets, nil
}

// ---------------------------------------------------------------------------
// Mock emitter that records emitted events
// ---------------------------------------------------------------------------

type recordingEmitter struct {
	events []model.AssetEvent
	mu     sync.Mutex
}

func (e *recordingEmitter) Emit(_ context.Context, event model.AssetEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
	return nil
}

func (e *recordingEmitter) EmitBatch(_ context.Context, events []model.AssetEvent) error {
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
		assets: []model.Asset{
			{Hostname: "web-01", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
			{Hostname: "db-01", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
		},
	})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)
	cfg := newTestConfig()

	result, err := eng.Run(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 2, result.NewAssets)
	assert.Equal(t, 0, result.UpdatedAssets)
	assert.Equal(t, 2, result.TotalAssets)
	assert.Greater(t, result.EventsEmitted, 0)
}

func TestEngine_ScanRunCreatedAndCompleted(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		assets: []model.Asset{
			{Hostname: "host-01", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
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

func TestEngine_NewAssetsGenerateDiscoveredEvents(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		assets: []model.Asset{
			{Hostname: "new-host", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
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
		if evt.EventType == model.EventAssetDiscovered {
			discoveredEvents++
		}
	}
	assert.Equal(t, 1, discoveredEvents, "one AssetDiscovered event expected for a new asset")
}

func TestEngine_UnauthorizedAssetsGenerateEvent(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		assets: []model.Asset{
			{Hostname: "rogue-host", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
		},
	})

	em := &recordingEmitter{}

	// Use a classifier that always returns unauthorized by writing an
	// allowlist file that does not match any discovered asset.
	allowlistPath := filepath.Join(t.TempDir(), "allowlist.yaml")
	err := os.WriteFile(allowlistPath, []byte("assets:\n  - hostname: \"only-this-one\"\n"), 0o644)
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
		if evt.EventType == model.EventUnauthorizedAssetDetected {
			unauthEvents++
		}
	}
	assert.Equal(t, 1, unauthEvents, "one UnauthorizedAssetDetected event expected")
}

func TestEngine_StaleAssetsGenerateNotSeenEvents(t *testing.T) {
	ms := newMockStore()

	// Pre-populate store with a stale asset.
	staleAsset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "old-server",
		AssetType:       model.AssetTypeServer,
		DiscoverySource: "test",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		FirstSeenAt:     time.Now().UTC().Add(-300 * time.Hour),
		LastSeenAt:      time.Now().UTC().Add(-300 * time.Hour),
	}
	staleAsset.ComputeNaturalKey()
	ms.assets[staleAsset.NaturalKey] = staleAsset

	// Discovery returns only a different asset (the stale one is not rediscovered).
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		assets: []model.Asset{
			{Hostname: "active-server", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
		},
	})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)
	cfg := newTestConfig()

	result, err := eng.Run(context.Background(), cfg)
	require.NoError(t, err)

	assert.Equal(t, 1, result.StaleAssets, "one stale asset should be detected")

	em.mu.Lock()
	defer em.mu.Unlock()

	var notSeenEvents int
	for _, evt := range em.events {
		if evt.EventType == model.EventAssetNotSeen {
			notSeenEvents++
		}
	}
	assert.Equal(t, 1, notSeenEvents, "one AssetNotSeen event expected for the stale asset")
}

// ---------------------------------------------------------------------------
// Slow source for deadline tests
// ---------------------------------------------------------------------------

type slowSource struct {
	name  string
	delay time.Duration
}

func (s *slowSource) Name() string { return s.name }
func (s *slowSource) Discover(ctx context.Context, _ map[string]any) ([]model.Asset, error) {
	select {
	case <-time.After(s.delay):
		return []model.Asset{
			{Hostname: "slow-host", AssetType: model.AssetTypeServer, DiscoverySource: s.name},
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
}

func TestEngine_ScanDeadlineNotExceeded(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		assets: []model.Asset{
			{Hostname: "fast-host", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
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

func TestEngine_EmptyDiscovery(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name:   "test",
		assets: nil,
	})

	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)
	cfg := newTestConfig()

	result, err := eng.Run(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 0, result.NewAssets)
	assert.Equal(t, 0, result.UpdatedAssets)
	assert.Equal(t, 0, result.EventsEmitted)
}
