package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// captureRecorder collects every heartbeat the registry emits so tests can
// assert on cardinality and per-source status without standing up the real
// observability stack.
type captureRecorder struct {
	events []recordedHeartbeat
	mu     sync.Mutex
}

type recordedHeartbeat struct {
	Source       string
	Status       model.HeartbeatStatus
	ItemsEmitted int
	Duration     time.Duration
}

func (c *captureRecorder) Record(_ context.Context, source string, status model.HeartbeatStatus, items int, d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, recordedHeartbeat{source, status, items, d})
	return nil
}

func (c *captureRecorder) snapshot() []recordedHeartbeat {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]recordedHeartbeat, len(c.events))
	copy(out, c.events)
	return out
}

// ---------------------------------------------------------------------------
// Mock sources
// ---------------------------------------------------------------------------

// fixedSource returns a predetermined set of assets.
type fixedSource struct {
	name   string
	assets []model.Asset
}

func (f *fixedSource) Name() string { return f.name }

func (f *fixedSource) Discover(_ context.Context, _ map[string]any) ([]model.Asset, error) {
	return f.assets, nil
}

// panickingSource panics during Discover.
type panickingSource struct {
	name string
}

func (p *panickingSource) Name() string { return p.name }

func (p *panickingSource) Discover(_ context.Context, _ map[string]any) ([]model.Asset, error) {
	panic("nil pointer dereference")
}

// failingSource always returns an error.
type failingSource struct {
	name string
}

func (f *failingSource) Name() string { return f.name }

func (f *failingSource) Discover(_ context.Context, _ map[string]any) ([]model.Asset, error) {
	return nil, errors.New("simulated failure")
}

// structuredFailingSource returns a catalogued *kiteerrors.Error so tests can
// assert the registry surfaces the flat structured envelope.
type structuredFailingSource struct {
	name string
}

func (f *structuredFailingSource) Name() string { return f.name }

func (f *structuredFailingSource) Discover(_ context.Context, _ map[string]any) ([]model.Asset, error) {
	return nil, kiteerrors.FromCatalog("KITE-E002", nil).With("phase", "auth")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestRegistry_DiscoverAll_RunsAllSources(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&fixedSource{
		name: "src1",
		assets: []model.Asset{
			{Hostname: "host-a", AssetType: model.AssetTypeServer},
		},
	})
	reg.Register(&fixedSource{
		name: "src2",
		assets: []model.Asset{
			{Hostname: "host-b", AssetType: model.AssetTypeWorkstation},
			{Hostname: "host-c", AssetType: model.AssetTypeContainer},
		},
	})

	configs := map[string]map[string]any{
		"src1": {},
		"src2": {},
	}

	assets, err := reg.DiscoverAll(context.Background(), configs)
	require.NoError(t, err)
	assert.Len(t, assets, 3, "all assets from all sources must be returned")
}

func TestRegistry_DiscoverAll_EmptyRegistry(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	reg := NewRegistry()
	assets, err := reg.DiscoverAll(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)

	// The silent no-op is now explained via the catalogued KITE-E009 envelope.
	var rec map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["error_code"] == "KITE-E009" {
			rec = m
			break
		}
	}
	require.NotNil(t, rec, "expected a KITE-E009 log line for the empty registry")
	assert.NotEmpty(t, rec["hint"], "E009 remediation hint must be present")
}

func TestRegistry_FailedSource_LogsFlatStructuredEnvelope(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	reg := NewRegistry()
	reg.Register(&structuredFailingSource{name: "wazuh"})

	_, err := reg.DiscoverAll(context.Background(), map[string]map[string]any{"wazuh": {}})
	require.NoError(t, err, "a failing source must not abort the run")

	var rec map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == "discovery source failed" {
			rec = m
			break
		}
	}
	require.NotNil(t, rec, "expected a 'discovery source failed' log line")

	// The catalog code/hint must appear as TOP-LEVEL fields, not nested.
	assert.Equal(t, "KITE-E002", rec["error_code"])
	assert.NotEmpty(t, rec["hint"])
	// Stable pivots preserved alongside the envelope.
	assert.Equal(t, string(LogCodeRegistrySourceFailed), rec["code"])
	assert.Equal(t, "wazuh", rec["source"])
	ctx, ok := rec["error_context"].(map[string]any)
	require.True(t, ok, "error_context must be an object")
	assert.Equal(t, "auth", ctx["phase"])
}

func TestRegistry_FailedSourceDoesNotAbortOthers(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&fixedSource{
		name: "good",
		assets: []model.Asset{
			{Hostname: "good-host", AssetType: model.AssetTypeServer},
		},
	})
	reg.Register(&failingSource{name: "bad"})

	configs := map[string]map[string]any{
		"good": {},
		"bad":  {},
	}

	assets, err := reg.DiscoverAll(context.Background(), configs)
	require.NoError(t, err)
	assert.Len(t, assets, 1, "assets from the successful source must still be returned")
	assert.Equal(t, "good-host", assets[0].Hostname)
}

func TestRegistry_AllSourcesFail(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&failingSource{name: "fail1"})
	reg.Register(&failingSource{name: "fail2"})

	configs := map[string]map[string]any{
		"fail1": {},
		"fail2": {},
	}

	assets, err := reg.DiscoverAll(context.Background(), configs)
	require.NoError(t, err, "per-source failures are logged, not returned as errors")
	assert.Empty(t, assets)
}

func TestRegistry_PanickingSourceDoesNotAbortOthers(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&fixedSource{
		name: "good",
		assets: []model.Asset{
			{Hostname: "host-a", AssetType: model.AssetTypeServer},
		},
	})
	reg.Register(&panickingSource{name: "bad"})

	configs := map[string]map[string]any{
		"good": {},
		"bad":  {},
	}

	assets, err := reg.DiscoverAll(context.Background(), configs)
	require.NoError(t, err)
	assert.Len(t, assets, 1, "assets from good source must be returned despite panic in bad source")
	assert.Equal(t, "host-a", assets[0].Hostname)
}

func TestRegistry_AllSourcesPanic(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&panickingSource{name: "panic1"})
	reg.Register(&panickingSource{name: "panic2"})

	configs := map[string]map[string]any{
		"panic1": {},
		"panic2": {},
	}

	assets, err := reg.DiscoverAll(context.Background(), configs)
	require.NoError(t, err, "panics are recovered, not returned as errors")
	assert.Empty(t, assets)
}

func TestRegistry_Register(t *testing.T) {
	reg := NewRegistry()
	assert.Empty(t, reg.sources)

	reg.Register(&fixedSource{name: "a"})
	assert.Len(t, reg.sources, 1)

	reg.Register(&fixedSource{name: "b"})
	assert.Len(t, reg.sources, 2)
}

func TestRegistry_DiscoverAll_EmitsHeartbeatPerSource(t *testing.T) {
	reg := NewRegistry()
	rec := &captureRecorder{}
	reg.SetHeartbeatRecorder(rec)

	reg.Register(&fixedSource{
		name: "good",
		assets: []model.Asset{
			{Hostname: "h1", AssetType: model.AssetTypeServer},
		},
	})
	reg.Register(&failingSource{name: "bad"})
	reg.Register(&panickingSource{name: "panic"})

	_, err := reg.DiscoverAll(context.Background(), map[string]map[string]any{
		"good": {}, "bad": {}, "panic": {},
	})
	require.NoError(t, err)

	events := rec.snapshot()
	// "good" + "bad" emit heartbeats; the panicking source recovers via
	// safety.Recover before the heartbeat call, so it does NOT emit. This
	// is the canonical "silent failure" the reconciler must catch by
	// noticing the missing collector against the canary baseline.
	byStatus := map[string]int{}
	bySource := map[string]model.HeartbeatStatus{}
	for _, e := range events {
		byStatus[string(e.Status)]++
		bySource[e.Source] = e.Status
	}
	assert.Equal(t, model.HeartbeatOK, bySource["good"], "successful source emits ok")
	assert.Equal(t, model.HeartbeatError, bySource["bad"], "failing source emits error")
	_, ok := bySource["panic"]
	assert.False(t, ok, "panicking source emits no heartbeat (canary diff is the safety net)")
	assert.Equal(t, 1, byStatus["ok"])
	assert.Equal(t, 1, byStatus["error"])
}

func TestRegistry_DiscoverAll_NilRecorderIsNoop(t *testing.T) {
	// Existing callers (tests, the introspection CLI) construct a Registry
	// without setting a recorder. That path must remain operational and
	// must not panic.
	reg := NewRegistry()
	reg.Register(&fixedSource{
		name:   "src",
		assets: []model.Asset{{Hostname: "h", AssetType: model.AssetTypeServer}},
	})
	assets, err := reg.DiscoverAll(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, assets, 1)
}
