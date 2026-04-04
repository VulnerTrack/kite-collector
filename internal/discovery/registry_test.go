package discovery

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
)

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

// failingSource always returns an error.
type failingSource struct {
	name string
}

func (f *failingSource) Name() string { return f.name }

func (f *failingSource) Discover(_ context.Context, _ map[string]any) ([]model.Asset, error) {
	return nil, errors.New("simulated failure")
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
	reg := NewRegistry()
	assets, err := reg.DiscoverAll(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
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

func TestRegistry_Register(t *testing.T) {
	reg := NewRegistry()
	assert.Empty(t, reg.sources)

	reg.Register(&fixedSource{name: "a"})
	assert.Len(t, reg.sources, 1)

	reg.Register(&fixedSource{name: "b"})
	assert.Len(t, reg.sources, 2)
}
