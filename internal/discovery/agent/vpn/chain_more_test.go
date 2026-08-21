package vpn

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type scriptedCollector struct {
	name     string
	profiles []Profile
	err      error
}

func (s scriptedCollector) Name() string { return s.name }
func (s scriptedCollector) Collect(context.Context) ([]Profile, error) {
	return s.profiles, s.err
}

// The default chain constructs every source collector and runs them all
// against the real (read-only) host: missing tools and absent config
// files must degrade to skips and warnings, never an error.
func TestNewChainCollector_SmokeRunOnRealHost(t *testing.T) {
	chain := NewChainCollector()
	assert.Equal(t, "vpn-profiles", chain.Name())

	profiles, err := chain.Collect(context.Background())
	require.NoError(t, err, "per-source failures are logged, not returned")
	for _, p := range profiles {
		assert.NotEmpty(t, string(p.Type), "every collected profile carries its type")
	}
}

// One failing source must not drop the others' profiles.
func TestChainCollector_IsolatesSourceFailures(t *testing.T) {
	chain := &chainCollector{collectors: []Collector{
		scriptedCollector{name: "broken", err: errors.New("parse exploded")},
		scriptedCollector{name: "ok", profiles: []Profile{{Type: TypeWireGuard, Name: "wg0"}}},
	}}
	profiles, err := chain.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, profiles, 1)
	assert.Equal(t, "wg0", profiles[0].Name)
}

// The MaxProfiles cap truncates deterministically (sorted) and stops
// invoking later sources.
func TestChainCollector_CapStopsLaterSources(t *testing.T) {
	big := make([]Profile, MaxProfiles+5)
	for i := range big {
		big[i] = Profile{Type: TypeOpenVPN, Name: fmt.Sprintf("p-%05d", i)}
	}
	var laterRan bool
	later := scriptedCollector{name: "later"}
	chain := &chainCollector{collectors: []Collector{
		scriptedCollector{name: "flood", profiles: big},
		collectorFunc(func(ctx context.Context) ([]Profile, error) {
			laterRan = true
			return later.Collect(ctx)
		}),
	}}
	profiles, err := chain.Collect(context.Background())
	require.NoError(t, err)
	assert.Len(t, profiles, MaxProfiles, "output is capped exactly at MaxProfiles")
	assert.False(t, laterRan, "sources after the cap must not run")
}

type collectorFunc func(ctx context.Context) ([]Profile, error)

func (collectorFunc) Name() string { return "func" }
func (f collectorFunc) Collect(ctx context.Context) ([]Profile, error) {
	return f(ctx)
}

func TestChainCollector_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	chain := &chainCollector{collectors: []Collector{
		scriptedCollector{name: "never", profiles: []Profile{{Name: "x"}}},
	}}
	_, err := chain.Collect(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cancelled")
}
