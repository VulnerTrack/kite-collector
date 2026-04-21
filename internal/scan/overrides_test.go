package scan

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
)

func baseConfig() *config.Config {
	return &config.Config{
		Discovery: config.DiscoveryConfig{
			Sources: map[string]config.SourceConfig{
				"network": {Enabled: true},
				"cloud":   {Enabled: true},
			},
		},
	}
}

func TestApplyOverrides_NoBody(t *testing.T) {
	cfg := baseConfig()
	out, err := ApplyOverrides(cfg, TriggerRequest{})
	require.NoError(t, err)
	assert.Same(t, cfg, out, "empty body must return the original cfg without allocating a copy")
}

func TestApplyOverrides_SubsetSources(t *testing.T) {
	cfg := baseConfig()
	out, err := ApplyOverrides(cfg, TriggerRequest{Sources: []string{"cloud"}})
	require.NoError(t, err)

	require.NotSame(t, cfg, out, "override must not mutate caller's cfg")
	assert.Len(t, out.Discovery.Sources, 1)
	_, ok := out.Discovery.Sources["cloud"]
	assert.True(t, ok)
	assert.Len(t, cfg.Discovery.Sources, 2, "original cfg untouched")
}

func TestApplyOverrides_OutOfBounds(t *testing.T) {
	cfg := baseConfig()
	_, err := ApplyOverrides(cfg, TriggerRequest{Sources: []string{"not-declared"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScopeOutOfBounds)
}

func TestApplyOverrides_UnknownScopeKey(t *testing.T) {
	cfg := baseConfig()
	_, err := ApplyOverrides(cfg, TriggerRequest{ScopeOverride: map[string]any{"world": []string{"all"}}})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrScopeOutOfBounds)
}

func TestApplyOverrides_KnownScopeKeyAccepted(t *testing.T) {
	cfg := baseConfig()
	_, err := ApplyOverrides(cfg, TriggerRequest{
		ScopeOverride: map[string]any{"include_sources": []string{"cloud"}},
	})
	require.NoError(t, err)
}

func TestApplyOverrides_NilConfig(t *testing.T) {
	_, err := ApplyOverrides(nil, TriggerRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, err))
}
