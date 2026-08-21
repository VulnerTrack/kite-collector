package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hostMetricsConfig(interval string, enabled bool, endpoint string) *Config {
	c := &Config{}
	c.Streaming.OTLP.Endpoint = endpoint
	c.Streaming.OTLP.HostMetrics.Interval = interval
	c.Streaming.OTLP.HostMetrics.Enabled = enabled
	return c
}

// TestHostMetricsEnabled_DefaultsOff is R9: the feature ships inert. A
// checkout with no host_metrics block collects nothing and emits nothing.
func TestHostMetricsEnabled_DefaultsOff(t *testing.T) {
	assert.False(t, (&Config{}).HostMetricsEnabled())
}

// TestHostMetricsEnabled_RequiresAnEndpoint keeps the flag from promising
// something the agent cannot deliver: with no OTLP endpoint there is
// nowhere to send samples, so running the collector would burn CPU for
// nothing.
func TestHostMetricsEnabled_RequiresAnEndpoint(t *testing.T) {
	assert.False(t, hostMetricsConfig("", true, "").HostMetricsEnabled())
	assert.True(t, hostMetricsConfig("", true, "https://otel.example.com").HostMetricsEnabled())
	assert.False(t, hostMetricsConfig("", false, "https://otel.example.com").HostMetricsEnabled())
}

func TestHostMetricsInterval(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want time.Duration
	}{
		{"unset falls back to the default", "", DefaultHostMetricsInterval},
		{"honours a configured value", "5m", 5 * time.Minute},
		{"honours the floor exactly", "15s", MinHostMetricsInterval},
		{"unparseable falls back to the default", "every-minute", DefaultHostMetricsInterval},
		// Validate rejects a sub-floor value outright; this clamp is the
		// belt-and-braces path for a Config built without Validate (tests,
		// programmatic construction).
		{"clamps below the floor", "1s", MinHostMetricsInterval},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hostMetricsConfig(tc.in, true, "https://otel.example.com").
				HostMetricsInterval()
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestValidate_RejectsSubFloorHostMetricsInterval is R8's enforcement
// point. Rejecting rather than silently clamping matters: an operator who
// typed 1s wanted per-second metrics and needs to learn they cannot have
// them, at load time, not from a graph that looks wrong a week later.
func TestValidate_RejectsSubFloorHostMetricsInterval(t *testing.T) {
	err := hostMetricsConfig("1s", true, "https://otel.example.com").Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "below the 15s floor")
}

func TestValidate_RejectsUnparseableHostMetricsInterval(t *testing.T) {
	err := hostMetricsConfig("soon", true, "https://otel.example.com").Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "streaming.otlp.host_metrics.interval")
}

func TestValidate_AcceptsFloorAndAbove(t *testing.T) {
	for _, interval := range []string{"", "15s", "60s", "5m", "1h"} {
		require.NoError(
			t,
			hostMetricsConfig(interval, true, "https://otel.example.com").Validate(),
			"interval %q should be accepted", interval,
		)
	}
}

// TestValidate_RejectsSubFloorIntervalEvenWhenDisabled: the interval is
// validated whether or not the feature is on. A parked-but-invalid value
// that only fails on the day someone flips the flag is exactly the
// rollout surprise the flag exists to avoid.
func TestValidate_RejectsSubFloorIntervalEvenWhenDisabled(t *testing.T) {
	err := hostMetricsConfig("2s", false, "https://otel.example.com").Validate()
	require.Error(t, err)
}
