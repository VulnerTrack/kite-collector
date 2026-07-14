package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogCodes_FollowConvention pins the `agent.<surface>.<event>`
// shape so a future contributor can't accidentally ship a code that
// breaks downstream Loki/Splunk filters. Every code MUST:
//   - have at least 3 dot-separated segments
//   - lead with the literal "agent." namespace (matches operator mental model
//     for "the agent binary"; deliberately NOT the package name "main")
//   - use snake_case lowercase for surface and event
func TestLogCodes_FollowConvention(t *testing.T) {
	codes := []LogCode{
		LogCodeBootstrapDataDirNotWritable,
		LogCodeTunnelStartFailed, LogCodeTunnelRewroteEndpoint,
		LogCodeStorePostgresSelected, LogCodeStoreSQLiteSelected,
		LogCodeTelemetryIdentityUnavailable, LogCodeTelemetryOTLPConfigured, LogCodeTelemetryOTLPDisabled,
		LogCodeAPIStarting, LogCodeAPIServerFailed,
		LogCodeDashboardStarting, LogCodeDashboardServerFailed,
		LogCodeDashboardListening, LogCodeDashboardListenerFailed,
		LogCodeScanStreamingStarting, LogCodeScanInitialFailed, LogCodeScanInitialComplete,
		LogCodeScanPeriodicFailed, LogCodeScanPeriodicComplete,
		LogCodeAgentShutdown,
		LogCodeEngineIdentityUnavailable,
		LogCodeCLIFlushWriter, LogCodeCLIConfigLoadFallback,
		LogCodeEnrollRequestSubmitted, LogCodeEnrollComplete,
		LogCodeLoginTokenAcquired,
	}

	for _, c := range codes {
		s := string(c)
		t.Run(s, func(t *testing.T) {
			parts := strings.Split(s, ".")
			assert.GreaterOrEqual(t, len(parts), 3,
				"code %q must have at least 3 dot-separated segments (namespace.surface.event)", s)
			assert.Equal(t, "agent", parts[0],
				"code %q must lead with the agent namespace prefix", s)
			assert.Equal(t, strings.ToLower(s), s,
				"code %q must be all lowercase for grep-friendliness", s)
			assert.NotContains(t, s, " ",
				"code %q must not contain spaces — use underscores between words", s)
		})
	}
}

// TestLogCodes_AreUnique pins the no-duplicate-code rule. Two log call
// sites sharing the same code would make downstream alerts ambiguous
// about which surface actually fired.
func TestLogCodes_AreUnique(t *testing.T) {
	seen := map[LogCode]bool{}
	all := []LogCode{
		LogCodeBootstrapDataDirNotWritable,
		LogCodeTunnelStartFailed, LogCodeTunnelRewroteEndpoint,
		LogCodeStorePostgresSelected, LogCodeStoreSQLiteSelected,
		LogCodeTelemetryIdentityUnavailable, LogCodeTelemetryOTLPConfigured, LogCodeTelemetryOTLPDisabled,
		LogCodeAPIStarting, LogCodeAPIServerFailed,
		LogCodeDashboardStarting, LogCodeDashboardServerFailed,
		LogCodeDashboardListening, LogCodeDashboardListenerFailed,
		LogCodeScanStreamingStarting, LogCodeScanInitialFailed, LogCodeScanInitialComplete,
		LogCodeScanPeriodicFailed, LogCodeScanPeriodicComplete,
		LogCodeAgentShutdown,
		LogCodeEngineIdentityUnavailable,
		LogCodeCLIFlushWriter, LogCodeCLIConfigLoadFallback,
		LogCodeEnrollRequestSubmitted, LogCodeEnrollComplete,
		LogCodeLoginTokenAcquired,
	}
	for _, c := range all {
		assert.False(t, seen[c],
			"duplicate log code %q — every call site must have a unique identifier", string(c))
		seen[c] = true
	}
}
