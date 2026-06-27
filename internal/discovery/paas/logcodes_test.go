package paas

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogCodes_FollowConvention pins the `paas.<surface>.<event>` shape.
// Surfaces are predominantly per-provider (vercel, render, heroku,
// coolify, railway, flyio, caprover) plus the shared `retry` surface
// for the HTTP retry helper used by every provider via apiClient.
func TestLogCodes_FollowConvention(t *testing.T) {
	codes := []LogCode{
		LogCodeVercelStarting, LogCodeVercelComplete,
		LogCodeRenderStarting, LogCodeRenderPaginationRejected, LogCodeRenderComplete,
		LogCodeHerokuStarting, LogCodeHerokuComplete,
		LogCodeCoolifyStarting, LogCodeCoolifyListServersFailed, LogCodeCoolifyComplete,
		LogCodeRailwayStarting, LogCodeRailwayComplete,
		LogCodeFlyIOStarting, LogCodeFlyIOInvalidAppName,
		LogCodeFlyIOListMachinesFailed, LogCodeFlyIOComplete,
		LogCodeCapRoverStarting, LogCodeCapRoverComplete,
		LogCodePaaSRetryBackoff, LogCodePaaSRetryNetworkError,
		LogCodePaaSRetryRateLimited, LogCodePaaSRetryServerError,
	}
	for _, c := range codes {
		s := string(c)
		t.Run(s, func(t *testing.T) {
			parts := strings.Split(s, ".")
			assert.GreaterOrEqual(t, len(parts), 3,
				"code %q must have ≥3 dot-separated segments", s)
			assert.Equal(t, "paas", parts[0],
				"code %q must lead with the paas namespace prefix", s)
			assert.Equal(t, strings.ToLower(s), s,
				"code %q must be all lowercase", s)
			assert.NotContains(t, s, " ", "code %q must not contain spaces", s)
		})
	}
}

func TestLogCodes_AreUnique(t *testing.T) {
	seen := map[LogCode]bool{}
	for _, c := range []LogCode{
		LogCodeVercelStarting, LogCodeVercelComplete,
		LogCodeRenderStarting, LogCodeRenderPaginationRejected, LogCodeRenderComplete,
		LogCodeHerokuStarting, LogCodeHerokuComplete,
		LogCodeCoolifyStarting, LogCodeCoolifyListServersFailed, LogCodeCoolifyComplete,
		LogCodeRailwayStarting, LogCodeRailwayComplete,
		LogCodeFlyIOStarting, LogCodeFlyIOInvalidAppName,
		LogCodeFlyIOListMachinesFailed, LogCodeFlyIOComplete,
		LogCodeCapRoverStarting, LogCodeCapRoverComplete,
		LogCodePaaSRetryBackoff, LogCodePaaSRetryNetworkError,
		LogCodePaaSRetryRateLimited, LogCodePaaSRetryServerError,
	} {
		assert.False(t, seen[c], "duplicate log code constant %q", string(c))
		seen[c] = true
	}
}
