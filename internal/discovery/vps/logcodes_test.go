package vps

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogCodes_FollowConvention pins the `vps.<surface>.<event>` shape.
// Surfaces are predominantly per-provider (vultr, scaleway, linode,
// kamatera, hostinger, hetzner, digitalocean, upcloud, ovhcloud) plus
// the shared `retry` surface for the HTTP retry helper used by every
// provider via apiClient.
func TestLogCodes_FollowConvention(t *testing.T) {
	codes := []LogCode{
		LogCodeVultrStarting, LogCodeVultrPaginationRejected, LogCodeVultrComplete,
		LogCodeScalewayStarting, LogCodeScalewayComplete,
		LogCodeLinodeStarting, LogCodeLinodeComplete,
		LogCodeKamateraStarting, LogCodeKamateraComplete,
		LogCodeHostingerStarting, LogCodeHostingerComplete,
		LogCodeHetznerStarting, LogCodeHetznerComplete,
		LogCodeDigitalOceanStarting, LogCodeDigitalOceanComplete,
		LogCodeUpCloudStarting, LogCodeUpCloudComplete,
		LogCodeOVHCloudStarting, LogCodeOVHCloudDedicatedDiscoverFailed,
		LogCodeOVHCloudVPSDiscoverFailed, LogCodeOVHCloudComplete,
		LogCodeOVHCloudSkipUnsafeDedicated, LogCodeOVHCloudGetDedicatedFailed,
		LogCodeOVHCloudSkipUnsafeVPS, LogCodeOVHCloudGetVPSFailed,
		LogCodeVPSRetryBackoff, LogCodeVPSRetryNetworkError,
		LogCodeVPSRetryRateLimited, LogCodeVPSRetryServerError,
	}
	for _, c := range codes {
		s := string(c)
		t.Run(s, func(t *testing.T) {
			parts := strings.Split(s, ".")
			assert.GreaterOrEqual(t, len(parts), 3,
				"code %q must have ≥3 dot-separated segments", s)
			assert.Equal(t, "vps", parts[0],
				"code %q must lead with the vps namespace prefix", s)
			assert.Equal(t, strings.ToLower(s), s,
				"code %q must be all lowercase", s)
			assert.NotContains(t, s, " ", "code %q must not contain spaces", s)
		})
	}
}

func TestLogCodes_AreUnique(t *testing.T) {
	seen := map[LogCode]bool{}
	for _, c := range []LogCode{
		LogCodeVultrStarting, LogCodeVultrPaginationRejected, LogCodeVultrComplete,
		LogCodeScalewayStarting, LogCodeScalewayComplete,
		LogCodeLinodeStarting, LogCodeLinodeComplete,
		LogCodeKamateraStarting, LogCodeKamateraComplete,
		LogCodeHostingerStarting, LogCodeHostingerComplete,
		LogCodeHetznerStarting, LogCodeHetznerComplete,
		LogCodeDigitalOceanStarting, LogCodeDigitalOceanComplete,
		LogCodeUpCloudStarting, LogCodeUpCloudComplete,
		LogCodeOVHCloudStarting, LogCodeOVHCloudDedicatedDiscoverFailed,
		LogCodeOVHCloudVPSDiscoverFailed, LogCodeOVHCloudComplete,
		LogCodeOVHCloudSkipUnsafeDedicated, LogCodeOVHCloudGetDedicatedFailed,
		LogCodeOVHCloudSkipUnsafeVPS, LogCodeOVHCloudGetVPSFailed,
		LogCodeVPSRetryBackoff, LogCodeVPSRetryNetworkError,
		LogCodeVPSRetryRateLimited, LogCodeVPSRetryServerError,
	} {
		assert.False(t, seen[c], "duplicate log code constant %q", string(c))
		seen[c] = true
	}
}
