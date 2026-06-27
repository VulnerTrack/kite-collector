package rest

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogCodes_FollowConvention pins the `rest.<surface>.<event>` shape.
// Every code must have ≥3 dot-separated segments, lead with the "rest"
// namespace, be all lowercase, and contain no spaces.
func TestLogCodes_FollowConvention(t *testing.T) {
	codes := []LogCode{
		LogCodeRequestReceived,
		LogCodeMiddlewarePanicRecovered,
		LogCodeMiddlewareResponseTruncated,
		LogCodeAssetsGetByID, LogCodeAssetsList,
		LogCodeEventsList,
		LogCodeScansGetLatest, LogCodeScansGetByID,
		LogCodeScansStart, LogCodeScansMarkCancel, LogCodeScansCoordinatorCancel,
		LogCodeScansSSESnapshotWrite, LogCodeScansSSEWrite,
		LogCodeRuntimeIncidentsList, LogCodeNetworkScanEventsList,
		LogCodeNetworkOpenPortsList, LogCodeSafetyGuardEventsList,
	}
	for _, c := range codes {
		s := string(c)
		t.Run(s, func(t *testing.T) {
			parts := strings.Split(s, ".")
			assert.GreaterOrEqual(t, len(parts), 3,
				"code %q must have ≥3 dot-separated segments", s)
			assert.Equal(t, "rest", parts[0],
				"code %q must lead with the rest namespace prefix", s)
			assert.Equal(t, strings.ToLower(s), s,
				"code %q must be all lowercase", s)
			assert.NotContains(t, s, " ", "code %q must not contain spaces", s)
		})
	}
}

// TestLogCodes_AreUnique pins the no-duplicate-constant rule.
// Multiple call sites may intentionally share a code (e.g., the request-
// received entry log on every handler, the three get-scan-run-failed
// store-failure paths, the two response-truncated middleware paths).
// This test only catches accidental constant duplication.
func TestLogCodes_AreUnique(t *testing.T) {
	seen := map[LogCode]bool{}
	for _, c := range []LogCode{
		LogCodeRequestReceived,
		LogCodeMiddlewarePanicRecovered,
		LogCodeMiddlewareResponseTruncated,
		LogCodeAssetsGetByID, LogCodeAssetsList,
		LogCodeEventsList,
		LogCodeScansGetLatest, LogCodeScansGetByID,
		LogCodeScansStart, LogCodeScansMarkCancel, LogCodeScansCoordinatorCancel,
		LogCodeScansSSESnapshotWrite, LogCodeScansSSEWrite,
		LogCodeRuntimeIncidentsList, LogCodeNetworkScanEventsList,
		LogCodeNetworkOpenPortsList, LogCodeSafetyGuardEventsList,
	} {
		assert.False(t, seen[c],
			"duplicate log code constant %q", string(c))
		seen[c] = true
	}
}
