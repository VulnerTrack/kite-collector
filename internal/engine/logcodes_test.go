package engine

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogCodes_FollowConvention pins the `<package>.<surface>.<event>`
// shape so a future contributor can't accidentally ship a code that
// breaks downstream Loki/Splunk filters. Every code MUST:
//   - have exactly three dot-separated segments
//   - lead with the literal "engine." package prefix
//   - use snake_case lowercase for surface and event
func TestLogCodes_FollowConvention(t *testing.T) {
	codes := []LogCode{
		LogCodeDiscoveryStart,
		LogCodeDiscoveryDeadlineExceeded,
		LogCodeDiscoveryComplete,
		LogCodeAssetsFingerprintSnapshot,
		LogCodeAssetsPersisted,
		LogCodeStaleDetectFailed,
		LogCodeSoftwarePersistFailed,
		LogCodeSoftwarePersisted,
		LogCodeSoftwareParseError,
		LogCodeSoftwareParseTruncated,
		LogCodeAuditFailed,
		LogCodeAuditFindingsPersistFailed,
		LogCodeAuditComplete,
		LogCodeAuditCodeFailed,
		LogCodeAuditCodePersistFailed,
		LogCodeAuditCodeComplete,
		LogCodeAuditContainerEnvFailed,
		LogCodeAuditContainerEnvPersistFailed,
		LogCodeAuditContainerEnvComplete,
		LogCodeAuditContainerEnvNoSource,
		LogCodeAuditLDAPFailed,
		LogCodeAuditLDAPPersistFailed,
		LogCodeAuditEntraFailed,
		LogCodeAuditEntraPersistFailed,
		LogCodeAuditEntraSnapshotPersist,
		LogCodeAuditEntraTenantFailed,
		LogCodeAuditEntraTenantPersistFailed,
		LogCodeAuditEntraTenantComplete,
		LogCodeCloudDNSSnapshotPersist,
		LogCodeEventsPersistFailed,
		LogCodeEventsEmitFailed,
		LogCodeScanRunCompleteFailed,
		LogCodeScanRunComplete,
		LogCodeRetryAttemptFailed,
	}

	for _, c := range codes {
		s := string(c)
		t.Run(s, func(t *testing.T) {
			parts := strings.Split(s, ".")
			assert.GreaterOrEqual(t, len(parts), 3,
				"code %q must have at least 3 dot-separated segments (package.surface.event)", s)
			assert.Equal(t, "engine", parts[0],
				"code %q must lead with the engine package prefix", s)
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
		LogCodeDiscoveryStart, LogCodeDiscoveryDeadlineExceeded, LogCodeDiscoveryComplete,
		LogCodeAssetsFingerprintSnapshot, LogCodeAssetsPersisted, LogCodeStaleDetectFailed,
		LogCodeSoftwarePersistFailed, LogCodeSoftwarePersisted, LogCodeSoftwareParseError, LogCodeSoftwareParseTruncated,
		LogCodeAuditFailed, LogCodeAuditFindingsPersistFailed, LogCodeAuditComplete,
		LogCodeAuditCodeFailed, LogCodeAuditCodePersistFailed, LogCodeAuditCodeComplete,
		LogCodeAuditContainerEnvFailed, LogCodeAuditContainerEnvPersistFailed,
		LogCodeAuditContainerEnvComplete, LogCodeAuditContainerEnvNoSource,
		LogCodeAuditLDAPFailed, LogCodeAuditLDAPPersistFailed,
		LogCodeAuditEntraFailed, LogCodeAuditEntraPersistFailed, LogCodeAuditEntraSnapshotPersist,
		LogCodeAuditEntraTenantFailed, LogCodeAuditEntraTenantPersistFailed, LogCodeAuditEntraTenantComplete,
		LogCodeCloudDNSSnapshotPersist,
		LogCodeEventsPersistFailed, LogCodeEventsEmitFailed,
		LogCodeScanRunCompleteFailed, LogCodeScanRunComplete,
		LogCodeRetryAttemptFailed,
	}
	for _, c := range all {
		assert.False(t, seen[c],
			"duplicate log code %q — every call site must have a unique identifier", string(c))
		seen[c] = true
	}
}
