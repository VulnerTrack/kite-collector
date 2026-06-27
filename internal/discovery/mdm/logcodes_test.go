package mdm

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogCodes_FollowConvention pins the `mdm.<provider>.<event>` shape.
// Surfaces are per-provider (jamf, intune, sccm) because remediation
// for each MDM platform routes to a different team — macOS fleet ops
// for Jamf, Microsoft 365 admins for Intune, on-prem ConfigMgr
// operators for SCCM.
func TestLogCodes_FollowConvention(t *testing.T) {
	codes := []LogCode{
		LogCodeJamfStarting, LogCodeJamfCredsMissing, LogCodeJamfAuthFailed,
		LogCodeJamfComputersFetched, LogCodeJamfDetailFetchFailed, LogCodeJamfComplete,
		LogCodeIntuneStarting, LogCodeIntuneCredsMissing, LogCodeIntuneTokenAcquireFailed,
		LogCodeIntuneSkipUnparseable, LogCodeIntuneComplete,
		LogCodeSCCMStarting, LogCodeSCCMCredsMissing, LogCodeSCCMAuthFailed,
		LogCodeSCCMSkipUnparseable, LogCodeSCCMComplete,
	}
	for _, c := range codes {
		s := string(c)
		t.Run(s, func(t *testing.T) {
			parts := strings.Split(s, ".")
			assert.GreaterOrEqual(t, len(parts), 3,
				"code %q must have ≥3 dot-separated segments", s)
			assert.Equal(t, "mdm", parts[0],
				"code %q must lead with the mdm namespace prefix", s)
			assert.Equal(t, strings.ToLower(s), s,
				"code %q must be all lowercase", s)
			assert.NotContains(t, s, " ", "code %q must not contain spaces", s)
		})
	}
}

func TestLogCodes_AreUnique(t *testing.T) {
	seen := map[LogCode]bool{}
	for _, c := range []LogCode{
		LogCodeJamfStarting, LogCodeJamfCredsMissing, LogCodeJamfAuthFailed,
		LogCodeJamfComputersFetched, LogCodeJamfDetailFetchFailed, LogCodeJamfComplete,
		LogCodeIntuneStarting, LogCodeIntuneCredsMissing, LogCodeIntuneTokenAcquireFailed,
		LogCodeIntuneSkipUnparseable, LogCodeIntuneComplete,
		LogCodeSCCMStarting, LogCodeSCCMCredsMissing, LogCodeSCCMAuthFailed,
		LogCodeSCCMSkipUnparseable, LogCodeSCCMComplete,
	} {
		assert.False(t, seen[c], "duplicate log code constant %q", string(c))
		seen[c] = true
	}
}
