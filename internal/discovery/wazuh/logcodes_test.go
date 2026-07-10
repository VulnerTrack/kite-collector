package wazuh

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogCodes_FollowConvention pins the `wazuh.<surface>.<event>`
// shape so a future contributor can't accidentally ship a code that
// breaks downstream Loki/Splunk filters.
func TestLogCodes_FollowConvention(t *testing.T) {
	codes := []LogCode{
		LogCodeAuthDefaultCredentials,
		LogCodeEnrichPackagesFailed,
		LogCodeEnrichVulnerabilitiesFailed,
		LogCodeEnrichSCAPoliciesFailed,
		LogCodeEnrichSCAChecksFailed,
		LogCodeEnrichPortsFailed,
		LogCodeEnrichInterfacesFailed,
		LogCodeEnrichAddressesFailed,
		LogCodeAgentsSkipInvalidJSON,
	}
	for _, c := range codes {
		s := string(c)
		t.Run(s, func(t *testing.T) {
			parts := strings.Split(s, ".")
			assert.GreaterOrEqual(t, len(parts), 3,
				"code %q must have at least 3 dot-separated segments", s)
			assert.Equal(t, "wazuh", parts[0],
				"code %q must lead with the wazuh namespace prefix", s)
			assert.Equal(t, strings.ToLower(s), s,
				"code %q must be all lowercase for grep-friendliness", s)
			assert.NotContains(t, s, " ",
				"code %q must not contain spaces — use underscores between words", s)
		})
	}
}

func TestLogCodes_AreUnique(t *testing.T) {
	seen := map[LogCode]bool{}
	all := []LogCode{
		LogCodeAuthDefaultCredentials,
		LogCodeEnrichPackagesFailed,
		LogCodeEnrichVulnerabilitiesFailed,
		LogCodeEnrichSCAPoliciesFailed,
		LogCodeEnrichSCAChecksFailed,
		LogCodeEnrichPortsFailed,
		LogCodeEnrichInterfacesFailed,
		LogCodeEnrichAddressesFailed,
		LogCodeAgentsSkipInvalidJSON,
	}
	for _, c := range all {
		assert.False(t, seen[c],
			"duplicate log code %q — every call site must have a unique identifier", string(c))
		seen[c] = true
	}
}
