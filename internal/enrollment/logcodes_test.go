package enrollment

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogCodes_FollowConvention pins the `enrollment.<surface>.<event>` shape.
func TestLogCodes_FollowConvention(t *testing.T) {
	codes := []LogCode{
		LogCodeEnrollmentCertCheckFailed,
		LogCodeEnrollmentStarting,
		LogCodeEnrollmentKeyBackendBelowPolicy,
		LogCodeEnrollmentKeyBackendOK,
	}
	for _, c := range codes {
		s := string(c)
		t.Run(s, func(t *testing.T) {
			parts := strings.Split(s, ".")
			assert.GreaterOrEqual(t, len(parts), 3,
				"code %q must have ≥3 dot-separated segments", s)
			assert.Equal(t, "enrollment", parts[0],
				"code %q must lead with the enrollment namespace prefix", s)
			assert.Equal(t, strings.ToLower(s), s,
				"code %q must be all lowercase", s)
			assert.NotContains(t, s, " ", "code %q must not contain spaces", s)
		})
	}
}

func TestLogCodes_AreUnique(t *testing.T) {
	seen := map[LogCode]bool{}
	for _, c := range []LogCode{
		LogCodeEnrollmentCertCheckFailed,
		LogCodeEnrollmentStarting,
		LogCodeEnrollmentKeyBackendBelowPolicy,
		LogCodeEnrollmentKeyBackendOK,
	} {
		assert.False(t, seen[c], "duplicate log code constant %q", string(c))
		seen[c] = true
	}
}
