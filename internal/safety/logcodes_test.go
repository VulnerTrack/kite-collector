package safety

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogCodes_FollowConvention pins the `safety.<surface>.<event>`
// shape. Every code MUST have ≥3 dot-separated segments, lead with the
// "safety" namespace, be all lowercase, no spaces.
func TestLogCodes_FollowConvention(t *testing.T) {
	codes := []LogCode{
		LogCodeSafetyCircuitHalfOpen,
		LogCodeSafetyCircuitClosed,
		LogCodeSafetyCircuitTripped,
		LogCodeSafetyPanicRecovered,
	}
	for _, c := range codes {
		s := string(c)
		t.Run(s, func(t *testing.T) {
			parts := strings.Split(s, ".")
			assert.GreaterOrEqual(t, len(parts), 3,
				"code %q must have ≥3 dot-separated segments (namespace.surface.event)", s)
			assert.Equal(t, "safety", parts[0],
				"code %q must lead with the safety namespace prefix", s)
			assert.Equal(t, strings.ToLower(s), s,
				"code %q must be all lowercase for grep-friendliness", s)
			assert.NotContains(t, s, " ",
				"code %q must not contain spaces — use underscores", s)
		})
	}
}

// TestLogCodes_AreUnique pins the no-duplicate-code rule for constant
// declarations. Two CALL SITES may intentionally share a code when
// they emit the same semantic event (e.g., Recover + LogPanic both
// fire LogCodeSafetyPanicRecovered) — this test only catches
// accidentally duplicated CONSTANTS.
func TestLogCodes_AreUnique(t *testing.T) {
	seen := map[LogCode]bool{}
	for _, c := range []LogCode{
		LogCodeSafetyCircuitHalfOpen,
		LogCodeSafetyCircuitClosed,
		LogCodeSafetyCircuitTripped,
		LogCodeSafetyPanicRecovered,
	} {
		assert.False(t, seen[c],
			"duplicate log code constant %q — declare it once and reuse the constant", string(c))
		seen[c] = true
	}
}
