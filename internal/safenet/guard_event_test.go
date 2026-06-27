package safenet

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewGuardEvent(t *testing.T) {
	t.Run("stamps now and clamps summary", func(t *testing.T) {
		long := strings.Repeat("x", MaxInputSummaryLen+50)
		ev := NewGuardEvent(GuardIPCountCap, GuardActionRejected, "scanner", long, "")

		assert.Equal(t, GuardIPCountCap, ev.GuardType)
		assert.Equal(t, GuardActionRejected, ev.Action)
		assert.Equal(t, "scanner", ev.SourceComponent)
		assert.Equal(t, "{}", ev.DetailsJSON)
		assert.Len(t, ev.InputSummary, MaxInputSummaryLen)
		assert.WithinDuration(t, time.Now().UTC(), ev.TriggeredAt, time.Second)
	})

	t.Run("strips control characters from summary", func(t *testing.T) {
		ev := NewGuardEvent(GuardCursorSanitizationReject, GuardActionRejected,
			"connector", "abc\x00\ndef", `{"k":"v"}`)
		assert.NotContains(t, ev.InputSummary, "\x00")
		assert.NotContains(t, ev.InputSummary, "\n")
		assert.Contains(t, ev.InputSummary, "abc")
		assert.Contains(t, ev.InputSummary, "def")
		assert.Equal(t, `{"k":"v"}`, ev.DetailsJSON)
	})

	t.Run("preserves short summary", func(t *testing.T) {
		ev := NewGuardEvent(GuardConcurrencyCap, GuardActionCapped,
			"scanner", "max=1024 cap=512", "")
		assert.Equal(t, "max=1024 cap=512", ev.InputSummary)
	})
}
