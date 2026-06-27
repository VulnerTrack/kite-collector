package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"

	"github.com/vulnertrack/kite-collector/internal/safenet"
)

func TestSafenetObserver(t *testing.T) {
	t.Run("increments safety guard counter on every event", func(t *testing.T) {
		m := New()
		obs := NewSafenetObserver(m)

		obs.ObserveGuardEvent(safenet.NewGuardEvent(
			safenet.GuardSSRFScopeBlock, safenet.GuardActionRejected,
			"scanner", "169.254.169.254 blocked", "{}",
		))

		got := testutil.ToFloat64(m.SafetyGuardTotal.WithLabelValues(
			string(safenet.GuardSSRFScopeBlock), string(safenet.GuardActionRejected),
		))
		assert.Equal(t, float64(1), got)
	})

	t.Run("pagination cap also bumps connector counter", func(t *testing.T) {
		m := New()
		obs := NewSafenetObserver(m)

		obs.ObserveGuardEvent(safenet.NewGuardEvent(
			safenet.GuardPaginationByteCap, safenet.GuardActionCapped,
			"heroku", "page too big", "{}",
		))

		guard := testutil.ToFloat64(m.SafetyGuardTotal.WithLabelValues(
			string(safenet.GuardPaginationByteCap),
			string(safenet.GuardActionCapped),
		))
		assert.Equal(t, float64(1), guard)

		trunc := testutil.ToFloat64(m.PaginationTruncatedTotal.WithLabelValues(
			"heroku", string(safenet.GuardPaginationByteCap),
		))
		assert.Equal(t, float64(1), trunc)
	})

	t.Run("non-pagination event does not bump truncation counter", func(t *testing.T) {
		m := New()
		obs := NewSafenetObserver(m)

		obs.ObserveGuardEvent(safenet.NewGuardEvent(
			safenet.GuardCursorSanitizationReject, safenet.GuardActionRejected,
			"vultr", "bad cursor", "{}",
		))

		trunc := testutil.ToFloat64(m.PaginationTruncatedTotal.WithLabelValues(
			"vultr", string(safenet.GuardCursorSanitizationReject),
		))
		assert.Equal(t, float64(0), trunc)
	})

	t.Run("nil observer is a no-op", func(t *testing.T) {
		var obs *SafenetObserver
		obs.ObserveGuardEvent(safenet.GuardEvent{})
	})
}
