package metrics

import (
	"github.com/vulnertrack/kite-collector/internal/safenet"
)

// SafenetObserver bridges safenet.GuardObserver to Prometheus counters.
// It increments kite_safety_guard_total for every event and additionally
// increments kite_pagination_truncated_total when the event represents a
// pagination cap fire. The connector/source comes from
// GuardEvent.SourceComponent so SafenetObserver does not need any
// per-connector configuration — wiring is one line in main.go.
type SafenetObserver struct {
	m *Metrics
}

// NewSafenetObserver returns an observer that writes to the supplied
// Metrics instance.
func NewSafenetObserver(m *Metrics) *SafenetObserver {
	return &SafenetObserver{m: m}
}

// ObserveGuardEvent satisfies safenet.GuardObserver.
func (o *SafenetObserver) ObserveGuardEvent(ev safenet.GuardEvent) {
	if o == nil || o.m == nil {
		return
	}
	o.m.SafetyGuardTotal.WithLabelValues(
		string(ev.GuardType), string(ev.Action),
	).Inc()

	if isPaginationCap(ev.GuardType) {
		o.m.PaginationTruncatedTotal.WithLabelValues(
			ev.SourceComponent, string(ev.GuardType),
		).Inc()
	}
}

func isPaginationCap(gt safenet.GuardEventType) bool {
	switch gt {
	case safenet.GuardPaginationIterationCap,
		safenet.GuardPaginationByteCap:
		return true
	case safenet.GuardSSRFScopeBlock,
		safenet.GuardIPCountCap,
		safenet.GuardPortRangeViolation,
		safenet.GuardConcurrencyCap,
		safenet.GuardCursorSanitizationReject:
		return false
	}
	return false
}
