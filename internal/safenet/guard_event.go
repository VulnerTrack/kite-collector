package safenet

import (
	"strings"
	"time"
)

// GuardEventType enumerates the SafetyGuardEvent.guard_type values defined
// by RFC-0124 §4.1.4. Stored as plain strings so they round-trip through
// SQLite CHECK constraints and ClickHouse LowCardinality(String).
type GuardEventType string

const (
	GuardSSRFScopeBlock           GuardEventType = "ssrf_scope_block"
	GuardIPCountCap               GuardEventType = "ip_count_cap"
	GuardPortRangeViolation       GuardEventType = "port_range_violation"
	GuardConcurrencyCap           GuardEventType = "concurrency_cap"
	GuardPaginationIterationCap   GuardEventType = "pagination_iteration_cap"
	GuardPaginationByteCap        GuardEventType = "pagination_byte_cap"
	GuardCursorSanitizationReject GuardEventType = "cursor_sanitization_rejected"
)

// GuardEventAction enumerates SafetyGuardEvent.action_taken values.
type GuardEventAction string

const (
	GuardActionRejected GuardEventAction = "rejected"
	GuardActionCapped   GuardEventAction = "capped"
	GuardActionLogged   GuardEventAction = "logged"
)

// MaxInputSummaryLen caps the length of GuardEvent.InputSummary so that
// large oversize inputs do not bloat the audit trail. RFC-0124 §4.1.4 says
// "Truncated (≤ 256 chars)".
const MaxInputSummaryLen = 256

// GuardEvent is the in-process representation of a SafetyGuardEvent. The
// store layer maps it to a SQLite row and the Python sync workflow maps it
// to a ClickHouse row. ScanID is empty when the guard fired outside a scan
// (e.g., inside a paginated HTTP connector).
type GuardEvent struct {
	GuardType       GuardEventType
	Action          GuardEventAction
	TriggeredAt     time.Time
	InputSummary    string
	SourceComponent string
	DetailsJSON     string
	ScanID          string
}

// NewGuardEvent returns a GuardEvent with TriggeredAt stamped to now (UTC),
// the InputSummary clamped to MaxInputSummaryLen, and control characters
// stripped (CWE-117). Use this constructor instead of building the struct
// inline so callers cannot accidentally bypass the clamp.
func NewGuardEvent(
	gt GuardEventType,
	action GuardEventAction,
	source, inputSummary, detailsJSON string,
) GuardEvent {
	return GuardEvent{
		GuardType:       gt,
		Action:          action,
		TriggeredAt:     time.Now().UTC(),
		InputSummary:    truncateAndStrip(inputSummary, MaxInputSummaryLen),
		SourceComponent: source,
		DetailsJSON:     ensureJSONObject(detailsJSON),
	}
}

// truncateAndStrip strips control characters and truncates to maxLen runes.
func truncateAndStrip(s string, maxLen int) string {
	if s == "" {
		return s
	}
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
	if len(cleaned) > maxLen {
		return cleaned[:maxLen]
	}
	return cleaned
}

// ensureJSONObject returns "{}" when the supplied details string is empty.
// Callers responsible for a well-formed JSON document; this helper only
// avoids storing empty strings in a NOT NULL column.
func ensureJSONObject(s string) string {
	if s == "" {
		return "{}"
	}
	return s
}
