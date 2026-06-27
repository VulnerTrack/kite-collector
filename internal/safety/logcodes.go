package safety

// LogCode is the typed identifier attached to every structured log
// entry the safety package emits. Convention: `safety.<surface>.<event>`
// so downstream tooling can pivot on a stable identifier without
// parsing freeform message text.
//
// Both panic-recovery code paths (the deferred Recover wrapper and the
// caller-driven LogPanic helper) intentionally share
// LogCodeSafetyPanicRecovered — they emit the same event from
// different call shapes and downstream alerts care about the event,
// not which wrapper fired it.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// circuit_breaker surface — per-source circuit transitions
	LogCodeSafetyCircuitHalfOpen LogCode = "safety.circuit_breaker.half_open"
	LogCodeSafetyCircuitClosed   LogCode = "safety.circuit_breaker.closed"
	LogCodeSafetyCircuitTripped  LogCode = "safety.circuit_breaker.tripped"

	// recover surface — panic-recovery event (shared by Recover + LogPanic)
	LogCodeSafetyPanicRecovered LogCode = "safety.recover.panic_recovered"
)
