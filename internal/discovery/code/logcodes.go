package code

// LogCode is the typed identifier attached to every structured log
// entry the source-code discovery package emits. Convention:
// `code.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- scanner surface (repo discovery walk) -----------------------
	LogCodeScannerPathResolveFailed LogCode = "code.scanner.path_resolve_failed"
	LogCodeScannerWalkFailed        LogCode = "code.scanner.walk_failed"
)
