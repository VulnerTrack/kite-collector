package scan

// LogCode is the typed identifier attached to every structured log
// entry the scan coordinator emits. Convention: `scan.<surface>.<event>`
// so downstream tooling can pivot on a stable identifier without
// parsing freeform message text.
//
// LogCodeScanEngineStorageExhausted is split out from
// LogCodeScanEngineError so on-call rules can route the
// storage-exhausted case directly to a known-remediation runbook
// (cloud-sync folder / network-mount removal) instead of generic
// engine-error triage.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// coordinator surface — top-level scan-run lifecycle
	LogCodeScanEngineError            LogCode = "scan.coordinator.engine_error"
	LogCodeScanEngineStorageExhausted LogCode = "scan.coordinator.engine_storage_exhausted"
	LogCodeScanSubscriberDropped      LogCode = "scan.coordinator.subscriber_dropped_event"
)
