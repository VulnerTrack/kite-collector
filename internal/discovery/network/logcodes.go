package network

// LogCode is the typed identifier attached to every structured log
// entry the network discovery package emits. Convention:
// `network.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// scanner surface — top-level scan loop lifecycle, persistence
	// failures, and per-target skip events
	LogCodeScannerStarting              LogCode = "network.scanner.starting"
	LogCodeScannerSafetyGuardFired      LogCode = "network.scanner.safety_guard_fired"
	LogCodeScannerGuardEventPersistFail LogCode = "network.scanner.guard_event_persist_failed"
	LogCodeScannerScanEventPersistFail  LogCode = "network.scanner.scan_event_persist_failed"
	LogCodeScannerOpenPortsPersistFail  LogCode = "network.scanner.open_ports_persist_failed"
	LogCodeScannerInvalidCIDRSkipped    LogCode = "network.scanner.invalid_cidr_skipped"
)
