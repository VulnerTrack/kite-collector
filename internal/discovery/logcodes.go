package discovery

// LogCode is the typed identifier attached to every structured log
// entry the discovery registry emits. Convention:
// `discovery.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- registry surface (per-source orchestration) -----------------
	LogCodeRegistrySourceCircuitOpen LogCode = "discovery.registry.source_circuit_open"
	LogCodeRegistrySourceFailed      LogCode = "discovery.registry.source_failed"

	// --- heartbeat surface -------------------------------------------
	LogCodeHeartbeatRecordFailed LogCode = "discovery.heartbeat.record_failed"
)
