package hostvolumes

// LogCode is the typed identifier attached to every structured log entry the
// host volumes bridge emits. Convention: `agent.host_volumes.<event>`, matching
// the sibling `agent.host_listeners.*` family, so downstream tooling (Loki /
// Splunk queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking change for
// any alert/dashboard that filters on it; add a new code and mark the old one
// Deprecated instead.
type LogCode string

const (
	// collect surface — partial inventories from per-mount probe failures
	LogCodeCollectDegraded LogCode = "agent.host_volumes.collect_degraded"
)
