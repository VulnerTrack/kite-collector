package volumes

// LogCode is the typed identifier attached to every structured log
// entry the agent volumes discovery package emits. Convention:
// `agent_volumes.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// collector surface — inventory cap warnings and per-partition
	// enumeration failures
	LogCodeCollectorInventoryCapped LogCode = "agent_volumes.collector.inventory_capped"
)
