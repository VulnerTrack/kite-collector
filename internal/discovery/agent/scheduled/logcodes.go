package scheduled

// LogCode is the typed identifier attached to every structured log
// entry the agent scheduled discovery package emits. Convention:
// `agent_scheduled.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// chain surface — per-source collector failures and the global
	// cap-reached warning when MaxJobs is hit mid-chain
	LogCodeChainSourceCollectorFailed LogCode = "agent_scheduled.chain.source_collector_failed"
	LogCodeChainCapReached            LogCode = "agent_scheduled.chain.cap_reached"
)
