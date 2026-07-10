package containers

// LogCode is the typed identifier attached to every structured log
// entry the agent containers discovery package emits. Convention:
// `agent_containers.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// chain surface — per-runtime collector failures and the global
	// cap-reached warning when MaxContainers is hit mid-chain
	LogCodeChainRuntimeCollectorFailed LogCode = "agent_containers.chain.runtime_collector_failed"
	LogCodeChainCapReached             LogCode = "agent_containers.chain.cap_reached"
)
