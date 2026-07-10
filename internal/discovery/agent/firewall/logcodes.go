package firewall

// LogCode is the typed identifier attached to every structured log
// entry the agent firewall discovery package emits. Convention:
// `agent_firewall.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// chain surface — per-engine collector failures and the global
	// cap-reached warning when MaxRules is hit mid-chain
	LogCodeChainEngineCollectorFailed LogCode = "agent_firewall.chain.engine_collector_failed"
	LogCodeChainCapReached            LogCode = "agent_firewall.chain.cap_reached"
)
