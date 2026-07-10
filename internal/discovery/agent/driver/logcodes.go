package driver

// LogCode is the typed identifier attached to every structured log
// entry the agent driver discovery package emits. Convention:
// `agent_driver.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// registry surface — per-collector lifecycle and aggregation
	// errors when the multi-source driver registry runs the fan-out
	LogCodeRegistryCollectorFailed LogCode = "agent_driver.registry.collector_failed"
)
