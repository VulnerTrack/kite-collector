package agent

// LogCode is the typed identifier attached to every structured log
// entry the agent discovery package emits. Convention:
// `agent_discovery.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text. The `agent_discovery` namespace
// avoids colliding with the broader `agent.*` namespace owned by the
// kite-collector command entrypoint.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// probe surface — host inspection lifecycle, per-collector
	// failures, and interface enumeration warnings
	LogCodeProbeInterfacesCollectFailed LogCode = "agent_discovery.probe.interfaces_collect_failed"
	LogCodeProbeSoftwareCollectFailed   LogCode = "agent_discovery.probe.software_collect_failed"
	LogCodeProbeDriversCollectFailed    LogCode = "agent_discovery.probe.drivers_collect_failed"
	LogCodeProbeDriverCollectorErrors   LogCode = "agent_discovery.probe.driver_collector_errors"
	LogCodeProbeInterfaceAddrsFailed    LogCode = "agent_discovery.probe.interface_addrs_failed"
	LogCodeProbeSoftwareParseErrors     LogCode = "agent_discovery.probe.software_parse_errors"
)
