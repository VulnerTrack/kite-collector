package vpn

// LogCode is the typed identifier attached to every structured log
// entry the agent vpn discovery package emits. Convention:
// `agent_vpn.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// chain surface — per-source collector failures and the global
	// cap-reached warning when MaxProfiles is hit mid-chain
	LogCodeChainSourceCollectorFailed LogCode = "agent_vpn.chain.source_collector_failed"
	LogCodeChainCapReached            LogCode = "agent_vpn.chain.cap_reached"

	// tailscale surface — risk signal raised when this host can see
	// mesh peers owned by another user (node sharing). End-user devices
	// holding cross-account routes is unusual and may indicate over-
	// shared infrastructure or stale share grants.
	LogCodeTailscaleSharedPeersDetected LogCode = "agent_vpn.tailscale.shared_peers_detected"
)
