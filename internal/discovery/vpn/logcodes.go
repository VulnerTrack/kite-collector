package vpn

// LogCode is the typed identifier attached to structured log entries this
// package emits. Convention: `vpn_discovery.<surface>.<event>` so
// downstream tooling (Loki/Splunk queries, alerts, runbooks) pivots on a
// stable identifier rather than freeform message text. The prefix is
// distinct from the agent/vpn posture package's `agent_vpn.*` codes so the
// two VPN packages never collide in a log index.
//
// Codes are immutable once shipped; add a new one rather than renaming.
type LogCode string

const (
	// --- source-level (vpn.go) --------------------------------------
	LogCodeEnumeratorFailed  LogCode = "vpn_discovery.source.enumerator_failed"
	LogCodeHostCapReached    LogCode = "vpn_discovery.source.host_cap_reached"
	LogCodeDiscoveryComplete LogCode = "vpn_discovery.source.discovery_complete"

	// --- tailscale --------------------------------------------------
	LogCodeTailscaleCLIFailed  LogCode = "vpn_discovery.tailscale.cli_failed"
	LogCodeTailscaleAPIFailed  LogCode = "vpn_discovery.tailscale.api_failed"
	LogCodeTailscaleDecodeFail LogCode = "vpn_discovery.tailscale.decode_failed"

	// --- wireguard --------------------------------------------------
	LogCodeWireGuardDumpFailed LogCode = "vpn_discovery.wireguard.dump_failed"

	// --- zerotier ---------------------------------------------------
	LogCodeZeroTierCLIFailed LogCode = "vpn_discovery.zerotier.cli_failed"

	// --- netbird ----------------------------------------------------
	LogCodeNetBirdCLIFailed LogCode = "vpn_discovery.netbird.cli_failed"
	LogCodeNetBirdAPIFailed LogCode = "vpn_discovery.netbird.api_failed"

	// --- ipsec / strongswan -----------------------------------------
	LogCodeIPSecCLIFailed LogCode = "vpn_discovery.ipsec.cli_failed"

	// --- openvpn ----------------------------------------------------
	LogCodeOpenVPNStatusReadFailed LogCode = "vpn_discovery.openvpn.status_read_failed"

	// --- nebula -----------------------------------------------------
	LogCodeNebulaConfigReadFailed LogCode = "vpn_discovery.nebula.config_read_failed"
)
