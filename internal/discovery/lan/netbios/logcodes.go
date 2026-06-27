package netbios

// LogCode — typed identifier for every structured log entry the
// netbios package emits. Convention: `lan_netbios.<surface>.<event>`.
type LogCode string

const (
	// discover surface — broadcast name-service query lifecycle
	LogCodeNetBIOSNoTargets       LogCode = "lan_netbios.discover.no_targets"
	LogCodeNetBIOSSOBroadcastFail LogCode = "lan_netbios.discover.so_broadcast_failed"
	LogCodeNetBIOSSendFailed      LogCode = "lan_netbios.discover.send_failed"
)
