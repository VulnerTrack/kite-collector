package tunnel

// LogCode is the typed identifier attached to every structured log
// entry the tunnel package emits. Convention:
// `tunnel.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// manager surface — tunnel subprocess lifecycle and health
	LogCodeManagerStartUnhealthy   LogCode = "tunnel.manager.start_unhealthy"
	LogCodeManagerRestartLimit     LogCode = "tunnel.manager.restart_limit_reached"
	LogCodeManagerSubprocessExited LogCode = "tunnel.manager.subprocess_exited"
	LogCodeManagerRestartFailed    LogCode = "tunnel.manager.restart_failed"
	LogCodeManagerRestartUnhealthy LogCode = "tunnel.manager.restart_unhealthy"
)
