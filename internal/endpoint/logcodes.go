package endpoint

// LogCode is the typed identifier attached to every structured log
// entry the endpoint package emits. Convention:
// `endpoint.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// manager surface — connection lifecycle and configuration
	LogCodeManagerConnectSkipped LogCode = "endpoint.manager.connect_skipped"
	LogCodeManagerNoTLS          LogCode = "endpoint.manager.no_tls"

	// health surface — transitions to degraded/unreachable state
	LogCodeHealthDegraded    LogCode = "endpoint.health.degraded"
	LogCodeHealthUnreachable LogCode = "endpoint.health.unreachable"

	// tofu surface — server certificate fingerprint mismatch
	LogCodeTOFUMismatch LogCode = "endpoint.tofu.fingerprint_mismatch"
)
