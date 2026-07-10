package metrics

// LogCode is the typed identifier attached to every structured log
// entry the metrics package emits. Convention:
// `metrics.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// server surface — Prometheus HTTP server lifecycle failures
	LogCodeServerExited LogCode = "metrics.server.exited"
)
