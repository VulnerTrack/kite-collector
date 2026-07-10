package emitter

// LogCode is the typed identifier attached to every structured log
// entry the emitter package emits. Convention:
// `emitter.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// otlp surface — OTLP endpoint normalization warnings
	LogCodeOTLPSchemeMissing LogCode = "emitter.otlp.scheme_missing"
)
