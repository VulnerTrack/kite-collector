package autodiscovery

// LogCode is the typed identifier attached to every structured log
// entry the autodiscovery package emits. Convention:
// `autodiscovery.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// port surface — TCP-port probe outcomes
	LogCodePortInsecureProbe LogCode = "autodiscovery.port.insecure_probe"

	// docker surface — Docker Engine API probe failures
	LogCodeDockerProbeFailed LogCode = "autodiscovery.docker.probe_failed"
)
