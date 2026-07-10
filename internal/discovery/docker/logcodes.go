package docker

// LogCode is the typed identifier attached to every structured log
// entry the Docker/Podman discovery package emits. Convention:
// `docker.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- enumerate surface (container / image enumeration) ----------
	LogCodeEnumerateEnvInspectFailed LogCode = "docker.enumerate.env_inspect_failed"
	LogCodeEnumerateInspectFailed    LogCode = "docker.enumerate.inspect_failed"
	LogCodeEnumerateListImagesFailed LogCode = "docker.enumerate.list_images_failed"
)
