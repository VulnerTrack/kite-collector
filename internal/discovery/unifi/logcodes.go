package unifi

// LogCode is the typed identifier attached to every structured log
// entry the UniFi discovery package emits. Convention:
// `unifi.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- cloud surface (Site Manager / Cloud API) -------------------
	LogCodeCloudListDevicesFailed LogCode = "unifi.cloud.list_devices_failed"

	// --- local surface (on-prem controller) -------------------------
	LogCodeLocalListClientsFailed LogCode = "unifi.local.list_clients_failed"
	LogCodeLocalListDevicesFailed LogCode = "unifi.local.list_devices_failed"
)
