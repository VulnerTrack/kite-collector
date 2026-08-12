package osquery

// LogCode is the typed identifier attached to every structured log entry the
// osquery discovery package emits. Convention: `osquery.<surface>.<event>` so
// downstream tooling (Loki/Splunk queries, alerting rules, runbooks) can
// pivot on a stable identifier without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking change for
// any alert/dashboard that filters on it; add a new code and mark the old
// one Deprecated instead.
type LogCode string

const (
	// --- discover surface (host identity over the extensions socket) ----
	LogCodeDiscoverSystemInfoFailed LogCode = "osquery.discover.system_info_failed"
	LogCodeDiscoverOSVersionFailed  LogCode = "osquery.discover.os_version_failed"
	LogCodeDiscoverKernelInfoFailed LogCode = "osquery.discover.kernel_info_failed"

	// --- yara surface (on-demand rule scans) -----------------------------
	// SigfileInvisible fires when the configured rules file cannot be proven
	// visible to the daemon — the scan is SKIPPED rather than reported clean,
	// because osquery answers a missing sigfile with a silent empty set.
	LogCodeYaraSigfileInvisible LogCode = "osquery.yara.sigfile_invisible"
	LogCodeYaraScanFailed       LogCode = "osquery.yara.scan_failed"
	LogCodeYaraMatchesFound     LogCode = "osquery.yara.matches_found"
)
