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
	// discover surface — host identity and FIM summary over the extensions socket
	LogCodeDiscoverSystemInfoFailed     LogCode = "osquery.discover.system_info_failed"     // system_info query failed; machine emitted with empty hostname/hardware identity
	LogCodeDiscoverOSVersionFailed      LogCode = "osquery.discover.os_version_failed"      // os_version query failed; machine emitted with empty OS family/version
	LogCodeDiscoverKernelInfoFailed     LogCode = "osquery.discover.kernel_info_failed"     // kernel_info query failed; machine emitted without kernel version
	LogCodeDiscoverFileEventsFailed     LogCode = "osquery.discover.file_events_failed"     // per-scan FIM summary failed — without this, "0 events" and "events subsystem broken" are indistinguishable
	LogCodeDiscoverListeningPortsFailed LogCode = "osquery.discover.listening_ports_failed" // listening_ports query failed; machine emitted without the saved current-ports inventory

	// yara surface — on-demand rule scans and their skip guards
	LogCodeYaraSigfileInvisible   LogCode = "osquery.yara.sigfile_invisible"    // daemon answered the visibility probe but cannot see the rules file (bad path/mount); scan SKIPPED, never reported clean
	LogCodeYaraSigfileProbeFailed LogCode = "osquery.yara.sigfile_probe_failed" // the visibility probe itself errored (daemon or file table broken); scan SKIPPED — different remediation than an invisible sigfile
	LogCodeYaraCompileProbeFailed LogCode = "osquery.yara.compile_probe_failed" // could not run the inline-rule compile probe (daemon binary unresolved or probe query errored); scan SKIPPED
	LogCodeYaraRulesUncompilable  LogCode = "osquery.yara.rules_uncompilable"   // inline yara_rules failed to compile (malformed rule text); scan SKIPPED, never reported clean
	LogCodeYaraScanFailed         LogCode = "osquery.yara.scan_failed"          // one configured path's yara-table scan errored; remaining paths still scan
	LogCodeYaraPathUnscannable    LogCode = "osquery.yara.path_unscannable"     // a path produced zero scan rows (missing/directory/unreadable/empty glob); NOT counted as scanned-clean
	LogCodeYaraAllPathsFailed     LogCode = "osquery.yara.all_paths_failed"     // no path was actually scanned (all errored/unscannable, or yara table absent); scan NOT reported, so a false clean is not emitted
	LogCodeYaraMatchesFound       LogCode = "osquery.yara.matches_found"        // YARA rules matched on the host — the alert line names the rules
)
