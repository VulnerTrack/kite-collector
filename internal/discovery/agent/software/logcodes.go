package software

// LogCode is the typed identifier attached to every structured log
// entry the agent software discovery package emits. Convention:
// `agent_software.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// registry surface — per-collector lifecycle and aggregation
	// errors when the multi-package-manager registry runs the fan-out
	LogCodeRegistryCollectorFailed LogCode = "agent_software.registry.collector_failed"

	// exec surface — privilege reduction applied to a collector child
	// process: the agent runs as root but the tool refuses root, so the
	// child runs as the tool's owning user with a minimal environment
	LogCodeExecDemotedToUser LogCode = "agent_software.exec.demoted_to_user"

	// pipx surface — diagnostics scraped from pipx CLI stderr on
	// non-zero exit codes
	LogCodePipxNonZeroExitDiagnostic LogCode = "agent_software.pipx.non_zero_exit_diagnostic"

	// brew surface — environment conditions that make Homebrew
	// inventory unavailable rather than failed (brew hard-refuses to
	// run as root, the normal state for a sudo-started agent)
	LogCodeBrewRootRefused LogCode = "agent_software.brew.root_refused"

	// cocoapods surface — same environment condition as brew: CocoaPods
	// hard-refuses to run as root, the normal state for a privileged
	// agent, so the inventory is skipped rather than failed
	LogCodeCocoaPodsRootRefused LogCode = "agent_software.cocoapods.root_refused"

	// swiftpm surface — project-scope conditions detected at collect
	// time (no Package.swift at or above the working directory)
	LogCodeSwiftPMNoManifest LogCode = "agent_software.swiftpm.no_manifest"
)
