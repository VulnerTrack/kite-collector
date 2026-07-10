package audit

// LogCode is the typed identifier attached to every structured log
// entry the audit package emits. Convention:
// `audit.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// auditor surface — top-level fan-out orchestrator
	LogCodeAuditorFailed LogCode = "audit.auditor.auditor_failed"

	// permissions surface — file permission checks
	LogCodePermissionsStatFailed LogCode = "audit.permissions.stat_failed"

	// service surface — listening-port discovery
	LogCodeServicePortDiscoveryFailed LogCode = "audit.service.port_discovery_failed"

	// ssh surface — sshd_config parsing
	LogCodeSSHPermissionDenied LogCode = "audit.ssh.permission_denied"

	// container_env surface — Docker env-var secret scanning
	LogCodeContainerEnvMissingTag    LogCode = "audit.container_env.missing_container_id_tag"
	LogCodeContainerEnvListFailed    LogCode = "audit.container_env.list_failed"
	LogCodeContainerEnvMaxCapReached LogCode = "audit.container_env.max_containers_cap_reached"

	// process_env surface — /proc env-var secret scanning
	LogCodeProcessEnvReadProcFailed LogCode = "audit.process_env.read_proc_failed"
	LogCodeProcessEnvMaxCapReached  LogCode = "audit.process_env.max_pids_cap_reached"

	// secrets surface — repository content scanning
	LogCodeSecretsMissingPathTag LogCode = "audit.secrets.missing_path_tag"
	LogCodeSecretsWalkError      LogCode = "audit.secrets.walk_error"
)
