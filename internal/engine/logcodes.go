package engine

// LogCode is the typed identifier attached to every structured log
// entry the engine package emits. Convention: `<package>.<surface>.<event>`
// so downstream tooling (Loki/Splunk queries, alerting rules, runbooks)
// can pivot on a stable identifier without parsing freeform message
// text.
//
// Every Warn/Error site MUST include the code as a `"code"` structured
// attribute. Info/Debug sites should include one too when they
// represent a notable state transition operators alert on.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// discovery surface — phase 1 of the scan pipeline
	LogCodeDiscoveryStart            LogCode = "engine.discovery.started"
	LogCodeDiscoveryDeadlineExceeded LogCode = "engine.discovery.deadline_exceeded"
	LogCodeDiscoveryComplete         LogCode = "engine.discovery.completed"

	// asset persistence — phase 2
	LogCodeAssetsFingerprintSnapshot LogCode = "engine.assets.fingerprint_snapshot_failed"
	LogCodeAssetsPersisted           LogCode = "engine.assets.persisted"
	LogCodeStaleDetectFailed         LogCode = "engine.assets.stale_detect_failed"

	// software persistence
	LogCodeSoftwarePersistFailed  LogCode = "engine.software.persist_failed"
	LogCodeSoftwarePersisted      LogCode = "engine.software.persisted"
	LogCodeSoftwareParseError     LogCode = "engine.software.parse_error"
	LogCodeSoftwareParseTruncated LogCode = "engine.software.parse_errors_truncated"

	// audit surfaces — config/code/container-env/ldap/entra auditors
	LogCodeAuditFailed                LogCode = "engine.audit.phase_failed"
	LogCodeAuditFindingsPersistFailed LogCode = "engine.audit.findings_persist_failed"
	LogCodeAuditComplete              LogCode = "engine.audit.completed"

	LogCodeAuditCodeFailed        LogCode = "engine.audit_code.failed"
	LogCodeAuditCodePersistFailed LogCode = "engine.audit_code.persist_failed"
	LogCodeAuditCodeComplete      LogCode = "engine.audit_code.completed"

	LogCodeAuditContainerEnvFailed        LogCode = "engine.audit_container_env.failed"
	LogCodeAuditContainerEnvPersistFailed LogCode = "engine.audit_container_env.persist_failed"
	LogCodeAuditContainerEnvComplete      LogCode = "engine.audit_container_env.completed"
	LogCodeAuditContainerEnvNoSource      LogCode = "engine.audit_container_env.no_docker_source"

	LogCodeAuditLDAPFailed        LogCode = "engine.audit_ldap.failed"
	LogCodeAuditLDAPPersistFailed LogCode = "engine.audit_ldap.persist_failed"

	LogCodeAuditEntraFailed              LogCode = "engine.audit_entra.failed"
	LogCodeAuditEntraPersistFailed       LogCode = "engine.audit_entra.persist_failed"
	LogCodeAuditEntraSnapshotPersist     LogCode = "engine.audit_entra.snapshot_persist_failed"
	LogCodeAuditEntraTenantFailed        LogCode = "engine.audit_entra.tenant_failed"
	LogCodeAuditEntraTenantPersistFailed LogCode = "engine.audit_entra.tenant_persist_failed"
	LogCodeAuditEntraTenantComplete      LogCode = "engine.audit_entra.tenant_completed"

	// cloud DNS snapshot persistence
	LogCodeCloudDNSSnapshotPersist LogCode = "engine.cloud_dns.snapshot_persist_failed"

	// event emission
	LogCodeEventsPersistFailed LogCode = "engine.events.persist_failed"
	LogCodeEventsEmitFailed    LogCode = "engine.events.emit_failed"

	// scan-run lifecycle
	LogCodeScanRunCompleteFailed LogCode = "engine.scan.complete_failed"
	LogCodeScanRunComplete       LogCode = "engine.scan.completed"

	// retry helper (retry.go)
	LogCodeRetryAttemptFailed LogCode = "engine.retry.attempt_failed"

	// observability reconcile (inline call in scan-run loop)
	LogCodeObservabilityReconcileFailed LogCode = "engine.observability.reconcile_failed"
)
