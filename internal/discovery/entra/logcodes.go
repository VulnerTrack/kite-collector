package entra

// LogCode is the typed identifier attached to every structured log
// entry the Entra ID discovery package emits. Convention:
// `entra.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- discover surface --------------------------------------------
	LogCodeDiscoverCredsMissing       LogCode = "entra.discover.creds_missing"        //#nosec G101 -- log code identifier signalling Entra ID credentials are missing, not a credential value
	LogCodeDiscoverTokenAcquireFailed LogCode = "entra.discover.token_acquire_failed" //#nosec G101 -- log code identifier for Entra OAuth token acquisition failure, not a token value
	LogCodeDiscoverEndpointRejected   LogCode = "entra.discover.endpoint_rejected"    //#nosec G101 -- log code identifier for a rejected/invalid Entra base URL, not a credential value

	// --- enrich surface (Phase 2 enrichment paths) -------------------
	LogCodeEnrichRoleAssignmentsFailed LogCode = "entra.enrich.role_assignments_failed"
	LogCodeEnrichMfaRegistrationFailed LogCode = "entra.enrich.mfa_registration_failed"
	LogCodeEnrichRoleMembersFailed     LogCode = "entra.enrich.role_members_failed"
	LogCodeEnrichMfaReportUnavailable  LogCode = "entra.enrich.mfa_report_unavailable"

	// --- pagination surface ------------------------------------------
	LogCodePaginationMaxObjectsTripped LogCode = "entra.pagination.max_objects_tripped"
)
