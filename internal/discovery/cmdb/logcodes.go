package cmdb

// LogCode is the typed identifier attached to every structured log
// entry the CMDB discovery package emits. Convention:
// `cmdb.<provider>.<event>` so downstream tooling can pivot on a
// stable identifier without parsing freeform message text.
//
// Codes are split PER PROVIDER (rather than shared via a `provider`
// structured field) because NetBox and ServiceNow are very different
// products with different remediation paths:
//   - NetBox is an open-source, self-hosted IPAM/DCIM — the runbook
//     for "NetBox auth failed" points at an on-prem instance and an
//     internal infrastructure team.
//   - ServiceNow is a SaaS enterprise CMDB — the runbook for
//     "ServiceNow auth failed" points at vendor consoles, ITSM admins,
//     and frequently a different team altogether.
//
// On-call routing maps a code directly to a team without parsing a
// sub-field.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- NetBox ------------------------------------------------------
	LogCodeNetBoxStarting        LogCode = "cmdb.netbox.starting"
	LogCodeNetBoxNotConfigured   LogCode = "cmdb.netbox.not_configured"
	LogCodeNetBoxComplete        LogCode = "cmdb.netbox.completed"
	LogCodeNetBoxAuthFailed      LogCode = "cmdb.netbox.auth_failed"
	LogCodeNetBoxSkipUnparseable LogCode = "cmdb.netbox.skip_unparseable_device"

	// --- ServiceNow --------------------------------------------------
	LogCodeServiceNowStarting        LogCode = "cmdb.servicenow.starting"
	LogCodeServiceNowNotConfigured   LogCode = "cmdb.servicenow.not_configured"
	LogCodeServiceNowComplete        LogCode = "cmdb.servicenow.completed"
	LogCodeServiceNowAuthFailed      LogCode = "cmdb.servicenow.auth_failed"
	LogCodeServiceNowSkipUnparseable LogCode = "cmdb.servicenow.skip_unparseable_ci"
)
