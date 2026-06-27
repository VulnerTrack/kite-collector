package mdm

// LogCode is the typed identifier attached to every structured log
// entry the MDM-discovery package emits. Convention:
// `mdm.<provider>.<event>` so downstream tooling can pivot on a stable
// identifier without parsing freeform message text.
//
// Per-provider codes follow the same reasoning as
// internal/discovery/cloud, internal/discovery/vps and
// internal/discovery/paas: runbooks for "Jamf auth failed",
// "Intune auth failed" and "SCCM auth failed" target different consoles,
// different docs, often different teams (macOS fleet vs. Microsoft 365
// admins vs. on-prem ConfigMgr operators). On-call routing maps a code
// directly to a team without parsing a sub-field.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- Jamf Pro (macOS-focused MDM) --------------------------------
	LogCodeJamfStarting          LogCode = "mdm.jamf.starting"
	LogCodeJamfCredsMissing      LogCode = "mdm.jamf.creds_missing"
	LogCodeJamfAuthFailed        LogCode = "mdm.jamf.auth_failed"
	LogCodeJamfComputersFetched  LogCode = "mdm.jamf.computers_fetched"
	LogCodeJamfDetailFetchFailed LogCode = "mdm.jamf.detail_fetch_failed"
	LogCodeJamfComplete          LogCode = "mdm.jamf.completed"

	// --- Microsoft Intune (Graph API) --------------------------------
	LogCodeIntuneStarting           LogCode = "mdm.intune.starting"
	LogCodeIntuneCredsMissing       LogCode = "mdm.intune.creds_missing"
	LogCodeIntuneTokenAcquireFailed LogCode = "mdm.intune.token_acquire_failed"
	LogCodeIntuneSkipUnparseable    LogCode = "mdm.intune.skip_unparseable_device"
	LogCodeIntuneComplete           LogCode = "mdm.intune.completed"

	// --- Microsoft SCCM / ConfigMgr (AdminService REST) --------------
	LogCodeSCCMStarting        LogCode = "mdm.sccm.starting"
	LogCodeSCCMCredsMissing    LogCode = "mdm.sccm.creds_missing"
	LogCodeSCCMAuthFailed      LogCode = "mdm.sccm.auth_failed"
	LogCodeSCCMSkipUnparseable LogCode = "mdm.sccm.skip_unparseable_device"
	LogCodeSCCMComplete        LogCode = "mdm.sccm.completed"
)
