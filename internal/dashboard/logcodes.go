package dashboard

// LogCode is the typed identifier attached to every structured log
// entry the dashboard package emits. The convention is
// `<package>.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable string
// without parsing freeform message text.
//
// Every site that logs at Warn or higher MUST include the code as a
// `"code"` structured attribute, e.g.:
//
//	logger.Error("snapshot marshal failed",
//	    "code", string(LogCodeObservabilitySnapshotMarshal),
//	    "error", err,
//	    "request_path", r.URL.Path)
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// observability surface — /observability page + /api/v1/observability/*
	LogCodeObservabilitySnapshotMarshal LogCode = "dashboard.observability.snapshot_marshal_failed"

	// onboarding/enroll surface — POST /api/v1/agent/enroll
	LogCodeEnrollMissingWrapKey LogCode = "dashboard.enroll.missing_wrap_key"
	LogCodeEnrollAEADWrap       LogCode = "dashboard.enroll.aead_wrap_failed"
	LogCodeEnrollUpsert         LogCode = "dashboard.enroll.upsert_failed"
	LogCodeEnrollSuccess        LogCode = "dashboard.enroll.success"
	LogCodeEnrollRender         LogCode = "dashboard.enroll.render_failed"
	LogCodeEnrollAutoCheck      LogCode = "dashboard.enroll.auto_check_failed"
	LogCodeIdentityUnwrap       LogCode = "dashboard.identity.unwrap_failed"

	// check surface — POST /api/v1/agent/check
	LogCodeCheckJSONEncode LogCode = "dashboard.check.json_encode_failed"

	// stream surface — POST /api/v1/agent/stream/{start,stop}
	LogCodeStreamStart LogCode = "dashboard.stream.start_failed"
	LogCodeStreamStop  LogCode = "dashboard.stream.stop_failed"

	// support-bundle surface — GET /support-bundle.zip
	LogCodeSupportBundleManifest LogCode = "dashboard.support_bundle.manifest_failed"

	// install surface — POST /api/v1/agent/install + /uninstall
	LogCodeAgentInstall           LogCode = "dashboard.install.agent_install_failed"
	LogCodeInstallStatusRender    LogCode = "dashboard.install.status_render_failed"
	LogCodeUninstallConfirmRender LogCode = "dashboard.install.uninstall_confirm_render_failed"
	LogCodeAgentUninstall         LogCode = "dashboard.install.agent_uninstall_failed"
	LogCodeAgentStateIdentity     LogCode = "dashboard.install.agent_state_identity_failed"
	LogCodeInstallJSONEncode      LogCode = "dashboard.install.json_encode_failed"

	// server bootstrap surface — Serve()
	LogCodeServeStaticSubFS     LogCode = "dashboard.serve.static_sub_fs_failed"
	LogCodeServeFragmentRender  LogCode = "dashboard.serve.fragment_render_failed"
	LogCodeServeTabPageRender   LogCode = "dashboard.serve.tab_page_render_failed"
	LogCodeServeTablePageRender LogCode = "dashboard.serve.table_page_render_failed"

	// csv export surface — /api/v1/{assets,software,findings,tables}/export.csv
	LogCodeExportAssetsCSV   LogCode = "dashboard.export.assets_csv_failed"
	LogCodeExportSoftwareCSV LogCode = "dashboard.export.software_csv_failed"
	LogCodeExportFindingsCSV LogCode = "dashboard.export.findings_csv_failed"
	LogCodeExportTableCSV    LogCode = "dashboard.export.table_csv_failed"

	// scan surface — POST /api/v1/scan
	LogCodeScanTrigger LogCode = "dashboard.scan.trigger_failed"

	// onboarding bootstrap surface — Serve() onboarding wiring
	LogCodeOnboardingDisabledNoWrapKey LogCode = "dashboard.onboarding.disabled_no_wrap_key"
	LogCodeOnboardingDisabledNoSQLite  LogCode = "dashboard.onboarding.disabled_store_not_sqlite"
	LogCodeOnboardingFragmentRender    LogCode = "dashboard.onboarding.fragment_render_failed"
)
