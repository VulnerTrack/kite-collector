package rest

// LogCode is the typed identifier attached to every structured log
// entry the REST API package emits. Convention: `rest.<surface>.<event>`
// so downstream tooling can pivot on a stable identifier without
// parsing freeform message text.
//
// Per-handler request-received logs all share LogCodeRequestReceived —
// they emit the same semantic event from different routes; the `path`
// + `method` structured fields differentiate. The two middleware
// response-truncated sites and the three store get-scan-run-failed
// sites also share their respective codes by the same principle.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// general request / middleware surface
	LogCodeRequestReceived             LogCode = "rest.request.received"
	LogCodeMiddlewarePanicRecovered    LogCode = "rest.middleware.panic_recovered"
	LogCodeMiddlewareResponseTruncated LogCode = "rest.middleware.response_truncated"

	// assets surface
	LogCodeAssetsGetByID LogCode = "rest.assets.get_by_id_failed"
	LogCodeAssetsList    LogCode = "rest.assets.list_failed"

	// events surface
	LogCodeEventsList LogCode = "rest.events.list_failed"

	// scans surface — read paths
	LogCodeScansGetLatest LogCode = "rest.scans.get_latest_failed"
	LogCodeScansGetByID   LogCode = "rest.scans.get_by_id_failed"

	// scans surface — start / cancel paths
	LogCodeScansStart             LogCode = "rest.scans.start_failed"
	LogCodeScansMarkCancel        LogCode = "rest.scans.mark_cancel_failed"
	LogCodeScansCoordinatorCancel LogCode = "rest.scans.coordinator_cancel_failed"

	// scans SSE stream
	LogCodeScansSSESnapshotWrite LogCode = "rest.scans.sse_snapshot_write_failed"
	LogCodeScansSSEWrite         LogCode = "rest.scans.sse_write_failed"

	// runtime_incidents / network / safety_guard list surfaces
	LogCodeRuntimeIncidentsList  LogCode = "rest.runtime_incidents.list_failed"
	LogCodeNetworkScanEventsList LogCode = "rest.network_scan_events.list_failed"
	LogCodeNetworkOpenPortsList  LogCode = "rest.network_open_ports.list_failed"
	LogCodeSafetyGuardEventsList LogCode = "rest.safety_guard_events.list_failed"
)
