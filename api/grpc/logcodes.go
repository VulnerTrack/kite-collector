package grpcapi

// LogCode is the typed identifier attached to every structured log
// entry the gRPC API package emits. Convention:
// `grpc.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// interceptors surface — panic recovery in unary/stream handlers
	LogCodeInterceptorsUnaryPanicRecovered  LogCode = "grpc.interceptors.unary_panic_recovered"
	LogCodeInterceptorsStreamPanicRecovered LogCode = "grpc.interceptors.stream_panic_recovered"

	// server surface — listener lifecycle and per-RPC failures
	LogCodeServerInsecureListener    LogCode = "grpc.server.insecure_listener"
	LogCodeServerAssetUpsertFail     LogCode = "grpc.server.asset_upsert_failed"
	LogCodeServerSoftwareUpsertFail  LogCode = "grpc.server.software_upsert_failed"
	LogCodeServerHeartbeatCNMismatch LogCode = "grpc.server.heartbeat_cn_mismatch"
)
