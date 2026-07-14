package main

// LogCode is the typed identifier attached to every structured log
// entry the kite-collector agent binary emits. Convention:
// `agent.<surface>.<event>` so downstream tooling (Loki/Splunk queries,
// alerting rules, runbooks) can pivot on a stable identifier without
// parsing freeform message text.
//
// The "agent" namespace deliberately differs from the cmd/main package
// name because operators reason about this binary as "the agent" — code
// like `agent.scan.initial_failed` reads correctly in an alert rule
// even though it originates inside package main.
//
// Every Warn/Error site MUST include the code as a `"code"` structured
// attribute. Info sites should include one when they mark a notable
// state transition operators want to alert or dashboard on (startup,
// shutdown, scan-cycle boundaries).
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// bootstrap surface — startup-time configuration validation
	LogCodeBootstrapDataDirNotWritable LogCode = "agent.bootstrap.data_dir_not_writable"

	// tunnel surface — optional reverse-tunnel to the platform
	LogCodeTunnelStartFailed     LogCode = "agent.tunnel.start_failed"
	LogCodeTunnelRewroteEndpoint LogCode = "agent.tunnel.rewrote_endpoint"

	// store surface — which backend the agent selected
	LogCodeStorePostgresSelected LogCode = "agent.store.backend_selected_postgres"
	LogCodeStoreSQLiteSelected   LogCode = "agent.store.backend_selected_sqlite"

	// telemetry surface — OTLP wiring decisions
	LogCodeTelemetryIdentityUnavailable LogCode = "agent.telemetry.identity_unavailable"
	LogCodeTelemetryOTLPConfigured      LogCode = "agent.telemetry.otlp_configured"
	LogCodeTelemetryOTLPDisabled        LogCode = "agent.telemetry.otlp_disabled"

	// api surface — REST API server lifecycle
	LogCodeAPIStarting     LogCode = "agent.api.starting"
	LogCodeAPIServerFailed LogCode = "agent.api.server_failed"

	// dashboard surface — embedded dashboard server lifecycle
	LogCodeDashboardStarting       LogCode = "agent.dashboard.starting"
	LogCodeDashboardServerFailed   LogCode = "agent.dashboard.server_failed"
	LogCodeDashboardListening      LogCode = "agent.dashboard.listening"
	LogCodeDashboardListenerFailed LogCode = "agent.dashboard.listener_failed"

	// scan surface — long-running scan loop
	LogCodeScanStreamingStarting LogCode = "agent.scan.streaming_starting"
	LogCodeScanInitialFailed     LogCode = "agent.scan.initial_failed"
	LogCodeScanInitialComplete   LogCode = "agent.scan.initial_complete"
	LogCodeScanPeriodicFailed    LogCode = "agent.scan.periodic_failed"
	LogCodeScanPeriodicComplete  LogCode = "agent.scan.periodic_complete"
	LogCodeAgentShutdown         LogCode = "agent.lifecycle.shutdown"

	// engine surface — scan engine identity wiring
	LogCodeEngineIdentityUnavailable LogCode = "agent.engine.identity_unavailable"

	// cli surface — inspector / wizard commands
	LogCodeCLIFlushWriter        LogCode = "agent.cli.flush_writer_failed"
	LogCodeCLIConfigLoadFallback LogCode = "agent.cli.config_load_fallback"

	// enrollment surface — CLI-driven enrollment wizard
	LogCodeEnrollRequestSubmitted LogCode = "agent.enroll.request_submitted"
	LogCodeEnrollComplete         LogCode = "agent.enroll.complete"

	// login surface — OAuth sign-in enrollment (copy/paste code flow)
	LogCodeLoginTokenAcquired LogCode = "agent.login.token_acquired"
)
