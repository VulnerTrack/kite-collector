package paas

// LogCode is the typed identifier attached to every structured log
// entry the PaaS-discovery package emits. Convention:
// `paas.<provider>.<event>` (per-provider) for events whose remediation
// is provider-specific, or `paas.<surface>.<event>` for cross-provider
// helpers (retry).
//
// Per-provider codes follow the same reasoning as
// internal/discovery/cloud + internal/discovery/vps: runbooks for
// "Vercel auth failed" and "Fly.io auth failed" target different
// dashboards, different docs, often different teams. On-call routing
// maps a code directly to a team without parsing sub-fields.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- Vercel ------------------------------------------------------
	LogCodeVercelStarting LogCode = "paas.vercel.starting"
	LogCodeVercelComplete LogCode = "paas.vercel.completed"

	// --- Render ------------------------------------------------------
	LogCodeRenderStarting           LogCode = "paas.render.starting"
	LogCodeRenderPaginationRejected LogCode = "paas.render.pagination_rejected"
	LogCodeRenderComplete           LogCode = "paas.render.completed"

	// --- Heroku ------------------------------------------------------
	LogCodeHerokuStarting LogCode = "paas.heroku.starting"
	LogCodeHerokuComplete LogCode = "paas.heroku.completed"

	// --- Coolify -----------------------------------------------------
	LogCodeCoolifyStarting          LogCode = "paas.coolify.starting"
	LogCodeCoolifyListServersFailed LogCode = "paas.coolify.list_servers_failed"
	LogCodeCoolifyComplete          LogCode = "paas.coolify.completed"

	// --- Railway -----------------------------------------------------
	LogCodeRailwayStarting LogCode = "paas.railway.starting"
	LogCodeRailwayComplete LogCode = "paas.railway.completed"

	// --- Fly.io ------------------------------------------------------
	LogCodeFlyIOStarting           LogCode = "paas.flyio.starting"
	LogCodeFlyIOInvalidAppName     LogCode = "paas.flyio.invalid_app_name"
	LogCodeFlyIOListMachinesFailed LogCode = "paas.flyio.list_machines_failed"
	LogCodeFlyIOComplete           LogCode = "paas.flyio.completed"

	// --- CapRover ----------------------------------------------------
	LogCodeCapRoverStarting LogCode = "paas.caprover.starting"
	LogCodeCapRoverComplete LogCode = "paas.caprover.completed"

	// --- retry helper (paas.go) — shared across every provider -------
	LogCodePaaSRetryBackoff      LogCode = "paas.retry.backoff"
	LogCodePaaSRetryNetworkError LogCode = "paas.retry.network_error"
	LogCodePaaSRetryRateLimited  LogCode = "paas.retry.rate_limited"
	LogCodePaaSRetryServerError  LogCode = "paas.retry.server_error"
)
