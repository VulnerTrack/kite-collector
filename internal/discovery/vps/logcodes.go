package vps

// LogCode is the typed identifier attached to every structured log
// entry the VPS-discovery package emits. Convention:
// `vps.<provider>.<event>` (per-provider) for events whose remediation
// is provider-specific, or `vps.<surface>.<event>` for cross-provider
// helpers (retry).
//
// Per-provider codes follow the same reasoning as
// internal/discovery/cloud: runbooks for "Linode auth failed" and
// "DigitalOcean auth failed" target different consoles, different
// docs, often different teams. On-call routing maps a code directly
// to a team without parsing sub-fields.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- Vultr -------------------------------------------------------
	LogCodeVultrStarting           LogCode = "vps.vultr.starting"
	LogCodeVultrPaginationRejected LogCode = "vps.vultr.pagination_rejected"
	LogCodeVultrComplete           LogCode = "vps.vultr.completed"

	// --- Scaleway ----------------------------------------------------
	LogCodeScalewayStarting LogCode = "vps.scaleway.starting"
	LogCodeScalewayComplete LogCode = "vps.scaleway.completed"

	// --- Linode ------------------------------------------------------
	LogCodeLinodeStarting LogCode = "vps.linode.starting"
	LogCodeLinodeComplete LogCode = "vps.linode.completed"

	// --- Kamatera ----------------------------------------------------
	LogCodeKamateraStarting LogCode = "vps.kamatera.starting"
	LogCodeKamateraComplete LogCode = "vps.kamatera.completed"

	// --- Hostinger ---------------------------------------------------
	LogCodeHostingerStarting LogCode = "vps.hostinger.starting"
	LogCodeHostingerComplete LogCode = "vps.hostinger.completed"

	// --- Hetzner -----------------------------------------------------
	LogCodeHetznerStarting LogCode = "vps.hetzner.starting"
	LogCodeHetznerComplete LogCode = "vps.hetzner.completed"

	// --- DigitalOcean ------------------------------------------------
	LogCodeDigitalOceanStarting LogCode = "vps.digitalocean.starting"
	LogCodeDigitalOceanComplete LogCode = "vps.digitalocean.completed"

	// --- UpCloud -----------------------------------------------------
	LogCodeUpCloudStarting LogCode = "vps.upcloud.starting"
	LogCodeUpCloudComplete LogCode = "vps.upcloud.completed"

	// --- OVHcloud (richer surface — splits dedicated vs VPS APIs) ----
	LogCodeOVHCloudStarting                LogCode = "vps.ovhcloud.starting"
	LogCodeOVHCloudDedicatedDiscoverFailed LogCode = "vps.ovhcloud.dedicated_discover_failed"
	LogCodeOVHCloudVPSDiscoverFailed       LogCode = "vps.ovhcloud.vps_discover_failed"
	LogCodeOVHCloudComplete                LogCode = "vps.ovhcloud.completed"
	LogCodeOVHCloudSkipUnsafeDedicated     LogCode = "vps.ovhcloud.skip_unsafe_dedicated_name"
	LogCodeOVHCloudGetDedicatedFailed      LogCode = "vps.ovhcloud.get_dedicated_failed"
	LogCodeOVHCloudSkipUnsafeVPS           LogCode = "vps.ovhcloud.skip_unsafe_vps_name"
	LogCodeOVHCloudGetVPSFailed            LogCode = "vps.ovhcloud.get_vps_failed"

	// --- retry helper (vps.go) — shared across every provider --------
	// Same shape as internal/discovery/cloud's retry codes. The
	// `caller` structured field carries the per-provider context
	// (e.g., "vultr.listInstances") so per-provider retry-storm
	// dashboards still work even though the code is shared.
	LogCodeVPSRetryBackoff      LogCode = "vps.retry.backoff"
	LogCodeVPSRetryNetworkError LogCode = "vps.retry.network_error"
	LogCodeVPSRetryRateLimited  LogCode = "vps.retry.rate_limited"
	LogCodeVPSRetryServerError  LogCode = "vps.retry.server_error"
)
