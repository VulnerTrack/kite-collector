package proxmox

// LogCode is the typed identifier attached to every structured log
// entry the Proxmox VE discovery package emits. Convention:
// `proxmox.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- enumerate surface (per-node guest enumeration) --------------
	LogCodeEnumerateVMsFailed       LogCode = "proxmox.enumerate.vms_failed"
	LogCodeEnumerateLXCFailed       LogCode = "proxmox.enumerate.lxc_failed"
	LogCodeEnumerateVMConfigFailed  LogCode = "proxmox.enumerate.vm_config_failed"
	LogCodeEnumerateSnapshotsFailed LogCode = "proxmox.enumerate.snapshots_failed"
)
