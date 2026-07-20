package model

import (
	"time"

	"github.com/google/uuid"
)

// ScanRun tracks the state and statistics of a single discovery scan execution.
type ScanRun struct {
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	// CancelRequestedAt is stamped when a POST /api/v1/scans/{id}/cancel
	// request or SIGTERM arrives before the engine has reached a terminal
	// state. The engine's final CompleteScanRun still owns the status
	// transition; this column just records that an operator asked for it.
	CancelRequestedAt *time.Time `json:"cancel_requested_at,omitempty"`
	ScopeConfig       string     `json:"scope_config"`      // JSON
	DiscoverySources  string     `json:"discovery_sources"` // []string stored as JSON string
	// TriggerSource is the provenance tag: "cli", "api", or "scheduled"
	// (reserved for RFC-0104 future work).
	TriggerSource string `json:"trigger_source"`
	// TriggeredBy is the free-form caller identity — OS user for CLI runs,
	// mTLS CN or API-key label for API runs.
	TriggeredBy     string     `json:"triggered_by,omitempty"`
	Status          ScanStatus `json:"status"`
	ID              uuid.UUID  `json:"id"`
	CoveragePercent float64    `json:"coverage_percent"`
	TotalMachines   int        `json:"total_machines"`
	NewMachines     int        `json:"new_machines"`
	UpdatedMachines int        `json:"updated_machines"`
	// AnalyzedMachines counts rescans that produced an MachineAnalyzed event —
	// machines that were already known and had no material change since the
	// previous tick. These are tracked separately from UpdatedMachines so the
	// dashboard can distinguish real state deltas from steady-state ticks.
	AnalyzedMachines int `json:"analyzed_machines"`
	StaleMachines    int `json:"stale_machines"`
	ErrorCount       int `json:"error_count"`
}

// ScanResult is a summary returned after a scan completes.
type ScanResult struct {
	Status             string  `json:"status"`
	TotalMachines      int     `json:"total_machines"`
	NewMachines        int     `json:"new_machines"`
	UpdatedMachines    int     `json:"updated_machines"`
	AnalyzedMachines   int     `json:"analyzed_machines"`
	StaleMachines      int     `json:"stale_machines"`
	EventsEmitted      int     `json:"events_emitted"`
	SoftwareCount      int     `json:"software_count"`
	SoftwareErrors     int     `json:"software_errors"`
	FindingsCount      int     `json:"findings_count"`
	PostureCount       int     `json:"posture_count"`
	ErrorCount         int     `json:"error_count"`
	PanicsRecovered    int     `json:"panics_recovered"`
	SourcesCircuitOpen int     `json:"sources_circuit_open"`
	SourcesFailed      int     `json:"sources_failed"`
	CoveragePercent    float64 `json:"coverage_percent"`
}
