package model

import (
	"time"

	"github.com/google/uuid"
)

// ConfigFinding represents a single configuration weakness discovered on an asset.
type ConfigFinding struct {
	ID          uuid.UUID `json:"id"`
	AssetID     uuid.UUID `json:"asset_id"`
	ScanRunID   uuid.UUID `json:"scan_run_id"`
	Auditor     string    `json:"auditor"`
	CheckID     string    `json:"check_id"`
	Title       string    `json:"title"`
	Severity    Severity  `json:"severity"`
	CWEID       string    `json:"cwe_id"`
	CWEName     string    `json:"cwe_name"`
	Evidence    string    `json:"evidence"`
	Expected    string    `json:"expected"`
	Remediation string    `json:"remediation"`
	CISControl  string    `json:"cis_control,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}
