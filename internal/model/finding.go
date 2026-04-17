package model

import (
	"time"

	"github.com/google/uuid"
)

// ConfigFinding represents a single configuration weakness discovered on an asset.
type ConfigFinding struct {
	// FirstSeenAt records when this finding was first observed. It is
	// preserved across scans so that mean-time-to-remediate can be computed.
	// Zero value means the timestamp is unknown (pre-migration rows).
	FirstSeenAt time.Time `json:"first_seen_at,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
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
	ID          uuid.UUID `json:"id"`
	AssetID     uuid.UUID `json:"asset_id"`
	ScanRunID   uuid.UUID `json:"scan_run_id"`
}
