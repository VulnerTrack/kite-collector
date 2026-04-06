package model

import (
	"time"

	"github.com/google/uuid"
)

// PostureAssessment represents a CAPEC attack pattern matched against one or
// more configuration findings on an asset.
type PostureAssessment struct {
	ID         uuid.UUID   `json:"id"`
	AssetID    uuid.UUID   `json:"asset_id"`
	ScanRunID  uuid.UUID   `json:"scan_run_id"`
	CAPECID    string      `json:"capec_id"`
	CAPECName  string      `json:"capec_name"`
	FindingIDs []uuid.UUID `json:"finding_ids"`
	Likelihood Severity    `json:"likelihood"`
	Mitigation string      `json:"mitigation"`
	Timestamp  time.Time   `json:"timestamp"`
}
