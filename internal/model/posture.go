package model

import (
	"time"

	"github.com/google/uuid"
)

// PostureAssessment represents a CAPEC attack pattern matched against one or
// more configuration findings on an asset.
type PostureAssessment struct {
	Timestamp  time.Time   `json:"timestamp"`
	CAPECID    string      `json:"capec_id"`
	CAPECName  string      `json:"capec_name"`
	Likelihood Severity    `json:"likelihood"`
	Mitigation string      `json:"mitigation"`
	FindingIDs []uuid.UUID `json:"finding_ids"`
	ID         uuid.UUID   `json:"id"`
	AssetID    uuid.UUID   `json:"asset_id"`
	ScanRunID  uuid.UUID   `json:"scan_run_id"`
}
