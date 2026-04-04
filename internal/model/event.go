package model

import (
	"time"

	"github.com/google/uuid"
)

// AssetEvent records a lifecycle event associated with an asset.
type AssetEvent struct {
	Timestamp time.Time `json:"timestamp"`
	EventType EventType `json:"event_type"`
	Severity  Severity  `json:"severity"`
	Details   string    `json:"details"` // JSON
	ID        uuid.UUID `json:"id"`
	AssetID   uuid.UUID `json:"asset_id"`
	ScanRunID uuid.UUID `json:"scan_run_id"`
}
