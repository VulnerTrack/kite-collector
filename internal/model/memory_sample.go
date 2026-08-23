package model

import (
	"time"

	"github.com/google/uuid"
)

// MemorySample is one point in a machine's RAM time series: the total and used
// bytes (and the derived percentage) observed at SampledAt. It is collected
// cross-platform from gopsutil and persisted locally, independent of any
// telemetry backend.
type MemorySample struct {
	SampledAt   time.Time `json:"sampled_at"`
	ID          uuid.UUID `json:"id"`
	MachineID   uuid.UUID `json:"machine_id"`
	TotalBytes  uint64    `json:"total_bytes"`
	UsedBytes   uint64    `json:"used_bytes"`
	UsedPercent float64   `json:"used_percent"`
}
