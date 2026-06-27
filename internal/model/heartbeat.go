package model

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// HeartbeatStatus is the closed enum used on ProbeHeartbeat.Status. Mirrors
// contract.AllowedProbeStatus and must stay in sync with it.
type HeartbeatStatus string

const (
	HeartbeatOK          HeartbeatStatus = "ok"
	HeartbeatError       HeartbeatStatus = "error"
	HeartbeatTimeout     HeartbeatStatus = "timeout"
	HeartbeatCircuitOpen HeartbeatStatus = "circuit_open"
)

// ProbeHeartbeat is the synthetic per-source per-scan liveness record. Every
// discovery source emits exactly one — whether it found assets or not — so
// the absence of a heartbeat for an expected collector is itself a signal.
//
// Signature is an Ed25519 signature over CanonicalPayload(), so the reconciler
// can verify the record was produced by a process holding the install's
// private key and that the binary hash field was not rewritten in transit.
type ProbeHeartbeat struct {
	CreatedAt    time.Time       `json:"created_at"`
	Source       string          `json:"source"`
	Status       HeartbeatStatus `json:"status"`
	BinaryHash   string          `json:"binary_hash"`
	Signature    []byte          `json:"signature"`
	ItemsEmitted int             `json:"items_emitted"`
	DurationMS   int64           `json:"duration_ms"`
	ID           uuid.UUID       `json:"id"`
	ScanRunID    uuid.UUID       `json:"scan_run_id"`
}

// CanonicalPayload returns the byte sequence Sign/Verify operate over. Order
// and separators are part of the wire contract: any change requires a major
// telemetry contract bump because old signatures stop verifying. Fields are
// joined with a "|" delimiter — never present in any of the underlying
// values (scan UUID, source name validated against the closed enum, status
// enum, integer-formatted counters, sha256: hex hash).
func (h ProbeHeartbeat) CanonicalPayload() []byte {
	return []byte(fmt.Sprintf("v1|%s|%s|%s|%d|%d|%s",
		h.ScanRunID.String(),
		h.Source,
		string(h.Status),
		h.ItemsEmitted,
		h.DurationMS,
		h.BinaryHash,
	))
}
