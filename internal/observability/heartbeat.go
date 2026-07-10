package observability

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/identity"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// HeartbeatSink is the minimal store surface the recorder needs. The
// concrete sqlite/postgres stores satisfy it; tests use a fake.
type HeartbeatSink interface {
	RecordHeartbeat(ctx context.Context, hb model.ProbeHeartbeat) error
}

// Recorder writes one signed ProbeHeartbeat per (scan_run, source). It is
// constructed once per scan by the Engine and handed to the discovery
// Registry via SetHeartbeatRecorder, so every Record call is automatically
// scoped to the right scan_run_id.
type Recorder struct {
	sink     HeartbeatSink
	identity *identity.Identity
	logger   *slog.Logger
	scanID   uuid.UUID
}

// NewRecorder binds a scan, signing identity, and sink. logger may be nil
// in which case slog.Default() is used.
func NewRecorder(scanID uuid.UUID, id *identity.Identity, sink HeartbeatSink, logger *slog.Logger) *Recorder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Recorder{
		scanID:   scanID,
		identity: id,
		sink:     sink,
		logger:   logger,
	}
}

// Record persists one heartbeat. Returning an error here surfaces inside
// the Registry's emitHeartbeat wrapper, which logs but does not propagate —
// a failed heartbeat must not cancel real discovery work.
func (r *Recorder) Record(
	ctx context.Context,
	source string,
	status model.HeartbeatStatus,
	itemsEmitted int,
	duration time.Duration,
) error {
	hb := model.ProbeHeartbeat{
		ID:           uuid.Must(uuid.NewV7()),
		ScanRunID:    r.scanID,
		Source:       source,
		Status:       status,
		ItemsEmitted: itemsEmitted,
		DurationMS:   duration.Milliseconds(),
		BinaryHash:   r.identity.BinaryHash,
		CreatedAt:    time.Now().UTC(),
	}
	hb.Signature = r.identity.Sign(hb.CanonicalPayload())

	if err := r.sink.RecordHeartbeat(ctx, hb); err != nil {
		r.logger.Warn(
			"heartbeat persist failed",
			"code", string(LogCodeHeartbeatPersistErr),
			"scan_id", r.scanID,
			"source", source,
			"status", status,
			"error", err,
		)
		return fmt.Errorf("record heartbeat: %w", err)
	}

	r.logger.Debug(
		"heartbeat emitted",
		"code", string(LogCodeHeartbeatEmitted),
		"scan_id", r.scanID,
		"source", source,
		"status", status,
		"items_emitted", itemsEmitted,
		"duration_ms", hb.DurationMS,
	)
	return nil
}
