package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// newScanRun creates a minimal scan_runs row so probe_heartbeats inserts
// satisfy the FK without dragging in the full Engine machinery.
func newScanRun(t *testing.T, s *SQLiteStore) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	require.NoError(t, s.CreateScanRun(context.Background(), model.ScanRun{
		ID:        id,
		StartedAt: time.Now().UTC(),
		Status:    model.ScanStatusRunning,
	}))
	return id
}

func newHeartbeat(scanID uuid.UUID, source string, status model.HeartbeatStatus, items int) model.ProbeHeartbeat {
	return model.ProbeHeartbeat{
		ID:           uuid.Must(uuid.NewV7()),
		ScanRunID:    scanID,
		Source:       source,
		Status:       status,
		ItemsEmitted: items,
		DurationMS:   42,
		BinaryHash:   "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		Signature:    []byte{0x01, 0x02, 0x03, 0x04},
		CreatedAt:    time.Now().UTC(),
	}
}

func TestRecordHeartbeat_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	scanID := newScanRun(t, s)

	hb := newHeartbeat(scanID, "agent.firewall", model.HeartbeatOK, 17)
	require.NoError(t, s.RecordHeartbeat(ctx, hb))

	got, err := s.ListHeartbeats(ctx, store.HeartbeatFilter{ScanRunID: &scanID})
	require.NoError(t, err)
	require.Len(t, got, 1)

	assert.Equal(t, hb.ID, got[0].ID)
	assert.Equal(t, hb.Source, got[0].Source)
	assert.Equal(t, hb.Status, got[0].Status)
	assert.Equal(t, hb.ItemsEmitted, got[0].ItemsEmitted)
	assert.Equal(t, hb.DurationMS, got[0].DurationMS)
	assert.Equal(t, hb.BinaryHash, got[0].BinaryHash)
	assert.Equal(t, hb.Signature, got[0].Signature)
}

func TestRecordHeartbeat_RejectsDuplicateSourcePerScan(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	scanID := newScanRun(t, s)

	require.NoError(t, s.RecordHeartbeat(ctx,
		newHeartbeat(scanID, "agent.firewall", model.HeartbeatOK, 1)))

	// Second insert for the same (scan, source) must fail — the registry
	// emits exactly one heartbeat per source per scan; a duplicate is a
	// programming error, not an event to swallow.
	err := s.RecordHeartbeat(ctx,
		newHeartbeat(scanID, "agent.firewall", model.HeartbeatOK, 2))
	require.Error(t, err)
}

func TestListHeartbeats_FilterBySourceAndStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	scanID := newScanRun(t, s)

	require.NoError(t, s.RecordHeartbeat(ctx,
		newHeartbeat(scanID, "agent.firewall", model.HeartbeatOK, 5)))
	require.NoError(t, s.RecordHeartbeat(ctx,
		newHeartbeat(scanID, "agent.processes", model.HeartbeatError, 0)))
	require.NoError(t, s.RecordHeartbeat(ctx,
		newHeartbeat(scanID, "agent.users", model.HeartbeatOK, 12)))

	allOK, err := s.ListHeartbeats(ctx, store.HeartbeatFilter{Status: "ok"})
	require.NoError(t, err)
	assert.Len(t, allOK, 2)

	just, err := s.ListHeartbeats(ctx, store.HeartbeatFilter{Source: "agent.processes"})
	require.NoError(t, err)
	require.Len(t, just, 1)
	assert.Equal(t, model.HeartbeatError, just[0].Status)
}

func TestListHeartbeats_RejectsWidenedIncidentTypes(t *testing.T) {
	// Asserts the migration that widened runtime_incidents.incident_type to
	// admit tamper_detected and canary_drift actually applied — the table
	// has to accept inserts with those values, which a pre-migration build
	// would reject via CHECK constraint.
	s := newTestStore(t)
	ctx := context.Background()
	scanID := newScanRun(t, s)

	for _, kind := range []model.IncidentType{
		model.IncidentTamperDetected,
		model.IncidentCanaryDrift,
	} {
		require.NoError(t, s.InsertRuntimeIncident(ctx, model.RuntimeIncident{
			ID:           uuid.Must(uuid.NewV7()),
			IncidentType: kind,
			Component:    "test",
			ErrorMessage: "synthetic",
			ScanRunID:    &scanID,
			Severity:     string(model.SeverityHigh),
			Recovered:    false,
			CreatedAt:    time.Now().UTC(),
		}))
	}
}
