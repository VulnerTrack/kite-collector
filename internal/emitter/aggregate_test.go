package emitter

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// newAggregateHarness wires an AggregateOTLPEmitter to a capture server so
// flushed payloads can be asserted byte-for-byte.
func newAggregateHarness(t *testing.T, status int) (*AggregateOTLPEmitter, *[]capturedRequest) {
	t.Helper()
	endpoint, reqs := startCaptureServer(t, status)
	otlp := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = otlp.Shutdown(context.Background()) })
	return NewAggregate(otlp), reqs
}

func aggregateEvent(eventType model.EventType, scanRun uuid.UUID) model.MachineEvent {
	return model.MachineEvent{
		ID:        uuid.Must(uuid.NewV7()),
		MachineID: uuid.Must(uuid.NewV7()),
		ScanRunID: scanRun,
		Timestamp: time.Unix(1_700_000_000, 0),
		EventType: eventType,
		Severity:  model.SeverityLow,
	}
}

// flushedRecord flushes the aggregate and returns the single log record of
// the single request that reached the capture server.
func flushedRecord(t *testing.T, agg *AggregateOTLPEmitter, reqs *[]capturedRequest) otlpLogRecord {
	t.Helper()
	require.NoError(t, agg.Flush(context.Background()))
	require.Len(t, *reqs, 1, "one flush must produce exactly one request")

	got := (*reqs)[0]
	assert.Equal(t, "/v1/logs", got.Path)
	assert.Equal(t, "application/json", got.ContentType)

	payload := decodeOTLPPayload(t, got.Body)
	require.Len(t, payload.ResourceLogs, 1)
	rl := payload.ResourceLogs[0]
	require.Len(t, rl.ScopeLogs, 1)
	assert.Equal(t, "kite-collector.aggregate", rl.ScopeLogs[0].Scope.Name)
	require.Len(t, rl.ScopeLogs[0].LogRecords, 1)
	return rl.ScopeLogs[0].LogRecords[0]
}

func TestAggregate_FlushCountsEveryEventClass(t *testing.T) {
	agg, reqs := newAggregateHarness(t, http.StatusOK)
	scanRun := uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-0123456789ab")

	ctx := context.Background()
	for _, et := range []model.EventType{
		model.EventMachineDiscovered,           // total+new
		model.EventMachineUpdated,              // total
		model.EventMachineAnalyzed,             // total, but NOT new
		model.EventUnauthorizedMachineDetected, // unauthorized
		model.EventUnmanagedMachineDetected,    // unmanaged
		model.EventMachineNotSeen,              // stale
		model.EventMachineRemoved,              // findings
		model.EventType("SomethingNovel"),      // default branch → findings
	} {
		require.NoError(t, agg.Emit(ctx, aggregateEvent(et, scanRun)))
	}
	agg.SetCorrelationStats(3, 7)
	agg.SetCoverage(87.5)

	rec := flushedRecord(t, agg, reqs)

	assert.Equal(t, 9, rec.SeverityNumber)
	assert.Equal(t, "INFO", rec.SeverityText)
	require.NotNil(t, rec.Body.StringValue)
	assert.Equal(t, "aggregate_scan_summary", *rec.Body.StringValue)

	attrs := attrMap(rec.Attributes)
	assert.Equal(t, scanRun.String(), attrs["scan_run_id"])
	assert.Equal(t, "3", attrs["total_machines"], "discovered+updated+analyzed")
	assert.Equal(t, "1", attrs["new_machines"], "analyzed rescans must not count as new")
	assert.Equal(t, "1", attrs["unauthorized_machines"])
	assert.Equal(t, "1", attrs["unmanaged_machines"])
	assert.Equal(t, "1", attrs["stale_machines"])
	assert.Equal(t, "2", attrs["findings_count"], "removed + unknown event types")
	assert.Equal(t, "3", attrs["critical_cves"])
	assert.Equal(t, "7", attrs["high_cves"])
	assert.Equal(t, "87.5", attrs["coverage_percent"])
}

func TestAggregate_EmitKeepsFirstScanRunID(t *testing.T) {
	agg, reqs := newAggregateHarness(t, http.StatusOK)
	first := uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-000000000001")
	second := uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-000000000002")

	ctx := context.Background()
	require.NoError(t, agg.Emit(ctx, aggregateEvent(model.EventMachineDiscovered, first)))
	require.NoError(t, agg.Emit(ctx, aggregateEvent(model.EventMachineDiscovered, second)))

	rec := flushedRecord(t, agg, reqs)
	assert.Equal(t, first.String(), attrMap(rec.Attributes)["scan_run_id"])
}

func TestAggregate_EmitBatchAggregatesAllEvents(t *testing.T) {
	agg, reqs := newAggregateHarness(t, http.StatusOK)
	scanRun := uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-0123456789ab")

	events := []model.MachineEvent{
		aggregateEvent(model.EventMachineDiscovered, scanRun),
		aggregateEvent(model.EventMachineDiscovered, scanRun),
		aggregateEvent(model.EventMachineNotSeen, scanRun),
	}
	require.NoError(t, agg.EmitBatch(context.Background(), events))

	rec := flushedRecord(t, agg, reqs)
	attrs := attrMap(rec.Attributes)
	assert.Equal(t, "2", attrs["total_machines"])
	assert.Equal(t, "2", attrs["new_machines"])
	assert.Equal(t, "1", attrs["stale_machines"])
}

func TestAggregate_FlushResetsState(t *testing.T) {
	agg, reqs := newAggregateHarness(t, http.StatusOK)
	scanRun := uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-0123456789ab")

	ctx := context.Background()
	require.NoError(t, agg.Emit(ctx, aggregateEvent(model.EventMachineDiscovered, scanRun)))
	agg.SetCorrelationStats(5, 9)
	agg.SetCoverage(50)
	require.NoError(t, agg.Flush(ctx))
	require.NoError(t, agg.Flush(ctx))

	require.Len(t, *reqs, 2)
	attrs := attrMap(decodeOTLPPayload(t, (*reqs)[1].Body).
		ResourceLogs[0].ScopeLogs[0].LogRecords[0].Attributes)
	assert.Equal(t, "", attrs["scan_run_id"], "flush must reset the scan run id")
	assert.Equal(t, "0", attrs["total_machines"])
	assert.Equal(t, "0", attrs["new_machines"])
	assert.Equal(t, "0", attrs["critical_cves"])
	assert.Equal(t, "0", attrs["high_cves"])
	assert.Equal(t, "0.0", attrs["coverage_percent"])
}

func TestAggregate_FlushSurfacesTransportError(t *testing.T) {
	agg, reqs := newAggregateHarness(t, http.StatusBadRequest)

	err := agg.Flush(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server returned 400")
	assert.Len(t, *reqs, 1, "4xx must not be retried")
}

func TestAggregate_ShutdownFlushesThenClosesTransport(t *testing.T) {
	endpoint, reqs := startCaptureServer(t, http.StatusOK)
	otlp := newWireTestEmitter(t, endpoint)
	agg := NewAggregate(otlp)

	require.NoError(t, agg.Shutdown(context.Background()))
	require.Len(t, *reqs, 1, "shutdown must flush the final aggregate")

	err := otlp.EmitBatch(context.Background(), []model.MachineEvent{{}})
	require.Error(t, err, "underlying transport must be closed after aggregate shutdown")
	assert.Contains(t, err.Error(), "shut down")
}

func TestAggregate_ShutdownSucceedsEvenWhenFlushFails(t *testing.T) {
	endpoint, reqs := startCaptureServer(t, http.StatusBadRequest)
	otlp := newWireTestEmitter(t, endpoint)
	agg := NewAggregate(otlp)

	require.NoError(t, agg.Shutdown(context.Background()),
		"a failed best-effort flush must not fail shutdown")
	assert.Len(t, *reqs, 1)
}

func TestIntKV_EncodesIntegerAsString(t *testing.T) {
	kv := intKV("total_machines", 42)
	assert.Equal(t, "total_machines", kv.Key)
	require.NotNil(t, kv.Value.StringValue)
	assert.Equal(t, "42", *kv.Value.StringValue)
}

func TestDoubleKV_FormatsWithOneDecimal(t *testing.T) {
	kv := doubleKV("coverage_percent", 12.34)
	assert.Equal(t, "coverage_percent", kv.Key)
	require.NotNil(t, kv.Value.StringValue)
	assert.Equal(t, "12.3", *kv.Value.StringValue)

	kv = doubleKV("coverage_percent", 100)
	assert.Equal(t, "100.0", *kv.Value.StringValue)
}
