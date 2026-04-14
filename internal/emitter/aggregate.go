package emitter

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Compile-time interface check.
var _ Emitter = (*AggregateOTLPEmitter)(nil)

// AggregateOTLPEmitter collects asset events during a scan and emits
// only aggregate counts and severity signals via OTLP. No hostnames,
// IPs, MACs, or software details leave the agent.
//
// See RFC-0077 §5.2.2 for the payload specification.
type AggregateOTLPEmitter struct {
	last time.Time      // last flush
	otlp *OTLPEmitter   // underlying transport
	agg  aggregateState
	mu   sync.Mutex
}

// aggregateState tracks running counts across a scan.
type aggregateState struct {
	scanRunID          string
	totalAssets        int
	newAssets          int
	unauthorizedAssets int
	unmanagedAssets    int
	staleAssets        int
	criticalCVEs       int
	highCVEs           int
	findingsCount      int
	coveragePercent    float64
}

// NewAggregate creates an AggregateOTLPEmitter that wraps an existing
// OTLPEmitter. Events are buffered and aggregated; only counts are sent.
func NewAggregate(otlp *OTLPEmitter) *AggregateOTLPEmitter {
	return &AggregateOTLPEmitter{otlp: otlp}
}

// Emit records an event in the aggregate counters. No data is sent
// to the collector until Flush is called.
func (a *AggregateOTLPEmitter) Emit(_ context.Context, event model.AssetEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.agg.scanRunID == "" {
		a.agg.scanRunID = event.ScanRunID.String()
	}

	switch event.EventType {
	case model.EventAssetDiscovered:
		a.agg.totalAssets++
		a.agg.newAssets++
	case model.EventAssetUpdated:
		a.agg.totalAssets++
	case model.EventUnauthorizedAssetDetected:
		a.agg.unauthorizedAssets++
	case model.EventUnmanagedAssetDetected:
		a.agg.unmanagedAssets++
	case model.EventAssetNotSeen:
		a.agg.staleAssets++
	case model.EventAssetRemoved:
		a.agg.findingsCount++
	default:
		a.agg.findingsCount++
	}

	return nil
}

// EmitBatch records a batch of events in the aggregate counters.
func (a *AggregateOTLPEmitter) EmitBatch(ctx context.Context, events []model.AssetEvent) error {
	for i := range events {
		if err := a.Emit(ctx, events[i]); err != nil {
			return err
		}
	}
	return nil
}

// SetCorrelationStats injects CVE correlation aggregates that were
// computed by the correlation engine. Called after correlation completes.
func (a *AggregateOTLPEmitter) SetCorrelationStats(critical, high int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.agg.criticalCVEs = critical
	a.agg.highCVEs = high
}

// SetCoverage records the scan coverage percentage.
func (a *AggregateOTLPEmitter) SetCoverage(percent float64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.agg.coveragePercent = percent
}

// Flush sends the current aggregate state as a single OTLP log record
// and resets the counters. This should be called once per scan cycle.
func (a *AggregateOTLPEmitter) Flush(ctx context.Context) error {
	a.mu.Lock()
	state := a.agg
	a.agg = aggregateState{}
	a.last = time.Now()
	a.mu.Unlock()

	payload := a.buildAggregatePayload(state)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("aggregate: marshal payload: %w", err)
	}
	return a.otlp.sendWithRetry(ctx, body)
}

// Shutdown flushes remaining aggregates and shuts down the transport.
func (a *AggregateOTLPEmitter) Shutdown(ctx context.Context) error {
	if err := a.Flush(ctx); err != nil {
		// Best effort flush; still shut down the transport.
		_ = err
	}
	return a.otlp.Shutdown(ctx)
}

func (a *AggregateOTLPEmitter) buildAggregatePayload(state aggregateState) otlpLogsPayload {
	now := strconv.FormatInt(time.Now().UnixNano(), 10)

	attrs := []otlpKeyValue{
		stringKV("scan_run_id", state.scanRunID),
		intKV("total_assets", state.totalAssets),
		intKV("new_assets", state.newAssets),
		intKV("unauthorized_assets", state.unauthorizedAssets),
		intKV("unmanaged_assets", state.unmanagedAssets),
		intKV("stale_assets", state.staleAssets),
		intKV("critical_cves", state.criticalCVEs),
		intKV("high_cves", state.highCVEs),
		intKV("findings_count", state.findingsCount),
		doubleKV("coverage_percent", state.coveragePercent),
	}

	bodyStr := "aggregate_scan_summary"
	record := otlpLogRecord{
		TimeUnixNano:         now,
		ObservedTimeUnixNano: now,
		SeverityNumber:       9, // INFO
		SeverityText:         "INFO",
		Body:                 otlpAnyValue{StringValue: &bodyStr},
		Attributes:           attrs,
	}

	return otlpLogsPayload{
		ResourceLogs: []otlpResourceLog{
			{
				Resource: otlpResource{
					Attributes: []otlpKeyValue{
						stringKV("service.name", a.otlp.serviceName),
						stringKV("service.version", a.otlp.serviceVersion),
					},
				},
				ScopeLogs: []otlpScopeLog{
					{
						Scope:      otlpScope{Name: "kite-collector.aggregate"},
						LogRecords: []otlpLogRecord{record},
					},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Additional OTLP value helpers for aggregate payloads
// ---------------------------------------------------------------------------

// intKV creates an OTLP key-value pair with an integer value.
// OTLP JSON encodes integers as strings in the intValue field.
func intKV(key string, value int) otlpKeyValue {
	s := strconv.Itoa(value)
	return otlpKeyValue{Key: key, Value: otlpAnyValue{StringValue: &s}}
}

// doubleKV creates an OTLP key-value pair with a double value.
func doubleKV(key string, value float64) otlpKeyValue {
	s := strconv.FormatFloat(value, 'f', 1, 64)
	return otlpKeyValue{Key: key, Value: otlpAnyValue{StringValue: &s}}
}

