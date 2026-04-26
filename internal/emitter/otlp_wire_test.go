package emitter

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// capturedRequest records a single HTTP request hitting the fake OTLP server.
type capturedRequest struct {
	Method      string
	Path        string
	ContentType string
	Body        []byte
}

// startCaptureServer launches an httptest.Server that records every inbound
// request into a thread-safe slice and replies with the supplied status code.
// The returned slice pointer is updated as requests arrive.
func startCaptureServer(t *testing.T, status int) (string, *[]capturedRequest) {
	t.Helper()
	var (
		mu       sync.Mutex
		captured []capturedRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = r.Body.Close()
		mu.Lock()
		captured = append(captured, capturedRequest{
			Method:      r.Method,
			Path:        r.URL.Path,
			ContentType: r.Header.Get("Content-Type"),
			Body:        body,
		})
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &captured
}

// startSequenceServer is like startCaptureServer but returns a different
// status for each subsequent request, defaulting to the last value once the
// sequence is exhausted. Useful for retry tests.
func startSequenceServer(t *testing.T, statuses []int) (string, *[]capturedRequest) {
	t.Helper()
	var (
		mu       sync.Mutex
		captured []capturedRequest
		idx      int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = r.Body.Close()
		mu.Lock()
		captured = append(captured, capturedRequest{
			Method:      r.Method,
			Path:        r.URL.Path,
			ContentType: r.Header.Get("Content-Type"),
			Body:        body,
		})
		status := statuses[len(statuses)-1]
		if idx < len(statuses) {
			status = statuses[idx]
		}
		idx++
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &captured
}

// decodeOTLPPayload parses the captured request body into the same internal
// payload structs the emitter produces. Same-package access keeps assertions
// type-safe.
func decodeOTLPPayload(t *testing.T, body []byte) otlpLogsPayload {
	t.Helper()
	var p otlpLogsPayload
	require.NoError(t, json.Unmarshal(body, &p))
	return p
}

// newWireTestEmitter builds an emitter pointed at endpoint with retry timing
// tightened down to milliseconds so retry tests stay well under one second.
func newWireTestEmitter(t *testing.T, endpoint string) *OTLPEmitter {
	t.Helper()
	o, err := NewOTLP(OTLPConfig{Endpoint: endpoint}, "9.9.9")
	require.NoError(t, err)
	o.retry = retryConfig{
		maxAttempts: 3,
		baseDelay:   1 * time.Millisecond,
		maxDelay:    5 * time.Millisecond,
	}
	return o
}

// attrMap flattens an OTLP attribute slice into a key→stringValue map for
// ergonomic lookups in assertions.
func attrMap(kvs []otlpKeyValue) map[string]string {
	m := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		if kv.Value.StringValue != nil {
			m[kv.Key] = *kv.Value.StringValue
		} else {
			m[kv.Key] = ""
		}
	}
	return m
}

// makeEvent assembles a fully-populated event for tests that want to assert
// optional attributes flow through.
func makeEvent(t *testing.T, eventType model.EventType, sev model.Severity) model.AssetEvent {
	t.Helper()
	return model.AssetEvent{
		ID:        uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-fedcba987654"),
		AssetID:   uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-aaaabbbbcccc"),
		ScanRunID: uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-0123456789ab"),
		Timestamp: time.Unix(1_700_000_000, 0),
		EventType: eventType,
		Severity:  sev,
		Details:   `{"reason":"unit-test"}`,
	}
}

// ---------------------------------------------------------------------------
// 1. Canonical event shape
// ---------------------------------------------------------------------------

func TestOTLP_WireShape_CanonicalEvent(t *testing.T) {
	endpoint, reqs := startCaptureServer(t, http.StatusOK)
	em := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	evt := makeEvent(t, model.EventAssetDiscovered, model.SeverityMedium)

	emitStart := time.Now()
	require.NoError(t, em.Emit(context.Background(), evt))

	require.Len(t, *reqs, 1, "expected exactly one request")
	got := (*reqs)[0]

	assert.Equal(t, http.MethodPost, got.Method)
	assert.Equal(t, "/v1/logs", got.Path)
	assert.Equal(t, "application/json", got.ContentType)

	payload := decodeOTLPPayload(t, got.Body)

	require.Len(t, payload.ResourceLogs, 1)
	rl := payload.ResourceLogs[0]
	resAttrs := attrMap(rl.Resource.Attributes)
	assert.Equal(t, "kite-collector", resAttrs["service.name"])
	assert.Equal(t, "9.9.9", resAttrs["service.version"])

	require.Len(t, rl.ScopeLogs, 1)
	sl := rl.ScopeLogs[0]
	assert.Equal(t, "kite-collector.emitter", sl.Scope.Name)

	require.Len(t, sl.LogRecords, 1)
	rec := sl.LogRecords[0]

	timeNanos, err := strconv.ParseInt(rec.TimeUnixNano, 10, 64)
	require.NoError(t, err, "timeUnixNano must parse to int64")
	observedNanos, err := strconv.ParseInt(rec.ObservedTimeUnixNano, 10, 64)
	require.NoError(t, err, "observedTimeUnixNano must parse to int64")
	assert.GreaterOrEqual(t, observedNanos, timeNanos, "observed time must be >= event time")
	assert.GreaterOrEqual(t, observedNanos, emitStart.Add(-time.Second).UnixNano(),
		"observed time must be near now")

	assert.Equal(t, 9, rec.SeverityNumber)
	assert.Equal(t, "medium", rec.SeverityText)

	require.NotNil(t, rec.Body.StringValue)
	assert.Equal(t, evt.Details, *rec.Body.StringValue)

	attrs := attrMap(rec.Attributes)
	assert.Equal(t, string(evt.EventType), attrs["event_type"])
	assert.Equal(t, evt.AssetID.String(), attrs["asset_id"])
	assert.Equal(t, evt.ScanRunID.String(), attrs["scan_run_id"])
	assert.Equal(t, string(evt.Severity), attrs["severity"])

	assert.Len(t, rec.TraceID, 32, "traceId must be 32 hex chars")
	assert.Equal(t, hex.EncodeToString(evt.ScanRunID[:]), rec.TraceID)
	assert.Len(t, rec.SpanID, 16, "spanId must be 16 hex chars")
	assert.Equal(t, hex.EncodeToString(evt.ID[:8]), rec.SpanID)
}

// ---------------------------------------------------------------------------
// 2. All event types reach the wire
// ---------------------------------------------------------------------------

func TestOTLP_WireShape_AllEventTypes(t *testing.T) {
	cases := []model.EventType{
		model.EventAssetDiscovered,
		model.EventAssetUpdated,
		model.EventUnauthorizedAssetDetected,
		model.EventUnmanagedAssetDetected,
		model.EventAssetNotSeen,
		model.EventAssetRemoved,
	}

	for _, et := range cases {
		t.Run(string(et), func(t *testing.T) {
			endpoint, reqs := startCaptureServer(t, http.StatusOK)
			em := newWireTestEmitter(t, endpoint)
			t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

			evt := makeEvent(t, et, model.SeverityLow)
			require.NoError(t, em.Emit(context.Background(), evt))

			require.Len(t, *reqs, 1)
			payload := decodeOTLPPayload(t, (*reqs)[0].Body)
			require.Len(t, payload.ResourceLogs, 1)
			require.Len(t, payload.ResourceLogs[0].ScopeLogs, 1)
			require.Len(t, payload.ResourceLogs[0].ScopeLogs[0].LogRecords, 1)

			attrs := attrMap(payload.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Attributes)
			assert.Equal(t, string(et), attrs["event_type"])
		})
	}
}

// ---------------------------------------------------------------------------
// 3. Severity mapping
// ---------------------------------------------------------------------------

func TestOTLP_WireShape_SeverityMapping(t *testing.T) {
	cases := []struct {
		sev   model.Severity
		label string
		num   int
	}{
		{model.SeverityLow, "low", 5},
		{model.SeverityMedium, "medium", 9},
		{model.SeverityHigh, "high", 13},
		{model.SeverityCritical, "critical", 17},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			endpoint, reqs := startCaptureServer(t, http.StatusOK)
			em := newWireTestEmitter(t, endpoint)
			t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

			evt := makeEvent(t, model.EventAssetDiscovered, tc.sev)
			require.NoError(t, em.Emit(context.Background(), evt))

			require.Len(t, *reqs, 1)
			payload := decodeOTLPPayload(t, (*reqs)[0].Body)
			rec := payload.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
			assert.Equal(t, tc.num, rec.SeverityNumber)
			assert.Equal(t, tc.label, rec.SeverityText)
		})
	}
}

// ---------------------------------------------------------------------------
// 4. Optional attributes appear when populated
// ---------------------------------------------------------------------------

func TestOTLP_WireShape_OptionalAttributesIncludedWhenSet(t *testing.T) {
	endpoint, reqs := startCaptureServer(t, http.StatusOK)
	em := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	evt := makeEvent(t, model.EventAssetDiscovered, model.SeverityHigh)
	evt.Hostname = "host-01.corp.local"
	evt.AssetType = model.AssetTypeServer
	evt.OSFamily = "linux"
	evt.Environment = "production"
	evt.Owner = "platform-team"
	evt.Criticality = "tier-1"
	evt.DiscoverySource = "agent"
	evt.IsAuthorized = model.AuthorizationAuthorized
	evt.IsManaged = model.ManagedManaged

	require.NoError(t, em.Emit(context.Background(), evt))

	require.Len(t, *reqs, 1)
	payload := decodeOTLPPayload(t, (*reqs)[0].Body)
	attrs := attrMap(payload.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Attributes)

	assert.Equal(t, "host-01.corp.local", attrs["hostname"])
	assert.Equal(t, string(model.AssetTypeServer), attrs["asset_type"])
	assert.Equal(t, "linux", attrs["os_family"])
	assert.Equal(t, "production", attrs["environment"])
	assert.Equal(t, "platform-team", attrs["owner"])
	assert.Equal(t, "tier-1", attrs["criticality"])
	assert.Equal(t, "agent", attrs["discovery_source"])
	assert.Equal(t, string(model.AuthorizationAuthorized), attrs["is_authorized"])
	assert.Equal(t, string(model.ManagedManaged), attrs["is_managed"])
}

// ---------------------------------------------------------------------------
// 5. Optional attributes omitted when blank
// ---------------------------------------------------------------------------

func TestOTLP_WireShape_OptionalAttributesOmittedWhenEmpty(t *testing.T) {
	endpoint, reqs := startCaptureServer(t, http.StatusOK)
	em := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	evt := makeEvent(t, model.EventAssetDiscovered, model.SeverityLow)
	require.NoError(t, em.Emit(context.Background(), evt))

	require.Len(t, *reqs, 1)
	payload := decodeOTLPPayload(t, (*reqs)[0].Body)
	attrs := attrMap(payload.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Attributes)

	optional := []string{
		"hostname",
		"asset_type",
		"os_family",
		"os_version",
		"kernel_version",
		"architecture",
		"environment",
		"owner",
		"criticality",
		"discovery_source",
		"is_authorized",
		"is_managed",
	}
	for _, key := range optional {
		_, present := attrs[key]
		assert.Falsef(t, present, "attribute %q must be omitted when empty", key)
	}
}

// ---------------------------------------------------------------------------
// 6. Batch shares trace id, distinct span ids
// ---------------------------------------------------------------------------

func TestOTLP_WireShape_BatchSharesTraceIDAndDistinctSpanIDs(t *testing.T) {
	endpoint, reqs := startCaptureServer(t, http.StatusOK)
	em := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	scanRun := uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-0123456789ab")
	events := make([]model.AssetEvent, 3)
	for i := range events {
		events[i] = model.AssetEvent{
			ID:        uuid.Must(uuid.NewV7()),
			AssetID:   uuid.Must(uuid.NewV7()),
			ScanRunID: scanRun,
			Timestamp: time.Unix(1_700_000_000, int64(i)),
			EventType: model.EventAssetDiscovered,
			Severity:  model.SeverityLow,
			Details:   `{}`,
		}
	}

	require.NoError(t, em.EmitBatch(context.Background(), events))

	require.Len(t, *reqs, 1)
	payload := decodeOTLPPayload(t, (*reqs)[0].Body)
	require.Len(t, payload.ResourceLogs, 1)
	require.Len(t, payload.ResourceLogs[0].ScopeLogs, 1)
	recs := payload.ResourceLogs[0].ScopeLogs[0].LogRecords
	require.Len(t, recs, 3)

	expectedTrace := hex.EncodeToString(scanRun[:])
	spanSeen := make(map[string]struct{}, 3)
	for i, rec := range recs {
		assert.Equalf(t, expectedTrace, rec.TraceID, "record %d traceId mismatch", i)
		assert.Lenf(t, rec.SpanID, 16, "record %d spanId length", i)
		spanSeen[rec.SpanID] = struct{}{}
	}
	assert.Len(t, spanSeen, 3, "all three spanIds must be distinct")
}

// ---------------------------------------------------------------------------
// 7. Caller-provided trace/span ids override derived values
// ---------------------------------------------------------------------------

func TestOTLP_WireShape_CallerProvidedTraceIDOverride(t *testing.T) {
	endpoint, reqs := startCaptureServer(t, http.StatusOK)
	em := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	const callerTrace = "deadbeefdeadbeefdeadbeefdeadbeef"
	const callerSpan = "cafebabecafebabe"

	evt := makeEvent(t, model.EventAssetDiscovered, model.SeverityHigh)
	evt.TraceID = callerTrace
	evt.SpanID = callerSpan

	require.NoError(t, em.Emit(context.Background(), evt))

	require.Len(t, *reqs, 1)
	payload := decodeOTLPPayload(t, (*reqs)[0].Body)
	rec := payload.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	assert.Equal(t, callerTrace, rec.TraceID)
	assert.Equal(t, callerSpan, rec.SpanID)
	assert.NotEqual(t, hex.EncodeToString(evt.ScanRunID[:]), rec.TraceID,
		"caller-provided trace id must not equal the derived value")
	assert.NotEqual(t, hex.EncodeToString(evt.ID[:8]), rec.SpanID,
		"caller-provided span id must not equal the derived value")
}

// ---------------------------------------------------------------------------
// 8. Retry on 5xx, then succeed
// ---------------------------------------------------------------------------

func TestOTLP_RetryOn5xx_EventualSuccess(t *testing.T) {
	endpoint, reqs := startSequenceServer(t, []int{
		http.StatusServiceUnavailable,
		http.StatusServiceUnavailable,
		http.StatusOK,
	})
	em := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	evt := makeEvent(t, model.EventAssetDiscovered, model.SeverityMedium)
	require.NoError(t, em.Emit(context.Background(), evt))

	assert.Len(t, *reqs, 3, "emitter should retry twice before the 200")
}

// ---------------------------------------------------------------------------
// 9. Do not retry on 4xx
// ---------------------------------------------------------------------------

func TestOTLP_NoRetryOn4xx(t *testing.T) {
	endpoint, reqs := startCaptureServer(t, http.StatusBadRequest)
	em := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	evt := makeEvent(t, model.EventAssetDiscovered, model.SeverityMedium)
	err := em.Emit(context.Background(), evt)
	require.Error(t, err)
	assert.Len(t, *reqs, 1, "4xx must not be retried")
}

// ---------------------------------------------------------------------------
// 10. Trace/span ids omitted when ids are nil
// ---------------------------------------------------------------------------

func TestOTLP_OmitsOptionalTraceIDWhenScanRunIDIsNil(t *testing.T) {
	endpoint, reqs := startCaptureServer(t, http.StatusOK)
	em := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	evt := model.AssetEvent{
		// Both ID and ScanRunID intentionally left as uuid.Nil.
		AssetID:   uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-aaaabbbbcccc"),
		Timestamp: time.Unix(1_700_000_000, 0),
		EventType: model.EventAssetDiscovered,
		Severity:  model.SeverityLow,
		Details:   `{}`,
	}
	require.NoError(t, em.Emit(context.Background(), evt))

	require.Len(t, *reqs, 1)

	// Decode into a generic map to detect key absence (omitempty).
	var generic struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []map[string]any `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	require.NoError(t, json.Unmarshal((*reqs)[0].Body, &generic))
	require.Len(t, generic.ResourceLogs, 1)
	require.Len(t, generic.ResourceLogs[0].ScopeLogs, 1)
	require.Len(t, generic.ResourceLogs[0].ScopeLogs[0].LogRecords, 1)

	rec := generic.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	_, hasTrace := rec["traceId"]
	_, hasSpan := rec["spanId"]
	assert.False(t, hasTrace, "traceId must be omitted when ScanRunID is nil")
	assert.False(t, hasSpan, "spanId must be omitted when event ID is nil")
}
