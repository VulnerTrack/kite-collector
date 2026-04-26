package emitter

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
)

func newTestEmitter(t *testing.T) *OTLPEmitter {
	t.Helper()
	o, err := NewOTLP(OTLPConfig{Endpoint: "http://localhost:4318"}, "test")
	assert.NoError(t, err)
	return o
}

func TestEventToLogRecord_DerivesTraceIDFromScanRunID(t *testing.T) {
	o := newTestEmitter(t)
	scanRun := uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-0123456789ab")
	evtID := uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-fedcba987654")
	e := &model.AssetEvent{
		ID:        evtID,
		ScanRunID: scanRun,
		Timestamp: time.Unix(0, 0),
	}

	rec := o.eventToLogRecord(e, "0")

	expected := hex.EncodeToString(scanRun[:])
	assert.Equal(t, expected, rec.TraceID)
	assert.Len(t, rec.TraceID, 32)
}

func TestEventToLogRecord_DerivesSpanIDFromEventID(t *testing.T) {
	o := newTestEmitter(t)
	scanRun := uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-0123456789ab")
	evtID := uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-fedcba987654")
	e := &model.AssetEvent{
		ID:        evtID,
		ScanRunID: scanRun,
		Timestamp: time.Unix(0, 0),
	}

	rec := o.eventToLogRecord(e, "0")

	expected := hex.EncodeToString(evtID[:8])
	assert.Equal(t, expected, rec.SpanID)
	assert.Len(t, rec.SpanID, 16)
}

func TestEventToLogRecord_PreservesCallerProvidedTraceID(t *testing.T) {
	o := newTestEmitter(t)
	const callerTrace = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const callerSpan = "bbbbbbbbbbbbbbbb"
	e := &model.AssetEvent{
		ID:        uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-fedcba987654"),
		ScanRunID: uuid.MustParse("018f9c2a-7b3d-7a01-8c2e-0123456789ab"),
		TraceID:   callerTrace,
		SpanID:    callerSpan,
		Timestamp: time.Unix(0, 0),
	}

	rec := o.eventToLogRecord(e, "0")

	assert.Equal(t, callerTrace, rec.TraceID)
	assert.Equal(t, callerSpan, rec.SpanID)
}

func TestEventToLogRecord_EmptyWhenIDsUnset(t *testing.T) {
	o := newTestEmitter(t)
	e := &model.AssetEvent{Timestamp: time.Unix(0, 0)}

	rec := o.eventToLogRecord(e, "0")

	assert.Equal(t, "", rec.TraceID)
	assert.Equal(t, "", rec.SpanID)
}

// TestEventToLogRecord_PopulatesEventName ensures the OTLP LogRecord.eventName
// proto field carries the namespaced event name derived from EventType.Name().
// Backends that index the v1.5+ eventName field rely on this rather than the
// snake_case attribute mirror.
func TestEventToLogRecord_PopulatesEventName(t *testing.T) {
	o := newTestEmitter(t)
	e := &model.AssetEvent{
		EventType: model.EventAssetDiscovered,
		Timestamp: time.Unix(0, 0),
	}

	rec := o.eventToLogRecord(e, "0")

	assert.Equal(t, "kite.asset.discovered", rec.EventName)
}

// ---------------------------------------------------------------------------
// Endpoint URL normalization
// ---------------------------------------------------------------------------

func TestNewOTLP_RejectsEmptyEndpoint(t *testing.T) {
	_, err := NewOTLP(OTLPConfig{Endpoint: ""}, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endpoint must not be empty")
}

func TestNewOTLP_DefaultsToHTTPSWhenSchemeMissing(t *testing.T) {
	o, err := NewOTLP(OTLPConfig{Endpoint: "otel.vulnertrack.io"}, "test")
	require.NoError(t, err)
	assert.Equal(t, "https://otel.vulnertrack.io/v1/logs", o.endpoint)
}

func TestNewOTLP_RejectsUnsupportedScheme(t *testing.T) {
	_, err := NewOTLP(OTLPConfig{Endpoint: "ftp://otel.example/v1/logs"}, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported endpoint scheme")
}

func TestNewOTLP_RejectsHostOnlyWhenNoHost(t *testing.T) {
	_, err := NewOTLP(OTLPConfig{Endpoint: "https:///v1/logs"}, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has no host")
}

func TestNewOTLP_ReplacesExistingPath(t *testing.T) {
	o, err := NewOTLP(OTLPConfig{Endpoint: "https://otel.example/custom"}, "test")
	require.NoError(t, err)
	assert.Equal(t, "https://otel.example/v1/logs", o.endpoint)
	assert.False(t, strings.Contains(o.endpoint, "custom"),
		"existing path component must be replaced, not appended")
}

func TestNewOTLP_PreservesExplicitHTTPS(t *testing.T) {
	o, err := NewOTLP(OTLPConfig{Endpoint: "https://otel.example"}, "test")
	require.NoError(t, err)
	assert.Equal(t, "https://otel.example/v1/logs", o.endpoint)
}

func TestNewOTLP_PreservesExplicitHTTP(t *testing.T) {
	o, err := NewOTLP(OTLPConfig{Endpoint: "http://localhost:4318"}, "test")
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:4318/v1/logs", o.endpoint)
}

// TestNewOTLP_TrailingSlashStripped covers the original behavior
// (operator supplies "http://host:4318/") to confirm normalization
// still produces a single, well-formed /v1/logs path.
func TestNewOTLP_TrailingSlashStripped(t *testing.T) {
	o, err := NewOTLP(OTLPConfig{Endpoint: "http://localhost:4318/"}, "test")
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:4318/v1/logs", o.endpoint)
}
