package emitter

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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
