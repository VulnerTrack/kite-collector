package emitter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/telemetry/hostmetrics"
)

func sampleBatch() []hostmetrics.Sample {
	return []hostmetrics.Sample{
		{
			Name:  hostmetrics.MetricCPUUtilization,
			Unit:  hostmetrics.UnitRatio,
			Kind:  hostmetrics.KindGauge,
			Value: 0.425,
		},
		{
			Name:      hostmetrics.MetricNetworkIO,
			Unit:      hostmetrics.UnitBytes,
			Kind:      hostmetrics.KindSum,
			Value:     1000,
			Monotonic: true,
			Attributes: map[string]string{
				hostmetrics.AttrDevice:    "eth0",
				hostmetrics.AttrDirection: hostmetrics.DirectionReceive,
			},
		},
		{
			Name:      hostmetrics.MetricNetworkIO,
			Unit:      hostmetrics.UnitBytes,
			Kind:      hostmetrics.KindSum,
			Value:     2000,
			Monotonic: true,
			Attributes: map[string]string{
				hostmetrics.AttrDevice:    "eth0",
				hostmetrics.AttrDirection: hostmetrics.DirectionTransmit,
			},
		},
	}
}

// captureServer returns an httptest server that records the last request
// body and path, plus a pointer to the captured values.
//
// capturedRequest itself is declared once for the whole package in
// otlp_wire_test.go — the logs emitter's wire tests got there first, and a
// second copy of the same four fields would not compile.
func captureServer(t *testing.T, status int) (*httptest.Server, *atomic.Pointer[capturedRequest]) {
	t.Helper()
	captured := &atomic.Pointer[capturedRequest]{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured.Store(&capturedRequest{
			Method:      r.Method,
			Path:        r.URL.Path,
			ContentType: r.Header.Get("Content-Type"),
			Body:        body,
		})
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, captured
}

func newMetricsEmitter(t *testing.T, endpoint string) *OTLPMetricsEmitter {
	t.Helper()
	e, err := NewOTLPMetrics(OTLPConfig{
		Endpoint: endpoint,
		Resource: map[string]string{
			"service.name": "kite-collector",
			"agent.id":     "018f9c2a-7b3d-7a01-8c2e-0123456789ab",
			"tenant.id":    "018f9c2a-7b3d-7a01-8c2e-fedcba987654",
			"host.name":    "web-03",
		},
	})
	require.NoError(t, err)
	// Keep the retry budget from turning a failure test into a slow test.
	e.retry.baseDelay = time.Millisecond
	e.retry.maxDelay = 2 * time.Millisecond
	return e
}

func TestNewOTLPMetrics_RejectsEmptyEndpoint(t *testing.T) {
	_, err := NewOTLPMetrics(OTLPConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endpoint must not be empty")
}

// TestNewOTLPMetrics_TargetsTheMetricsPath is the whole point of the second
// emitter: same host, same certificate, different OTLP path.
func TestNewOTLPMetrics_TargetsTheMetricsPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"http://localhost:4318", "http://localhost:4318/v1/metrics"},
		{"https://otel.example.com", "https://otel.example.com/v1/metrics"},
		{"otel.example.com", "https://otel.example.com/v1/metrics"},
		// An operator-supplied path is replaced, not appended to — the same
		// rule normalizeOTLPEndpoint applies for /v1/logs.
		{"https://otel.example.com/v1/logs", "https://otel.example.com/v1/metrics"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			e, err := NewOTLPMetrics(OTLPConfig{Endpoint: tc.in})
			require.NoError(t, err)
			assert.Equal(t, tc.want, e.endpoint)
		})
	}
}

func TestNewOTLPMetrics_RejectsUnsupportedScheme(t *testing.T) {
	_, err := NewOTLPMetrics(OTLPConfig{Endpoint: "ftp://otel.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported endpoint scheme")
}

// TestEmitBatch_PostsWellFormedOTLPJSON is the wire-contract test: the
// collector's OTLP/HTTP receiver has to accept this byte-for-byte, and the
// ClickHouse exporter routes gauges and sums into different tables.
func TestEmitBatch_PostsWellFormedOTLPJSON(t *testing.T) {
	srv, captured := captureServer(t, http.StatusOK)
	e := newMetricsEmitter(t, srv.URL)

	require.NoError(t, e.EmitBatch(context.Background(), sampleBatch()))

	req := captured.Load()
	require.NotNil(t, req)
	assert.Equal(t, "/v1/metrics", req.Path)
	assert.Equal(t, "application/json", req.ContentType)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(req.Body, &payload))

	resourceMetrics, ok := payload["resourceMetrics"].([]any)
	require.True(t, ok)
	require.Len(t, resourceMetrics, 1)

	rm, ok := resourceMetrics[0].(map[string]any)
	require.True(t, ok)
	scopeMetrics, ok := rm["scopeMetrics"].([]any)
	require.True(t, ok)
	require.Len(t, scopeMetrics, 1)

	sm, ok := scopeMetrics[0].(map[string]any)
	require.True(t, ok)
	scope, ok := sm["scope"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, MetricsScopeName, scope["name"])

	metrics, ok := sm["metrics"].([]any)
	require.True(t, ok)
	// Two instruments: one gauge, one sum carrying both directions.
	require.Len(t, metrics, 2)

	gauge, ok := metrics[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, hostmetrics.MetricCPUUtilization, gauge["name"])
	assert.Equal(t, hostmetrics.UnitRatio, gauge["unit"])
	assert.NotEmpty(t, gauge["description"])
	assert.NotContains(t, gauge, "sum")
	gaugeBody, ok := gauge["gauge"].(map[string]any)
	require.True(t, ok)
	gaugePoints, ok := gaugeBody["dataPoints"].([]any)
	require.True(t, ok)
	require.Len(t, gaugePoints, 1)

	sum, ok := metrics[1].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, hostmetrics.MetricNetworkIO, sum["name"])
	assert.NotContains(t, sum, "gauge")
	sumBody, ok := sum["sum"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, sumBody["isMonotonic"])
	assert.InDelta(t, float64(aggregationTemporalityCumulative),
		sumBody["aggregationTemporality"], 1e-9)
	sumPoints, ok := sumBody["dataPoints"].([]any)
	require.True(t, ok)
	assert.Len(t, sumPoints, 2, "both directions belong to one instrument")
}

// TestEmitBatch_DataPointsCarryNanosecondTimestamps pins the OTLP encoding
// of timeUnixNano as a decimal *string* — a JSON number would lose
// precision past 2^53 and the collector rejects it.
func TestEmitBatch_DataPointsCarryNanosecondTimestamps(t *testing.T) {
	srv, captured := captureServer(t, http.StatusOK)
	e := newMetricsEmitter(t, srv.URL)

	at := time.Date(2026, 8, 21, 14, 30, 0, 123456789, time.UTC)
	require.NoError(t, e.emit(context.Background(), sampleBatch(), at))

	req := captured.Load()
	require.NotNil(t, req)

	var payload otlpMetricsPayload
	require.NoError(t, json.Unmarshal(req.Body, &payload))
	require.Len(t, payload.ResourceMetrics, 1)

	want := strconv.FormatInt(at.UnixNano(), 10)
	points := payload.ResourceMetrics[0].ScopeMetrics[0].Metrics[0].Gauge.DataPoints
	require.Len(t, points, 1)
	assert.Equal(t, want, points[0].TimeUnixNano)
	assert.Equal(t, want, points[0].StartTimeUnixNano)
	assert.InDelta(t, 0.425, points[0].AsDouble, 1e-9)
}

// TestEmitSnapshot_UsesTheSnapshotCollectionTime keeps every sample from
// one tick on one instant, which is what makes the hourly rollup's
// sample_count a usable data-quality signal.
func TestEmitSnapshot_UsesTheSnapshotCollectionTime(t *testing.T) {
	srv, captured := captureServer(t, http.StatusOK)
	e := newMetricsEmitter(t, srv.URL)

	at := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)
	snap := hostmetrics.Snapshot{CollectedAt: at, Samples: sampleBatch()}
	require.NoError(t, e.EmitSnapshot(context.Background(), snap))

	var payload otlpMetricsPayload
	require.NoError(t, json.Unmarshal(captured.Load().Body, &payload))

	want := strconv.FormatInt(at.UnixNano(), 10)
	for _, m := range payload.ResourceMetrics[0].ScopeMetrics[0].Metrics {
		points := m.Gauge
		if points == nil {
			for _, p := range m.Sum.DataPoints {
				assert.Equal(t, want, p.TimeUnixNano)
			}
			continue
		}
		for _, p := range points.DataPoints {
			assert.Equal(t, want, p.TimeUnixNano)
		}
	}
}

// TestEmitBatch_CarriesTheRFC0115ResourceIdentity is R2: the metrics signal
// must reuse the same identity attributes the logs signal already carries,
// so the collector can attribute a batch to an agent and tenant.
func TestEmitBatch_CarriesTheRFC0115ResourceIdentity(t *testing.T) {
	srv, captured := captureServer(t, http.StatusOK)
	e := newMetricsEmitter(t, srv.URL)

	require.NoError(t, e.EmitBatch(context.Background(), sampleBatch()))

	var payload otlpMetricsPayload
	require.NoError(t, json.Unmarshal(captured.Load().Body, &payload))

	attrs := map[string]string{}
	for _, kv := range payload.ResourceMetrics[0].Resource.Attributes {
		require.NotNil(t, kv.Value.StringValue)
		attrs[kv.Key] = *kv.Value.StringValue
	}
	assert.Equal(t, "kite-collector", attrs["service.name"])
	assert.Equal(t, "web-03", attrs["host.name"])
	assert.Equal(t, "018f9c2a-7b3d-7a01-8c2e-0123456789ab", attrs["agent.id"])
	assert.Equal(t, "018f9c2a-7b3d-7a01-8c2e-fedcba987654", attrs["tenant.id"])
}

// TestEmitBatch_StripsForbiddenAttributeKeys is the defence-in-depth pass
// on top of hostmetrics' collection-site value cap (RFC-0157 §6.1).
func TestEmitBatch_StripsForbiddenAttributeKeys(t *testing.T) {
	srv, captured := captureServer(t, http.StatusOK)
	e, err := NewOTLPMetrics(OTLPConfig{
		Endpoint: srv.URL,
		Resource: map[string]string{
			"service.name":  "kite-collector",
			"agent.id":      "018f9c2a-7b3d-7a01-8c2e-0123456789ab",
			"user_password": "hunter2",
		},
	})
	require.NoError(t, err)

	require.NoError(t, e.EmitBatch(context.Background(), []hostmetrics.Sample{{
		Name:  hostmetrics.MetricDiskUtilization,
		Unit:  hostmetrics.UnitRatio,
		Kind:  hostmetrics.KindGauge,
		Value: 0.62,
		Attributes: map[string]string{
			hostmetrics.AttrDevice: "sda1",
			"api_key":              "leaked",
			"cmdline":              "/usr/bin/secret --token abc",
		},
	}}))

	body := string(captured.Load().Body)
	assert.NotContains(t, body, "hunter2")
	assert.NotContains(t, body, "leaked")
	assert.NotContains(t, body, "cmdline")
	assert.Contains(t, body, "sda1")
	assert.Contains(t, body, "agent.id")
}

// TestResourceAttributes_AreSortedForByteStability keeps the payload stable
// across runs despite Go's randomised map iteration.
func TestResourceAttributes_AreSortedForByteStability(t *testing.T) {
	e := newMetricsEmitter(t, "http://localhost:4318")

	first := e.resourceAttributes()
	for range 5 {
		assert.Equal(t, first, e.resourceAttributes())
	}
	for i := 1; i < len(first); i++ {
		assert.Less(t, first[i-1].Key, first[i].Key)
	}
}

func TestResourceAttributes_FallsBackWhenResourceIsEmpty(t *testing.T) {
	e, err := NewOTLPMetrics(OTLPConfig{Endpoint: "http://localhost:4318"})
	require.NoError(t, err)

	attrs := e.resourceAttributes()
	require.Len(t, attrs, 2)
	assert.Equal(t, "service.name", attrs[0].Key)
	assert.Equal(t, "service.namespace", attrs[1].Key)
}

func TestEmitBatch_EmptyBatchIsANoop(t *testing.T) {
	srv, captured := captureServer(t, http.StatusInternalServerError)
	e := newMetricsEmitter(t, srv.URL)

	require.NoError(t, e.EmitBatch(context.Background(), nil))
	assert.Nil(t, captured.Load(), "no request should have been made")
}

func TestEmitBatch_AfterShutdownReturnsAnError(t *testing.T) {
	srv, _ := captureServer(t, http.StatusOK)
	e := newMetricsEmitter(t, srv.URL)

	require.NoError(t, e.Shutdown(context.Background()))
	// Shutdown is idempotent.
	require.NoError(t, e.Shutdown(context.Background()))

	err := e.EmitBatch(context.Background(), sampleBatch())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shut down")
}

// TestEmitBatch_RetriesTransientFailuresThenSucceeds exercises the shared
// backoff: 5xx is transient, so the third attempt lands.
func TestEmitBatch_RetriesTransientFailuresThenSucceeds(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	e := newMetricsEmitter(t, srv.URL)
	require.NoError(t, e.EmitBatch(context.Background(), sampleBatch()))
	assert.Equal(t, int32(3), attempts.Load())
}

// TestEmitBatch_DoesNotRetryClientErrors: a 400 means the payload is wrong,
// and resending it unchanged cannot help.
func TestEmitBatch_DoesNotRetryClientErrors(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	e := newMetricsEmitter(t, srv.URL)
	err := e.EmitBatch(context.Background(), sampleBatch())
	require.Error(t, err)
	assert.Equal(t, int32(1), attempts.Load())
}

// TestEmitBatch_GivesUpAfterTheRetryBudget documents the best-effort
// contract: the batch is dropped and the next tick is unaffected.
func TestEmitBatch_GivesUpAfterTheRetryBudget(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	e := newMetricsEmitter(t, srv.URL)
	err := e.EmitBatch(context.Background(), sampleBatch())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted")
	assert.Equal(t, int32(3), attempts.Load())
}
