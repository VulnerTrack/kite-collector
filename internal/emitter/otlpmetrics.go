package emitter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vulnertrack/kite-collector/internal/telemetry/hostmetrics"
	"github.com/vulnertrack/kite-collector/internal/telemetry/redact"
)

// MetricsScopeName is the OTLP instrumentation-scope name carried on every
// host-metrics batch. It is the third sibling of the two log scopes the
// Python ingest side already watermarks
// ("kite-collector.emitter", "kite-collector.aggregate"), and the value the
// fetch step filters on.
const MetricsScopeName = "kite-collector.host_metrics"

// otlpMetricsPath is the OTLP/HTTP metrics endpoint, symmetric with the
// logs emitter's hard-coded /v1/logs. Both terminate on the same
// mTLS-authenticated collector receiver; no new ingress path is introduced
// (RFC-0157 R2).
const otlpMetricsPath = "/v1/metrics"

// aggregationTemporalityCumulative is OTLP's
// AGGREGATION_TEMPORALITY_CUMULATIVE. Every sum instrument here reports a
// counter read straight off the kernel (bytes/errors since boot), which is
// cumulative by construction.
const aggregationTemporalityCumulative = 2

// OTLPMetricsEmitter sends host-metric samples as an OTLP metrics signal
// over HTTP/JSON to a collector's /v1/metrics endpoint.
//
// It is a deliberate sibling of OTLPEmitter rather than an extension of it:
// the two signals carry different payload shapes and different scopes, but
// share this package's TLS construction (buildTLSConfig), retry policy
// (retryConfig, backoffDelay, transientError), and the RFC-0115 resource
// attribute set. Hand-rolled JSON keeps the CGO_ENABLED=0 build constraint
// documented on OTLPEmitter intact — see RFC-0157 §9 Alternative 2 for why
// the OTel SDK MeterProvider was rejected for this signal.
type OTLPMetricsEmitter struct {
	client   *http.Client
	resource map[string]string
	endpoint string
	retry    retryConfig

	mu     sync.Mutex // guards closed
	closed bool
}

// NewOTLPMetrics creates an emitter that pushes host metrics to the metrics
// path of the same OTLP endpoint the logs emitter uses. cfg is the exact
// same OTLPConfig value — same endpoint, same client certificate, same CA.
func NewOTLPMetrics(cfg OTLPConfig) (*OTLPMetricsEmitter, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("otlp metrics: endpoint must not be empty")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()

	if cfg.TLS.Enabled {
		tlsCfg, err := buildTLSConfig(cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("otlp metrics: tls setup: %w", err)
		}
		transport.TLSClientConfig = tlsCfg
	}

	endpoint, err := metricsEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}

	return &OTLPMetricsEmitter{
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		endpoint: endpoint,
		resource: cfg.Resource,
		retry: retryConfig{
			maxAttempts: 3,
			baseDelay:   1 * time.Second,
			maxDelay:    30 * time.Second,
		},
	}, nil
}

// metricsEndpoint reuses the logs emitter's endpoint validation verbatim
// (scheme defaulting, unsupported-scheme rejection, missing-host rejection)
// and then swaps the path. Duplicating the validation instead would let the
// two signals drift apart on exactly the inputs operators get wrong.
func metricsEndpoint(raw string) (string, error) {
	normalized, err := normalizeOTLPEndpoint(raw)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return "", fmt.Errorf("otlp metrics: invalid endpoint %q: %w", raw, err)
	}
	u.Path = otlpMetricsPath
	return u.String(), nil
}

// EmitBatch sends every sample in one OTLP /v1/metrics request, stamped
// with the current time. An empty batch is a no-op, and a shut-down emitter
// reports an error rather than silently dropping.
func (o *OTLPMetricsEmitter) EmitBatch(ctx context.Context, samples []hostmetrics.Sample) error {
	return o.emit(ctx, samples, time.Now().UTC())
}

// EmitSnapshot is the form the agent's streaming loop calls. The snapshot's
// collection timestamp becomes every data point's timeUnixNano, so all
// samples from one tick land on one instant — which is what makes the
// hourly rollup's sample_count a meaningful data-quality signal.
func (o *OTLPMetricsEmitter) EmitSnapshot(ctx context.Context, snap hostmetrics.Snapshot) error {
	at := snap.CollectedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	return o.emit(ctx, snap.Samples, at)
}

func (o *OTLPMetricsEmitter) emit(
	ctx context.Context,
	samples []hostmetrics.Sample,
	at time.Time,
) error {
	o.mu.Lock()
	closed := o.closed
	o.mu.Unlock()

	if closed {
		return fmt.Errorf("otlp metrics: emitter is shut down")
	}
	if len(samples) == 0 {
		return nil
	}

	body, err := json.Marshal(o.buildMetricsPayload(samples, at))
	if err != nil {
		return fmt.Errorf("otlp metrics: marshal payload: %w", err)
	}
	return o.sendWithRetry(ctx, body)
}

// Shutdown marks the emitter closed and releases idle connections.
func (o *OTLPMetricsEmitter) Shutdown(_ context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.closed {
		return nil
	}
	o.closed = true
	o.client.CloseIdleConnections()
	return nil
}

// ---------------------------------------------------------------------------
// OTLP JSON metrics payload types
// ---------------------------------------------------------------------------

// These mirror the OTLP JSON metrics format defined in
// https://opentelemetry.io/docs/specs/otlp/#otlphttp-request — the same
// hand-rolled approach the log payload structs above already take.

type otlpMetricsPayload struct {
	ResourceMetrics []otlpResourceMetric `json:"resourceMetrics"`
}

type otlpResourceMetric struct {
	Resource     otlpResource      `json:"resource"`
	ScopeMetrics []otlpScopeMetric `json:"scopeMetrics"`
}

type otlpScopeMetric struct {
	Scope   otlpScope    `json:"scope"`
	Metrics []otlpMetric `json:"metrics"`
}

type otlpMetric struct {
	Gauge       *otlpGauge `json:"gauge,omitempty"`
	Sum         *otlpSum   `json:"sum,omitempty"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Unit        string     `json:"unit,omitempty"`
}

type otlpGauge struct {
	DataPoints []otlpNumberDataPoint `json:"dataPoints"`
}

type otlpSum struct {
	DataPoints             []otlpNumberDataPoint `json:"dataPoints"`
	AggregationTemporality int                   `json:"aggregationTemporality"`
	IsMonotonic            bool                  `json:"isMonotonic"`
}

type otlpNumberDataPoint struct {
	StartTimeUnixNano string         `json:"startTimeUnixNano"`
	TimeUnixNano      string         `json:"timeUnixNano"`
	Attributes        []otlpKeyValue `json:"attributes"`
	AsDouble          float64        `json:"asDouble"`
}

// ---------------------------------------------------------------------------
// Payload construction
// ---------------------------------------------------------------------------

// metricKey groups data points that belong to the same OTLP instrument.
// Two samples share an instrument only when name, unit, kind, and
// monotonicity all match — mixing them would produce a metric the collector
// cannot type.
type metricKey struct {
	name      string
	unit      string
	kind      hostmetrics.Kind
	monotonic bool
}

func (o *OTLPMetricsEmitter) buildMetricsPayload(
	samples []hostmetrics.Sample,
	at time.Time,
) otlpMetricsPayload {
	nano := strconv.FormatInt(at.UnixNano(), 10)

	order := make([]metricKey, 0, len(samples))
	points := make(map[metricKey][]otlpNumberDataPoint, len(samples))

	for i := range samples {
		s := samples[i]
		key := metricKey{
			name:      s.Name,
			unit:      s.Unit,
			kind:      s.Kind,
			monotonic: s.Monotonic,
		}
		if _, seen := points[key]; !seen {
			order = append(order, key)
		}
		points[key] = append(points[key], otlpNumberDataPoint{
			StartTimeUnixNano: nano,
			TimeUnixNano:      nano,
			AsDouble:          s.Value,
			Attributes:        dataPointAttributes(s.Attributes),
		})
	}

	metrics := make([]otlpMetric, 0, len(order))
	for _, key := range order {
		metric := otlpMetric{
			Name:        key.name,
			Unit:        key.unit,
			Description: instrumentDescription(key.name),
		}
		if key.kind == hostmetrics.KindSum {
			metric.Sum = &otlpSum{
				DataPoints:             points[key],
				AggregationTemporality: aggregationTemporalityCumulative,
				IsMonotonic:            key.monotonic,
			}
		} else {
			metric.Gauge = &otlpGauge{DataPoints: points[key]}
		}
		metrics = append(metrics, metric)
	}

	return otlpMetricsPayload{
		ResourceMetrics: []otlpResourceMetric{
			{
				Resource: otlpResource{Attributes: o.resourceAttributes()},
				ScopeMetrics: []otlpScopeMetric{
					{
						Scope:   otlpScope{Name: MetricsScopeName},
						Metrics: metrics,
					},
				},
			},
		},
	}
}

// resourceAttributes reuses the RFC-0115 resource set built for the logs
// signal, filtered through the same forbidden-key denylist. Falling back to
// an empty list rather than the logs emitter's service.name/service.version
// pair would leave the collector unable to attribute the batch, so the
// minimal identity pair is reproduced here.
func (o *OTLPMetricsEmitter) resourceAttributes() []otlpKeyValue {
	if len(o.resource) > 0 {
		clean := redact.Filter(o.resource)
		keys := make([]string, 0, len(clean))
		for k := range clean {
			keys = append(keys, k)
		}
		// Map iteration order is randomised; sorting keeps the emitted
		// payload byte-stable, which is what makes the wire tests
		// meaningful and collector-side diffs readable.
		sort.Strings(keys)
		out := make([]otlpKeyValue, 0, len(keys))
		for _, k := range keys {
			out = append(out, stringKV(k, clean[k]))
		}
		return out
	}
	return []otlpKeyValue{
		stringKV("service.name", "kite-collector"),
		stringKV("service.namespace", "vulnertrack"),
	}
}

// dataPointAttributes renders a sample's attribute map, dropping any key
// the RFC-0115 denylist forbids. hostmetrics already caps values to a fixed
// device/direction/state vocabulary (R5); this filter is the same
// defence-in-depth pass buildAttributes runs for logs.
func dataPointAttributes(attrs map[string]string) []otlpKeyValue {
	if len(attrs) == 0 {
		return []otlpKeyValue{}
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		if redact.IsForbidden(k) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]otlpKeyValue, 0, len(keys))
	for _, k := range keys {
		out = append(out, stringKV(k, attrs[k]))
	}
	return out
}

// instrumentDescriptions is the human-readable half of the instrument
// catalog. It is intentionally kept next to the wire format rather than in
// hostmetrics: the collector stores it on every row of otel_metrics_*, so
// it is a wire concern.
var instrumentDescriptions = map[string]string{
	hostmetrics.MetricCPUUtilization:    "Fraction of CPU time spent in a non-idle state.",
	hostmetrics.MetricMemoryUsage:       "Physical memory in use, in bytes.",
	hostmetrics.MetricMemoryUtilization: "Fraction of physical memory in use.",
	hostmetrics.MetricDiskUsage:         "Filesystem space in use, in bytes.",
	hostmetrics.MetricDiskUtilization:   "Fraction of filesystem space in use.",
	hostmetrics.MetricNetworkIO:         "Cumulative bytes transferred on a network interface.",
	hostmetrics.MetricNetworkErrors:     "Cumulative network errors observed on an interface.",
	hostmetrics.MetricUptime:            "Time since the host last booted, in seconds.",
	hostmetrics.MetricLoad1:             "1-minute load average.",
	hostmetrics.MetricLoad5:             "5-minute load average.",
	hostmetrics.MetricLoad15:            "15-minute load average.",
}

func instrumentDescription(name string) string {
	return instrumentDescriptions[name]
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

// sendWithRetry mirrors OTLPEmitter.sendWithRetry: a small fixed budget,
// exponential backoff with the shared cap, retry only on transient errors,
// then give up. Host metrics are best-effort telemetry — the next tick's
// data is unaffected by this one being dropped (RFC-0157 §7.4).
func (o *OTLPMetricsEmitter) sendWithRetry(ctx context.Context, body []byte) error {
	var lastErr error

	for attempt := 0; attempt < o.retry.maxAttempts; attempt++ {
		if attempt > 0 {
			delay := backoffDelay(attempt, o.retry.baseDelay, o.retry.maxDelay)
			select {
			case <-ctx.Done():
				return fmt.Errorf(
					"otlp metrics: context cancelled during retry backoff: %w", ctx.Err(),
				)
			case <-time.After(delay):
			}
		}

		lastErr = o.doSend(ctx, body)
		if lastErr == nil {
			return nil
		}

		if !isTransient(lastErr) {
			return lastErr
		}
	}

	return fmt.Errorf(
		"otlp metrics: exhausted %d retry attempts: %w", o.retry.maxAttempts, lastErr,
	)
}

func (o *OTLPMetricsEmitter) doSend(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("otlp metrics: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		// A malformed URL is terminal; a connection error is not.
		var urlErr *url.Error
		if errors.As(err, &urlErr) &&
			strings.Contains(urlErr.Err.Error(), "unsupported protocol scheme") {
			return fmt.Errorf("otlp metrics: send request: %w", err)
		}
		return &transientError{err: fmt.Errorf("otlp metrics: send request: %w", err)}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	err = fmt.Errorf("otlp metrics: server returned %d: %s", resp.StatusCode, string(respBody))

	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return &transientError{err: err}
	}
	return err
}
