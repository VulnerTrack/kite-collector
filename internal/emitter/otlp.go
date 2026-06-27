package emitter

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/telemetry/redact"
)

// Compile-time interface check.
var _ Emitter = (*OTLPEmitter)(nil)

// OTLPConfig holds the configuration for connecting to an OTLP-compatible
// log collector endpoint.
type OTLPConfig struct {
	// Resource carries the OTel resource attributes attached to every
	// exported batch. When empty the emitter falls back to a minimal set
	// containing only service.name and service.version (legacy v0
	// behaviour, kept for unit tests). Production callers should build
	// this via internal/telemetry/resource.Build to satisfy the RFC-0115
	// contract.
	Resource map[string]string
	Endpoint string
	Protocol string // "grpc" or "http"
	TLS      TLSConfig
}

// TLSConfig specifies optional mutual-TLS parameters.
type TLSConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
	Enabled  bool
}

// retryConfig controls exponential-backoff behaviour.
type retryConfig struct {
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
}

// OTLPEmitter sends AssetEvent records as OTLP log entries over HTTP/JSON
// to an OpenTelemetry Collector's /v1/logs endpoint.
//
// Only the HTTP+JSON transport is implemented because it avoids heavy
// gRPC/protobuf dependencies and works with CGO_ENABLED=0 builds. When
// Protocol is set to "grpc" the emitter falls back to HTTP+JSON on the
// same endpoint, logging a warning at construction time so operators can
// adjust the collector configuration accordingly.
type OTLPEmitter struct {
	client         *http.Client
	resource       map[string]string // RFC-0115 §4.2 resource attributes
	endpoint       string            // full URL including /v1/logs
	serviceName    string
	serviceVersion string
	retry          retryConfig

	mu     sync.Mutex // guards closed
	closed bool
}

// NewOTLP creates an OTLPEmitter that pushes log records to the given OTLP
// endpoint. serviceVersion is embedded as the service.version resource
// attribute on every exported log record.
func NewOTLP(cfg OTLPConfig, serviceVersion string) (*OTLPEmitter, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("otlp: endpoint must not be empty")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()

	if cfg.TLS.Enabled {
		tlsCfg, err := buildTLSConfig(cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("otlp: tls setup: %w", err)
		}
		transport.TLSClientConfig = tlsCfg
	}

	endpoint, err := normalizeOTLPEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}

	return &OTLPEmitter{
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		endpoint:       endpoint,
		serviceName:    "kite-collector",
		serviceVersion: serviceVersion,
		resource:       cfg.Resource,
		retry: retryConfig{
			maxAttempts: 3,
			baseDelay:   1 * time.Second,
			maxDelay:    30 * time.Second,
		},
	}, nil
}

// normalizeOTLPEndpoint validates and normalizes the operator-supplied OTLP
// endpoint. It accepts:
//   - host-only strings ("otel.example.com") — defaults the scheme to https.
//   - full URLs with scheme http/https.
//
// It rejects empty endpoints, unsupported schemes (anything other than http
// or https), URLs with no host, and unparseable inputs. The returned URL
// always has its path replaced with /v1/logs (existing paths are dropped to
// avoid producing /custom/v1/logs when the operator already supplied one).
func normalizeOTLPEndpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("otlp: invalid endpoint %q: %w", raw, err)
	}

	// url.Parse treats a scheme-less host like "otel.example.com" as a
	// relative path with the host living in u.Path. Detect that case and
	// re-parse with an explicit https:// prefix.
	if u.Scheme == "" && u.Host == "" {
		normalized := "https://" + raw
		reparsed, perr := url.Parse(normalized)
		if perr != nil {
			return "", fmt.Errorf("otlp: invalid endpoint %q: %w", raw, perr)
		}
		slog.Warn(
			"otlp: endpoint missing scheme; defaulting to https",
			"endpoint", raw,
			"normalized", normalized,
		)
		u = reparsed
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf(
			"otlp: unsupported endpoint scheme %q (want http or https)", u.Scheme,
		)
	}

	if u.Host == "" {
		return "", fmt.Errorf("otlp: endpoint %q has no host", raw)
	}

	u.Path = "/v1/logs"
	return u.String(), nil
}

// Emit sends a single event as an OTLP log record.
func (o *OTLPEmitter) Emit(ctx context.Context, event model.AssetEvent) error {
	return o.EmitBatch(ctx, []model.AssetEvent{event})
}

// EmitBatch sends multiple events in a single OTLP /v1/logs request.
func (o *OTLPEmitter) EmitBatch(ctx context.Context, events []model.AssetEvent) error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return fmt.Errorf("otlp: emitter is shut down")
	}
	o.mu.Unlock()

	if len(events) == 0 {
		return nil
	}

	payload := o.buildPayload(events)

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("otlp: marshal payload: %w", err)
	}

	return o.sendWithRetry(ctx, body)
}

// Shutdown marks the emitter as closed and releases the underlying HTTP
// transport. Any in-flight Emit calls that started before Shutdown will
// be allowed to complete; subsequent calls return an error.
func (o *OTLPEmitter) Shutdown(_ context.Context) error {
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
// OTLP JSON payload types
// ---------------------------------------------------------------------------

// The structs below mirror the OTLP JSON log format defined in
// https://opentelemetry.io/docs/specs/otlp/#otlphttp-request

type otlpLogsPayload struct {
	ResourceLogs []otlpResourceLog `json:"resourceLogs"`
}

type otlpResourceLog struct {
	Resource  otlpResource   `json:"resource"`
	ScopeLogs []otlpScopeLog `json:"scopeLogs"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpScopeLog struct {
	Scope      otlpScope       `json:"scope"`
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type otlpLogRecord struct {
	Body                 otlpAnyValue   `json:"body"`
	TimeUnixNano         string         `json:"timeUnixNano"`
	SeverityText         string         `json:"severityText"`
	EventName            string         `json:"eventName,omitempty"`
	ObservedTimeUnixNano string         `json:"observedTimeUnixNano"`
	TraceID              string         `json:"traceId,omitempty"`
	SpanID               string         `json:"spanId,omitempty"`
	Attributes           []otlpKeyValue `json:"attributes"`
	SeverityNumber       int            `json:"severityNumber"`
}

type otlpAnyValue struct {
	StringValue *string `json:"stringValue,omitempty"`
}

type otlpKeyValue struct {
	Value otlpAnyValue `json:"value"`
	Key   string       `json:"key"`
}

// ---------------------------------------------------------------------------
// Payload construction
// ---------------------------------------------------------------------------

func (o *OTLPEmitter) buildPayload(events []model.AssetEvent) otlpLogsPayload {
	records := make([]otlpLogRecord, 0, len(events))
	now := strconv.FormatInt(time.Now().UnixNano(), 10)

	for i := range events {
		records = append(records, o.eventToLogRecord(&events[i], now))
	}

	return otlpLogsPayload{
		ResourceLogs: []otlpResourceLog{
			{
				Resource: otlpResource{Attributes: o.resourceAttributes()},
				ScopeLogs: []otlpScopeLog{
					{
						Scope:      otlpScope{Name: "kite-collector.emitter"},
						LogRecords: records,
					},
				},
			},
		},
	}
}

// resourceAttributes returns the resource attribute key/value list per the
// RFC-0115 contract. When the emitter was constructed with a populated
// Resource map (the production path) it is used verbatim; otherwise we fall
// back to the legacy two-attribute set (service.name, service.version)
// that historic unit tests still assert against.
//
// Forbidden keys are stripped via redact.Filter so callers cannot smuggle
// credentials into the resource by mistake.
func (o *OTLPEmitter) resourceAttributes() []otlpKeyValue {
	if len(o.resource) > 0 {
		clean := redact.Filter(o.resource)
		out := make([]otlpKeyValue, 0, len(clean))
		for k, v := range clean {
			out = append(out, stringKV(k, v))
		}
		return out
	}
	return []otlpKeyValue{
		stringKV("service.name", o.serviceName),
		stringKV("service.version", o.serviceVersion),
	}
}

func (o *OTLPEmitter) eventToLogRecord(e *model.AssetEvent, observedNano string) otlpLogRecord {
	traceID := e.TraceID
	if traceID == "" {
		traceID = deriveTraceID(e)
	}
	spanID := e.SpanID
	if spanID == "" {
		spanID = deriveSpanID(e)
	}
	return otlpLogRecord{
		TimeUnixNano:         strconv.FormatInt(e.Timestamp.UnixNano(), 10),
		ObservedTimeUnixNano: observedNano,
		SeverityNumber:       severityToNumber(e.Severity),
		SeverityText:         string(e.Severity),
		EventName:            e.EventType.Name(),
		Body:                 stringVal(e.Details),
		TraceID:              traceID,
		SpanID:               spanID,
		Attributes:           buildAttributes(e),
	}
}

// deriveTraceID produces a deterministic OTLP traceId from the event's
// ScanRunID. UUIDv7 is 16 bytes which encodes to exactly 32 hex chars,
// matching the OTLP traceId spec. All events from the same scan share
// the same traceId, enabling backend correlation. Returns "" when the
// scan_run_id is unset so the omitempty JSON tag suppresses the field.
func deriveTraceID(e *model.AssetEvent) string {
	if e.ScanRunID == uuid.Nil {
		return ""
	}
	return hex.EncodeToString(e.ScanRunID[:])
}

// deriveSpanID produces a deterministic OTLP spanId from the event's ID.
// The first 8 bytes of a UUIDv7 encode to exactly 16 hex chars, matching
// the OTLP spanId spec. Each event gets a unique spanId. Deterministic +
// idempotent: replaying the same scan reproduces identical span IDs.
// Returns "" when the event id is unset.
func deriveSpanID(e *model.AssetEvent) string {
	if e.ID == uuid.Nil {
		return ""
	}
	return hex.EncodeToString(e.ID[:8])
}

// buildAttributes constructs the OTLP log record attribute list from an event.
// Optional asset fields are only included when non-empty so that minimal
// events (e.g. those not created via FromAsset) remain compact.
//
// All keys pass through redact.IsForbidden before being emitted so the
// RFC-0115 §4.3 forbidden-key denylist is enforced at the last layer
// before serialization. The keys produced here are all hard-coded constants
// that the contract permits, so the filter is a defence-in-depth check
// against future drift rather than a hot-path cost.
func buildAttributes(e *model.AssetEvent) []otlpKeyValue {
	pairs := [][2]string{
		{"event_type", string(e.EventType)},
		{"event_name", e.EventType.Name()},
		{"asset_id", e.AssetID.String()},
		{"scan_run_id", e.ScanRunID.String()},
		{"severity", string(e.Severity)},
	}
	add := func(key, value string) {
		if value == "" {
			return
		}
		pairs = append(pairs, [2]string{key, value})
	}
	add("hostname", e.Hostname)
	add("asset_type", string(e.AssetType))
	add("os_family", e.OSFamily)
	add("os_version", e.OSVersion)
	add("kernel_version", e.KernelVersion)
	add("architecture", e.Architecture)
	add("environment", e.Environment)
	add("owner", e.Owner)
	add("criticality", e.Criticality)
	add("discovery_source", e.DiscoverySource)
	add("is_authorized", string(e.IsAuthorized))
	add("is_managed", string(e.IsManaged))

	attrs := make([]otlpKeyValue, 0, len(pairs))
	for _, p := range pairs {
		if redact.IsForbidden(p[0]) {
			continue
		}
		attrs = append(attrs, stringKV(p[0], p[1]))
	}
	return attrs
}

// ---------------------------------------------------------------------------
// Retry logic
// ---------------------------------------------------------------------------

func (o *OTLPEmitter) sendWithRetry(ctx context.Context, body []byte) error {
	var lastErr error

	for attempt := 0; attempt < o.retry.maxAttempts; attempt++ {
		if attempt > 0 {
			delay := backoffDelay(attempt, o.retry.baseDelay, o.retry.maxDelay)
			select {
			case <-ctx.Done():
				return fmt.Errorf("otlp: context cancelled during retry backoff: %w", ctx.Err())
			case <-time.After(delay):
			}
		}

		lastErr = o.doSend(ctx, body)
		if lastErr == nil {
			return nil
		}

		// Only retry on transient (5xx / connection) errors.
		if !isTransient(lastErr) {
			return lastErr
		}
	}

	return fmt.Errorf("otlp: exhausted %d retry attempts: %w", o.retry.maxAttempts, lastErr)
}

func (o *OTLPEmitter) doSend(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("otlp: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		// URL-shape errors (e.g. "unsupported protocol scheme") are
		// terminal: no amount of retrying will make a malformed URL
		// valid. Return the bare error so the retry loop exits
		// immediately. Connection errors remain transient.
		var urlErr *url.Error
		if errors.As(err, &urlErr) &&
			strings.Contains(urlErr.Err.Error(), "unsupported protocol scheme") {
			return fmt.Errorf("otlp: send request: %w", err)
		}
		return &transientError{err: fmt.Errorf("otlp: send request: %w", err)}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	err = fmt.Errorf("otlp: server returned %d: %s", resp.StatusCode, string(respBody))

	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return &transientError{err: err}
	}
	return err
}

// transientError wraps errors that are safe to retry.
type transientError struct {
	err error
}

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }

func isTransient(err error) bool {
	te := (*transientError)(nil)
	ok := false
	for e := err; e != nil; {
		if t, is := e.(*transientError); is {
			te = t
			ok = true
			break
		}
		u, canUnwrap := e.(interface{ Unwrap() error })
		if !canUnwrap {
			break
		}
		e = u.Unwrap()
	}
	_ = te
	return ok
}

// backoffDelay computes an exponential backoff with a cap.
func backoffDelay(attempt int, base, max time.Duration) time.Duration {
	delay := time.Duration(float64(base) * math.Pow(2, float64(attempt-1)))
	if delay > max {
		delay = max
	}
	return delay
}

// ---------------------------------------------------------------------------
// TLS helpers
// ---------------------------------------------------------------------------

// buildTLSConfig constructs a *tls.Config for the OTLP emitter.
//
// Verification strategy — strictest check that succeeds:
//  1. Full standard TLS: system roots + private CA, hostname match.
//     Passes for public certs (Cloudflare, Let's Encrypt).
//  2. CA-chain only: system roots + private CA, no hostname check.
//     Fallback for private PKI certs issued for internal names (e.g. "otelcol").
//  3. Reject — neither check passed.
func buildTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	// Build trusted pool: system roots extended with our private CA.
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		caPEM, readErr := os.ReadFile(cfg.CAFile)
		if readErr != nil {
			return nil, fmt.Errorf("read CA file %q: %w", cfg.CAFile, readErr)
		}
		pool.AppendCertsFromPEM(caPEM)
	}

	tlsCfg := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("server presented no certificate")
			}
			intermediates := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			// Pass 1: full verification — hostname + CA chain (public certs).
			if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				DNSName:       cs.ServerName,
				Roots:         pool,
				Intermediates: intermediates,
			}); err == nil {
				return nil
			}
			// Pass 2: CA-chain only — private PKI cert issued for internal name.
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots:         pool,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			if err != nil {
				return fmt.Errorf("verify peer certificate: %w", err)
			}
			return nil
		},
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// ---------------------------------------------------------------------------
// OTLP value helpers
// ---------------------------------------------------------------------------

func stringVal(s string) otlpAnyValue {
	return otlpAnyValue{StringValue: &s}
}

func stringKV(key, value string) otlpKeyValue {
	return otlpKeyValue{Key: key, Value: stringVal(value)}
}

// severityToNumber maps model.Severity to the OTLP severity number range.
// See https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber
func severityToNumber(s model.Severity) int {
	switch s {
	case model.SeverityLow:
		return 5 // DEBUG2 — informational low-priority finding
	case model.SeverityMedium:
		return 9 // INFO
	case model.SeverityHigh:
		return 13 // WARN
	case model.SeverityCritical:
		return 17 // ERROR
	default:
		return 0 // UNSPECIFIED
	}
}
