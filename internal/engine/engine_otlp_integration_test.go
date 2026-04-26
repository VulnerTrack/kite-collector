package engine

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/classifier"
	"github.com/vulnertrack/kite-collector/internal/dedup"
	"github.com/vulnertrack/kite-collector/internal/discovery"
	"github.com/vulnertrack/kite-collector/internal/emitter"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/policy"
)

// ---------------------------------------------------------------------------
// Engine -> OTLP wire integration tests.
//
// Unlike engine_test.go (which uses recordingEmitter and asserts only at the
// model level) and emitter/otlp_wire_test.go (which posts hand-built events),
// these tests exercise the full pipeline: real Engine -> real OTLPEmitter ->
// real HTTP POST -> httptest.Server capture -> JSON decode -> assert.
//
// They verify that what the engine actually produces lands on the wire with
// the expected event_type, body, severity, scan_run_id, traceId, spanId, and
// timestamps.
// ---------------------------------------------------------------------------

// captureRequest records a single inbound HTTP request.
type captureRequest struct {
	Method      string
	Path        string
	ContentType string
	Body        []byte
}

// startCaptureServer launches an httptest.Server that records every inbound
// POST and returns 200 OK. Returns the base URL plus a snapshot accessor.
func startCaptureServer(t *testing.T) (string, func() []captureRequest) {
	t.Helper()
	var (
		mu       sync.Mutex
		captured []captureRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = r.Body.Close()
		mu.Lock()
		captured = append(captured, captureRequest{
			Method:      r.Method,
			Path:        r.URL.Path,
			ContentType: r.Header.Get("Content-Type"),
			Body:        append([]byte(nil), body...),
		})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	get := func() []captureRequest {
		mu.Lock()
		defer mu.Unlock()
		out := make([]captureRequest, len(captured))
		copy(out, captured)
		return out
	}
	return srv.URL, get
}

// decodePayload parses an OTLP /v1/logs JSON body into a generic map. Used
// because the emitter's payload structs are unexported and not reachable
// from this package.
func decodePayload(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var out map[string]any
	require.NoError(t, json.Unmarshal(body, &out))
	return out
}

// logRecords navigates the OTLP envelope and returns the flat list of log
// records found in the first resource/scope pair. Fails the test if the
// shape doesn't match.
func logRecords(t *testing.T, payload map[string]any) []map[string]any {
	t.Helper()
	resourceLogs, ok := payload["resourceLogs"].([]any)
	require.True(t, ok, "payload missing resourceLogs array")
	require.Len(t, resourceLogs, 1, "expected exactly one resourceLogs entry")
	rl := resourceLogs[0].(map[string]any)
	scopeLogs, ok := rl["scopeLogs"].([]any)
	require.True(t, ok, "missing scopeLogs array")
	require.Len(t, scopeLogs, 1, "expected exactly one scopeLogs entry")
	sl := scopeLogs[0].(map[string]any)
	rawRecords, ok := sl["logRecords"].([]any)
	require.True(t, ok, "missing logRecords array")
	out := make([]map[string]any, 0, len(rawRecords))
	for _, r := range rawRecords {
		out = append(out, r.(map[string]any))
	}
	return out
}

// resourceAttrs returns the resource attribute map.
func resourceAttrs(t *testing.T, payload map[string]any) map[string]string {
	t.Helper()
	rl := payload["resourceLogs"].([]any)[0].(map[string]any)
	resource := rl["resource"].(map[string]any)
	return attrSliceToMap(t, resource["attributes"])
}

// scopeName returns the OTLP scope name from the first scope.
func scopeName(t *testing.T, payload map[string]any) string {
	t.Helper()
	rl := payload["resourceLogs"].([]any)[0].(map[string]any)
	sl := rl["scopeLogs"].([]any)[0].(map[string]any)
	scope := sl["scope"].(map[string]any)
	name, _ := scope["name"].(string)
	return name
}

// attrSliceToMap flattens an OTLP attribute slice into a key->stringValue map.
func attrSliceToMap(t *testing.T, raw any) map[string]string {
	t.Helper()
	attrs, ok := raw.([]any)
	require.True(t, ok, "attributes is not an array")
	out := make(map[string]string, len(attrs))
	for _, a := range attrs {
		kv := a.(map[string]any)
		key, _ := kv["key"].(string)
		valBlock, _ := kv["value"].(map[string]any)
		if sv, ok := valBlock["stringValue"].(string); ok {
			out[key] = sv
		} else {
			out[key] = ""
		}
	}
	return out
}

// recordAttrs returns the attribute map for a single log record.
func recordAttrs(t *testing.T, rec map[string]any) map[string]string {
	t.Helper()
	return attrSliceToMap(t, rec["attributes"])
}

// bodyString returns the body.stringValue field of a record. Returns ""
// when the field is missing or the typed slot is empty.
func bodyString(t *testing.T, rec map[string]any) string {
	t.Helper()
	body, ok := rec["body"].(map[string]any)
	if !ok {
		return ""
	}
	sv, _ := body["stringValue"].(string)
	return sv
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type harness struct {
	engine     *Engine
	store      *mockStore
	getReqs    func() []captureRequest
	emitter    *emitter.OTLPEmitter
	captureURL string
}

// newEngineHarness wires up an engine pointed at a real OTLP emitter that
// posts to a captureServer. Caller passes a registry plus optional custom
// policy/classifier overrides via opts.
type harnessOpts struct {
	policy     *policy.Engine
	classifier *classifier.Classifier
	registry   *discovery.Registry
}

func newEngineHarness(t *testing.T, opts harnessOpts) *harness {
	t.Helper()
	url, getReqs := startCaptureServer(t)

	em, err := emitter.NewOTLP(emitter.OTLPConfig{
		Endpoint: url,
		Protocol: "http",
	}, "test-1.2.3")
	require.NoError(t, err)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	st := newMockStore()
	reg := opts.registry
	if reg == nil {
		reg = discovery.NewRegistry()
	}

	cls := opts.classifier
	if cls == nil {
		auth, aerr := classifier.NewAuthorizer("", nil)
		require.NoError(t, aerr)
		cls = classifier.New(auth, classifier.NewManager(nil))
	}

	pol := opts.policy
	if pol == nil {
		pol = policy.New(nil, 168*time.Hour)
	}

	dd := dedup.New(st, nil)
	eng := New(st, reg, dd, cls, em, pol, nil)

	return &harness{
		engine:     eng,
		store:      st,
		captureURL: url,
		getReqs:    getReqs,
		emitter:    em,
	}
}

// authorizingClassifier returns a classifier whose allowlist matches the
// given hostnames as authorized. requiredControls drives the Manager: empty
// list yields ManagedUnknown; non-empty with no software inventory yields
// ManagedUnmanaged.
func authorizingClassifier(t *testing.T, hostnames []string, requiredControls []string) *classifier.Classifier {
	t.Helper()
	dir := t.TempDir()
	allowlist := filepath.Join(dir, "allowlist.yaml")
	body := "assets:\n"
	for _, h := range hostnames {
		body += "  - hostname: \"" + h + "\"\n"
	}
	require.NoError(t, os.WriteFile(allowlist, []byte(body), 0o600))
	auth, err := classifier.NewAuthorizer(allowlist, []string{"hostname"})
	require.NoError(t, err)
	mgr := classifier.NewManager(requiredControls)
	return classifier.New(auth, mgr)
}

// rejectAllClassifier returns a classifier whose allowlist matches no asset
// (so every asset is flagged Unauthorized).
func rejectAllClassifier(t *testing.T) *classifier.Classifier {
	t.Helper()
	return authorizingClassifier(t, []string{"only-this-one"}, nil)
}

// findRecord returns the first log record whose event_type attribute matches.
func findRecord(t *testing.T, recs []map[string]any, eventType model.EventType) map[string]any {
	t.Helper()
	for _, r := range recs {
		attrs := recordAttrs(t, r)
		if attrs["event_type"] == string(eventType) {
			return r
		}
	}
	t.Fatalf("no record with event_type=%s among %d records", eventType, len(recs))
	return nil
}

// stringField returns a top-level string field of a log record.
func stringField(rec map[string]any, key string) string {
	v, _ := rec[key].(string)
	return v
}

// numberField returns a top-level numeric field as int. JSON decodes numbers
// as float64.
func numberField(rec map[string]any, key string) int {
	v, _ := rec[key].(float64)
	return int(v)
}

// ---------------------------------------------------------------------------
// 1. Discovered event — full wire payload assertions
// ---------------------------------------------------------------------------

func TestEngineToOTLP_DiscoveredEvent_FullWirePayload(t *testing.T) {
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		assets: []model.Asset{
			{
				Hostname:        "wire-host-01",
				AssetType:       model.AssetTypeServer,
				OSFamily:        "linux",
				DiscoverySource: "test",
			},
		},
	})

	h := newEngineHarness(t, harnessOpts{registry: reg})

	beforeRun := time.Now().UTC()
	_, err := h.engine.Run(context.Background(), newTestConfig())
	require.NoError(t, err)
	afterRun := time.Now().UTC().Add(5 * time.Second)

	reqs := h.getReqs()
	require.Len(t, reqs, 1, "exactly one POST expected")
	got := reqs[0]
	assert.Equal(t, http.MethodPost, got.Method)
	assert.Equal(t, "/v1/logs", got.Path)
	assert.Equal(t, "application/json", got.ContentType)

	payload := decodePayload(t, got.Body)

	resAttrs := resourceAttrs(t, payload)
	assert.Equal(t, "kite-collector", resAttrs["service.name"])
	assert.Equal(t, "test-1.2.3", resAttrs["service.version"])
	assert.Equal(t, "kite-collector.emitter", scopeName(t, payload))

	recs := logRecords(t, payload)
	require.Len(t, recs, 1, "exactly one logRecord expected")
	rec := recs[0]

	attrs := recordAttrs(t, rec)
	assert.Equal(t, string(model.EventAssetDiscovered), attrs["event_type"])

	// Resolve the engine-assigned scan_run_id and asset_id by reading the
	// persisted event row from the mock store.
	h.store.mu.Lock()
	require.Len(t, h.store.events, 1, "engine should have persisted one event")
	persisted := h.store.events[0]
	h.store.mu.Unlock()

	assert.Equal(t, persisted.AssetID.String(), attrs["asset_id"])
	assert.Equal(t, persisted.ScanRunID.String(), attrs["scan_run_id"])

	// Severity: engine policy default for an asset that is neither
	// unauthorized nor unmanaged is "medium" (severityNumber 9).
	assert.Equal(t, "medium", attrs["severity"])
	assert.Equal(t, "medium", stringField(rec, "severityText"))
	assert.Equal(t, 9, numberField(rec, "severityNumber"))

	// NOTE: engine-produced events currently have no Details payload, so
	// body.stringValue lands on the wire as the empty string. Surfacing
	// this gap explicitly here so future work can decide whether to add a
	// human-readable summary or a JSON details blob.
	assert.Equal(t, "", bodyString(t, rec))

	traceID := stringField(rec, "traceId")
	spanID := stringField(rec, "spanId")
	assert.Len(t, traceID, 32, "traceId must be 32 hex chars")
	assert.Equal(t, hex.EncodeToString(persisted.ScanRunID[:]), traceID)
	assert.Len(t, spanID, 16, "spanId must be 16 hex chars")

	timeNanos, err := strconv.ParseInt(stringField(rec, "timeUnixNano"), 10, 64)
	require.NoError(t, err)
	assert.Greater(t, timeNanos, int64(0))
	assert.GreaterOrEqual(t, timeNanos, beforeRun.UnixNano())
	assert.LessOrEqual(t, timeNanos, afterRun.UnixNano())

	observedNanos, err := strconv.ParseInt(stringField(rec, "observedTimeUnixNano"), 10, 64)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, observedNanos, timeNanos,
		"observedTimeUnixNano must be >= timeUnixNano")
}

// ---------------------------------------------------------------------------
// 2. Updated event
// ---------------------------------------------------------------------------

func TestEngineToOTLP_UpdatedEvent_EmitsAssetUpdated(t *testing.T) {
	// Pre-load the asset with FirstSeenAt < LastSeenAt so the merge path
	// produces an event flagged as updated rather than discovered.
	existing := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "updated-host",
		AssetType:       model.AssetTypeServer,
		DiscoverySource: "test",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		FirstSeenAt:     time.Now().UTC().Add(-72 * time.Hour),
		LastSeenAt:      time.Now().UTC().Add(-72 * time.Hour),
	}
	existing.ComputeNaturalKey()

	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		assets: []model.Asset{
			{Hostname: "updated-host", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
		},
	})

	h := newEngineHarness(t, harnessOpts{registry: reg})
	h.store.assets[existing.NaturalKey] = existing

	_, err := h.engine.Run(context.Background(), newTestConfig())
	require.NoError(t, err)

	reqs := h.getReqs()
	require.Len(t, reqs, 1)
	recs := logRecords(t, decodePayload(t, reqs[0].Body))
	require.Len(t, recs, 1)
	attrs := recordAttrs(t, recs[0])
	assert.Equal(t, string(model.EventAssetUpdated), attrs["event_type"])
}

// ---------------------------------------------------------------------------
// 3. Unauthorized event
// ---------------------------------------------------------------------------

func TestEngineToOTLP_UnauthorizedAsset_EmitsUnauthorizedAssetDetected(t *testing.T) {
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		assets: []model.Asset{
			{Hostname: "rogue-host", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
		},
	})

	h := newEngineHarness(t, harnessOpts{
		registry:   reg,
		classifier: rejectAllClassifier(t),
	})

	_, err := h.engine.Run(context.Background(), newTestConfig())
	require.NoError(t, err)

	reqs := h.getReqs()
	require.Len(t, reqs, 1)
	recs := logRecords(t, decodePayload(t, reqs[0].Body))
	require.Len(t, recs, 1)
	attrs := recordAttrs(t, recs[0])
	assert.Equal(t, string(model.EventUnauthorizedAssetDetected), attrs["event_type"])
	assert.Equal(t, string(model.AuthorizationUnauthorized), attrs["is_authorized"])
	assert.Equal(t, "high", attrs["severity"])
	assert.Equal(t, 13, numberField(recs[0], "severityNumber"))
}

// ---------------------------------------------------------------------------
// 4. Unmanaged event
// ---------------------------------------------------------------------------

func TestEngineToOTLP_UnmanagedAsset_EmitsUnmanagedAssetDetected(t *testing.T) {
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		assets: []model.Asset{
			{Hostname: "managed-but-uncontrolled", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
		},
	})

	// Allowlist matches the host (-> Authorized) AND requiredControls is
	// non-empty with no software in the store (-> Unmanaged). Authorized
	// must come first so the engine chooses Unmanaged over Unauthorized.
	cls := authorizingClassifier(t, []string{"managed-but-uncontrolled"}, []string{"required-edr"})
	h := newEngineHarness(t, harnessOpts{registry: reg, classifier: cls})

	_, err := h.engine.Run(context.Background(), newTestConfig())
	require.NoError(t, err)

	reqs := h.getReqs()
	require.Len(t, reqs, 1)
	recs := logRecords(t, decodePayload(t, reqs[0].Body))
	require.Len(t, recs, 1)
	attrs := recordAttrs(t, recs[0])
	assert.Equal(t, string(model.EventUnmanagedAssetDetected), attrs["event_type"])
	assert.Equal(t, string(model.AuthorizationAuthorized), attrs["is_authorized"])
	assert.Equal(t, string(model.ManagedUnmanaged), attrs["is_managed"])
}

// ---------------------------------------------------------------------------
// 5. Stale -> AssetNotSeen
// ---------------------------------------------------------------------------

func TestEngineToOTLP_StaleAsset_EmitsAssetNotSeen(t *testing.T) {
	stale := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "stale-host",
		AssetType:       model.AssetTypeWorkstation,
		DiscoverySource: "test",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		FirstSeenAt:     time.Now().UTC().Add(-300 * time.Hour),
		LastSeenAt:      time.Now().UTC().Add(-300 * time.Hour),
	}
	stale.ComputeNaturalKey()

	// Discovery returns no assets — only the stale one matters.
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{name: "test", assets: nil})

	h := newEngineHarness(t, harnessOpts{registry: reg})
	h.store.assets[stale.NaturalKey] = stale

	_, err := h.engine.Run(context.Background(), newTestConfig())
	require.NoError(t, err)

	reqs := h.getReqs()
	require.Len(t, reqs, 1)
	recs := logRecords(t, decodePayload(t, reqs[0].Body))
	require.Len(t, recs, 1, "exactly one AssetNotSeen record")
	rec := recs[0]
	attrs := recordAttrs(t, rec)

	assert.Equal(t, string(model.EventAssetNotSeen), attrs["event_type"])
	assert.Equal(t, "medium", attrs["severity"])
	assert.Equal(t, "medium", stringField(rec, "severityText"))
	assert.Equal(t, 9, numberField(rec, "severityNumber"))
	// FromAsset wiring (RFC-0112) means stale-asset metadata is now on the
	// wire alongside ids — assert the fields propagated correctly.
	assert.Equal(t, "stale-host", attrs["hostname"])
	assert.Equal(t, string(model.AssetTypeWorkstation), attrs["asset_type"])
}

// ---------------------------------------------------------------------------
// 6. Batch shares scan_run_id and traceId, distinct spanIds and asset_ids
// ---------------------------------------------------------------------------

func TestEngineToOTLP_BatchSharesScanRunIDAndTraceID(t *testing.T) {
	reg := discovery.NewRegistry()
	reg.Register(&mockSource{
		name: "test",
		assets: []model.Asset{
			{Hostname: "batch-host-a", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
			{Hostname: "batch-host-b", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
			{Hostname: "batch-host-c", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
		},
	})
	h := newEngineHarness(t, harnessOpts{registry: reg})

	_, err := h.engine.Run(context.Background(), newTestConfig())
	require.NoError(t, err)

	reqs := h.getReqs()
	require.Len(t, reqs, 1, "engine must batch all events into a single POST")
	recs := logRecords(t, decodePayload(t, reqs[0].Body))
	require.Len(t, recs, 3)

	scanIDs := make(map[string]struct{}, 3)
	traceIDs := make(map[string]struct{}, 3)
	spanIDs := make(map[string]struct{}, 3)
	assetIDs := make(map[string]struct{}, 3)

	for _, rec := range recs {
		attrs := recordAttrs(t, rec)
		assert.Equal(t, string(model.EventAssetDiscovered), attrs["event_type"])
		scanIDs[attrs["scan_run_id"]] = struct{}{}
		assetIDs[attrs["asset_id"]] = struct{}{}
		traceIDs[stringField(rec, "traceId")] = struct{}{}
		spanIDs[stringField(rec, "spanId")] = struct{}{}
	}
	assert.Len(t, scanIDs, 1, "all records share the same scan_run_id")
	assert.Len(t, traceIDs, 1, "all records share the same traceId")
	assert.Len(t, spanIDs, 3, "each record has a distinct spanId")
	assert.Len(t, assetIDs, 3, "each record has a distinct asset_id")
}

// ---------------------------------------------------------------------------
// 7. All event types: severity number/text mapping
// ---------------------------------------------------------------------------

func TestEngineToOTLP_AllEngineEventTypes_SeverityNumberMapping(t *testing.T) {
	// Build per-scenario harnesses because each requires distinct
	// classifier/policy wiring.
	type expect struct {
		eventType model.EventType
		severity  model.Severity
		sevNum    int
	}

	t.Run("Discovered=medium(9)", func(t *testing.T) {
		reg := discovery.NewRegistry()
		reg.Register(&mockSource{
			name: "test",
			assets: []model.Asset{
				{Hostname: "disc-host", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
			},
		})
		h := newEngineHarness(t, harnessOpts{registry: reg})
		_, err := h.engine.Run(context.Background(), newTestConfig())
		require.NoError(t, err)
		assertSingleEvent(t, h.getReqs(), expect{model.EventAssetDiscovered, model.SeverityMedium, 9})
	})

	t.Run("Updated=low(5)", func(t *testing.T) {
		// Pre-load asset so dedup yields an Updated event. Use a policy
		// rule keyed on Environment="staging" => low so the merged asset
		// (which carries Environment="staging" from the existing record)
		// is scored low.
		existing := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			Hostname:        "upd-host",
			AssetType:       model.AssetTypeServer,
			Environment:     "staging",
			DiscoverySource: "test",
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       model.ManagedUnknown,
			FirstSeenAt:     time.Now().UTC().Add(-72 * time.Hour),
			LastSeenAt:      time.Now().UTC().Add(-72 * time.Hour),
		}
		existing.ComputeNaturalKey()
		reg := discovery.NewRegistry()
		reg.Register(&mockSource{
			name: "test",
			assets: []model.Asset{
				{Hostname: "upd-host", AssetType: model.AssetTypeServer, Environment: "staging", DiscoverySource: "test"},
			},
		})
		pol := policy.New([]model.SeverityRule{
			{Environment: "staging", Severity: model.SeverityLow},
		}, 168*time.Hour)
		h := newEngineHarness(t, harnessOpts{registry: reg, policy: pol})
		h.store.assets[existing.NaturalKey] = existing

		_, err := h.engine.Run(context.Background(), newTestConfig())
		require.NoError(t, err)
		assertSingleEvent(t, h.getReqs(), expect{model.EventAssetUpdated, model.SeverityLow, 5})
	})

	t.Run("Unauthorized=high(13)", func(t *testing.T) {
		reg := discovery.NewRegistry()
		reg.Register(&mockSource{
			name: "test",
			assets: []model.Asset{
				{Hostname: "unauth-host", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
			},
		})
		h := newEngineHarness(t, harnessOpts{
			registry:   reg,
			classifier: rejectAllClassifier(t),
		})
		_, err := h.engine.Run(context.Background(), newTestConfig())
		require.NoError(t, err)
		assertSingleEvent(t, h.getReqs(), expect{model.EventUnauthorizedAssetDetected, model.SeverityHigh, 13})
	})

	t.Run("Unmanaged=critical(17)", func(t *testing.T) {
		reg := discovery.NewRegistry()
		reg.Register(&mockSource{
			name: "test",
			assets: []model.Asset{
				{Hostname: "unmgd-host", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
			},
		})
		cls := authorizingClassifier(t, []string{"unmgd-host"}, []string{"required-edr"})
		// Rule: any asset whose IsManaged is "unmanaged" => critical.
		pol := policy.New([]model.SeverityRule{
			{IsManaged: model.ManagedUnmanaged, Severity: model.SeverityCritical},
		}, 168*time.Hour)
		h := newEngineHarness(t, harnessOpts{registry: reg, classifier: cls, policy: pol})

		_, err := h.engine.Run(context.Background(), newTestConfig())
		require.NoError(t, err)
		assertSingleEvent(t, h.getReqs(), expect{model.EventUnmanagedAssetDetected, model.SeverityCritical, 17})
	})

	t.Run("NotSeen=medium(9)", func(t *testing.T) {
		// Engine hardcodes SeverityMedium for AssetNotSeen events
		// regardless of policy rules — the policy stub here has a rule
		// that would score low if it were consulted, but the engine
		// bypasses the policy for stale assets. This subtest pins that
		// behaviour.
		stale := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			Hostname:        "ns-host",
			AssetType:       model.AssetTypeServer,
			DiscoverySource: "test",
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       model.ManagedUnknown,
			FirstSeenAt:     time.Now().UTC().Add(-300 * time.Hour),
			LastSeenAt:      time.Now().UTC().Add(-300 * time.Hour),
		}
		stale.ComputeNaturalKey()
		reg := discovery.NewRegistry()
		reg.Register(&mockSource{name: "test", assets: nil})
		pol := policy.New([]model.SeverityRule{
			{Environment: "", Severity: model.SeverityLow}, // would catch all if consulted
		}, 168*time.Hour)
		h := newEngineHarness(t, harnessOpts{registry: reg, policy: pol})
		h.store.assets[stale.NaturalKey] = stale

		_, err := h.engine.Run(context.Background(), newTestConfig())
		require.NoError(t, err)
		assertSingleEvent(t, h.getReqs(), expect{model.EventAssetNotSeen, model.SeverityMedium, 9})
	})
}

// assertSingleEvent decodes the captured POST body and asserts that the lone
// log record matches the expected event type, severity text, and severity
// number.
func assertSingleEvent(t *testing.T, reqs []captureRequest, exp struct {
	eventType model.EventType
	severity  model.Severity
	sevNum    int
},
) {
	t.Helper()
	require.Len(t, reqs, 1, "expected a single POST")
	recs := logRecords(t, decodePayload(t, reqs[0].Body))

	rec := findRecord(t, recs, exp.eventType)
	attrs := recordAttrs(t, rec)
	assert.Equal(t, string(exp.severity), attrs["severity"])
	assert.Equal(t, string(exp.severity), stringField(rec, "severityText"))
	assert.Equal(t, exp.sevNum, numberField(rec, "severityNumber"))
}
