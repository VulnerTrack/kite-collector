package emitter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/telemetry/contract"
	telresource "github.com/vulnertrack/kite-collector/internal/telemetry/resource"
)

// TestOTLPEmitter_ResourceAttributesMatchContract drives the real
// OTLPEmitter with a resource map produced by telemetry/resource.Build and
// asserts that every resource attribute on the wire is in the RFC-0115
// closed allow-set, every required key is present, and the four
// constant-valued attributes carry the right values.
func TestOTLPEmitter_ResourceAttributesMatchContract(t *testing.T) {
	captured := make(chan otlpLogsPayload, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var p otlpLogsPayload
		require.NoError(t, json.Unmarshal(body, &p))
		captured <- p
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resourceAttrs := telresource.Build(telresource.Config{
		AgentID:        uuid.Must(uuid.NewV7()),
		ServiceVersion: "1.2.3-test",
		TenantID:       "01931cb6-b7c4-7c41-b000-fedcba987654",
		Environment:    "pilot",
	})

	em, err := NewOTLP(OTLPConfig{
		Endpoint: srv.URL,
		Resource: resourceAttrs,
	}, "1.2.3-test")
	require.NoError(t, err)
	defer func() { _ = em.Shutdown(context.Background()) }()

	evt := model.MachineEvent{
		ID:        uuid.Must(uuid.NewV7()),
		MachineID: uuid.Must(uuid.NewV7()),
		ScanRunID: uuid.Must(uuid.NewV7()),
		EventType: model.EventMachineDiscovered,
		Severity:  model.SeverityHigh,
		Timestamp: time.Now(),
		Hostname:  "edge-01.acme.example",
	}
	require.NoError(t, em.Emit(context.Background(), evt))

	got := <-captured
	require.Len(t, got.ResourceLogs, 1)

	wireResource := map[string]string{}
	for _, kv := range got.ResourceLogs[0].Resource.Attributes {
		require.NotNil(t, kv.Value.StringValue, "resource attribute %q has non-string value", kv.Key)
		wireResource[kv.Key] = *kv.Value.StringValue
	}

	for _, k := range contract.RequiredResourceAttributes {
		v, ok := wireResource[string(k)]
		assert.Truef(t, ok, "missing required resource attribute %q", k)
		assert.NotEmptyf(t, v, "empty value for %q", k)
	}
	for k := range wireResource {
		assert.Truef(t, contract.IsAllowedResourceAttribute(k),
			"emitter sent resource attribute outside contract: %q", k)
	}
	assert.Equal(t, contract.ServiceName, wireResource[string(contract.ResAttrServiceName)])
	assert.Equal(t, contract.ServiceNamespace, wireResource[string(contract.ResAttrServiceNamespace)])
	assert.Equal(t, contract.AgentType, wireResource[string(contract.ResAttrAgentType)])
	assert.Equal(t, contract.Version, wireResource[string(contract.ResAttrContractVersion)])
}

// TestOTLPEmitter_RedactsForbiddenResourceKeys feeds the emitter a resource
// map containing a forbidden key (`db_password`) and asserts the wire
// output drops it.
func TestOTLPEmitter_RedactsForbiddenResourceKeys(t *testing.T) {
	captured := make(chan otlpLogsPayload, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p otlpLogsPayload
		_ = json.Unmarshal(body, &p)
		captured <- p
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	em, err := NewOTLP(OTLPConfig{
		Endpoint: srv.URL,
		Resource: map[string]string{
			"service.name":    "kite-collector",
			"service.version": "0.0.0",
			"db_password":     "should-never-leave",
			"api_key":         "neither-this",
		},
	}, "0.0.0")
	require.NoError(t, err)
	defer func() { _ = em.Shutdown(context.Background()) }()

	evt := model.MachineEvent{
		ID:        uuid.Must(uuid.NewV7()),
		MachineID: uuid.Must(uuid.NewV7()),
		ScanRunID: uuid.Must(uuid.NewV7()),
		EventType: model.EventMachineDiscovered,
		Severity:  model.SeverityHigh,
		Timestamp: time.Now(),
	}
	require.NoError(t, em.Emit(context.Background(), evt))

	got := <-captured
	for _, kv := range got.ResourceLogs[0].Resource.Attributes {
		assert.NotEqual(t, "db_password", kv.Key, "forbidden key leaked")
		assert.NotEqual(t, "api_key", kv.Key, "forbidden key leaked")
	}
}

// TestOTLPEmitter_RecordAttributesMatchContract asserts the RFC-0115 v1
// log-record attribute layer: for every legacy lifecycle event type the
// emitter produces, the record carries an allowed event.name, every
// security.*/event.* key is inside the event's closed attribute set, and
// every required key is present. Legacy snake_case keys (event_type,
// machine_id, ...) ride alongside during the §2.3 dual-emit window and are
// exempt from the closed-set check.
func TestOTLPEmitter_RecordAttributesMatchContract(t *testing.T) {
	machineID := uuid.Must(uuid.NewV7())
	scanID := uuid.Must(uuid.NewV7())

	for _, eventType := range []model.EventType{
		model.EventMachineDiscovered,
		model.EventMachineUpdated,
		model.EventMachineAnalyzed,
		model.EventUnauthorizedMachineDetected,
		model.EventUnmanagedMachineDetected,
		model.EventMachineNotSeen,
		model.EventMachineRemoved,
	} {
		evt := model.MachineEvent{
			ID:              uuid.Must(uuid.NewV7()),
			MachineID:       machineID,
			ScanRunID:       scanID,
			EventType:       eventType,
			Severity:        model.SeverityLow,
			Timestamp:       time.Now(),
			Hostname:        "edge-02.acme.example",
			MachineType:     model.MachineTypeVirtualMachine,
			OSFamily:        "linux",
			OSVersion:       "22.04",
			DiscoverySource: "agent",
			IsAuthorized:    model.AuthorizationAuthorized,
			IsManaged:       model.ManagedManaged,
			FirstSeenAt:     time.Now().Add(-24 * time.Hour),
		}

		wire := map[string]string{}
		for _, kv := range buildAttributes(&evt) {
			require.NotNil(t, kv.Value.StringValue)
			wire[kv.Key] = *kv.Value.StringValue
		}

		name := contract.EventName(wire["event.name"])
		require.Truef(t, contract.IsAllowedEventName(string(name)),
			"%s: event.name %q not in contract", eventType, name)
		assert.Equal(t, contract.EventDomain, wire["event.domain"])

		for key := range wire {
			if !strings.Contains(key, ".") {
				continue // legacy dual-emit key
			}
			assert.Truef(t, contract.IsAllowedEventAttribute(name, key),
				"%s: attribute %q not allowed on %q", eventType, key, name)
		}
		for _, req := range contract.EventRequiredAttributes[name] {
			assert.Containsf(t, wire, req,
				"%s: required attribute %q missing", eventType, req)
		}
		assert.Equal(t, "vm", wire["security.machine.type"], "closed enum mapping")
	}
}
