package emitter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/telemetry/contract"
	"github.com/vulnertrack/kite-collector/internal/telemetry/recordsig"
)

// testRecordSigner stands in for the agent identity: raw Ed25519 signing
// plus the identity-style fingerprint.
type testRecordSigner struct{ priv ed25519.PrivateKey }

func (s testRecordSigner) Sign(msg []byte) []byte { return ed25519.Sign(s.priv, msg) }
func (s testRecordSigner) Fingerprint() string {
	return recordsig.Fingerprint(s.priv.Public().(ed25519.PublicKey))
}

func TestOTLPEmitter_SignsEveryLogRecord(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var (
		mu   sync.Mutex
		body []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	em, err := NewOTLP(OTLPConfig{
		Endpoint:     srv.URL,
		RecordSigner: testRecordSigner{priv: priv},
	}, "test")
	require.NoError(t, err)

	machine := model.Machine{
		ID: uuid.Must(uuid.NewV7()), Hostname: "edge-01", MachineType: model.MachineTypeServer,
		OSFamily: "linux", IsAuthorized: model.AuthorizationAuthorized, IsManaged: model.ManagedManaged,
		DiscoverySource: "network", FirstSeenAt: time.Now(), LastSeenAt: time.Now(),
	}
	scan := uuid.Must(uuid.NewV7())
	mk := func(t model.EventType, sev model.Severity, details string) model.MachineEvent {
		ev := model.MachineEvent{
			ID: uuid.Must(uuid.NewV7()), EventType: t, ScanRunID: scan,
			Severity: sev, Details: details, Timestamp: time.Now(),
		}
		ev.FromMachine(machine)
		return ev
	}
	events := []model.MachineEvent{
		mk(model.EventMachineDiscovered, model.SeverityLow, "discovered"),
		mk(model.EventUnauthorizedMachineDetected, model.SeverityHigh, "unauthorized"),
	}
	require.NoError(t, em.EmitBatch(context.Background(), events))

	mu.Lock()
	defer mu.Unlock()
	var payload otlpLogsPayload
	require.NoError(t, json.Unmarshal(body, &payload))
	records := payload.ResourceLogs[0].ScopeLogs[0].LogRecords
	require.Len(t, records, len(events))

	for _, rec := range records {
		view := rec.canonicalView()
		assert.Equal(t, recordsig.AlgorithmEd25519, view.Attributes[contract.AttrRecordSignatureAlg])
		assert.Equal(t, recordsig.Fingerprint(pub), view.Attributes[contract.AttrRecordSignerFingerprint])
		assert.NoError(t, recordsig.Verify(view, pub), "record %s must verify as sent", rec.EventName)

		// The signature must cover the attributes: flipping one breaks it.
		view.Attributes["hostname"] = "evil-01"
		assert.ErrorIs(t, recordsig.Verify(view, pub), recordsig.ErrInvalidSignature)

		// Every attribute the record carries, signature included, is in
		// the contract for its event.
		name := contract.EventName(view.Attributes[contract.AttrEventName])
		for key := range view.Attributes {
			if key == "event_type" || key == "event_name" || key == "machine_id" || key == "scan_run_id" ||
				key == "severity" || key == "hostname" || key == "machine_type" || key == "os_family" ||
				key == "is_authorized" || key == "is_managed" || key == "discovery_source" {
				continue // legacy dual-emit keys, outside the v1 allow-set by design
			}
			assert.Truef(t, contract.IsAllowedEventAttribute(name, key), "%s: %q not allowed", name, key)
		}
	}
}

func TestOTLPEmitter_UnsignedWithoutRecordSigner(t *testing.T) {
	em, err := NewOTLP(OTLPConfig{Endpoint: "http://127.0.0.1:1"}, "test")
	require.NoError(t, err)
	ev := model.MachineEvent{ID: uuid.Must(uuid.NewV7()), EventType: model.EventMachineDiscovered, Timestamp: time.Now()}
	rec := em.eventToLogRecord(&ev, "1")
	for _, kv := range rec.Attributes {
		assert.NotEqual(t, contract.AttrRecordSignature, kv.Key)
	}
}

// The contract and the signer must agree on attribute names; they are
// deliberately not imported from one another.
func TestRecordSignatureAttributeNamesMatchContract(t *testing.T) {
	assert.Equal(t, recordsig.AttrSignature, contract.AttrRecordSignature)
	assert.Equal(t, recordsig.AttrSignerFingerprint, contract.AttrRecordSignerFingerprint)
	assert.Equal(t, recordsig.AttrAlgorithm, contract.AttrRecordSignatureAlg)
}
