package observability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/identity"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// fakeStore implements ReconcilerStore in-memory. Tests pre-load heartbeats
// and inspect the incidents slice after ReconcileScan returns.
type fakeStore struct {
	hbs       []model.ProbeHeartbeat
	incidents []model.RuntimeIncident
}

func (f *fakeStore) ListHeartbeats(_ context.Context, _ store.HeartbeatFilter) ([]model.ProbeHeartbeat, error) {
	return f.hbs, nil
}

func (f *fakeStore) InsertRuntimeIncident(_ context.Context, inc model.RuntimeIncident) error {
	f.incidents = append(f.incidents, inc)
	return nil
}

func (f *fakeStore) RecordHeartbeat(_ context.Context, hb model.ProbeHeartbeat) error {
	f.hbs = append(f.hbs, hb)
	return nil
}

func newTestIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return &identity.Identity{
		AgentID:            uuid.Must(uuid.NewV7()),
		PublicKey:          pub,
		PrivateKey:         priv,
		BinaryHash:         "sha256:expected",
		ExpectedBinaryHash: "sha256:expected",
	}
}

func makeHeartbeat(scanID uuid.UUID, source string, items int, hash string) model.ProbeHeartbeat {
	return model.ProbeHeartbeat{
		ID:           uuid.Must(uuid.NewV7()),
		ScanRunID:    scanID,
		Source:       source,
		Status:       model.HeartbeatOK,
		ItemsEmitted: items,
		DurationMS:   10,
		BinaryHash:   hash,
		CreatedAt:    time.Now().UTC(),
	}
}

// signWith stamps a valid signature using id's private key.
func signWith(id *identity.Identity, hb *model.ProbeHeartbeat) {
	hb.Signature = id.Sign(hb.CanonicalPayload())
}

func TestReconcile_HappyPath_NoIncidents(t *testing.T) {
	id := newTestIdentity(t)
	scanID := uuid.Must(uuid.NewV7())

	hb1 := makeHeartbeat(scanID, "agent.firewall", 5, id.ExpectedBinaryHash)
	signWith(id, &hb1)
	hb2 := makeHeartbeat(scanID, "agent.processes", 0, id.ExpectedBinaryHash)
	signWith(id, &hb2)

	st := &fakeStore{hbs: []model.ProbeHeartbeat{hb1, hb2}}
	rec := NewReconciler(id, st, config.CanaryConfig{
		ExpectedCollectors: []string{"agent.firewall", "agent.processes"},
	}, slog.Default())

	res, err := rec.ReconcileScan(context.Background(), scanID)
	require.NoError(t, err)
	assert.Equal(t, 2, res.HeartbeatsChecked)
	assert.Equal(t, 0, res.BadSignatures)
	assert.Equal(t, 0, res.BinaryHashDrift)
	assert.Empty(t, res.MissingCollectors)
	assert.Empty(t, res.ExtraCollectors)
	assert.Empty(t, st.incidents)
}

func TestReconcile_BadSignature_RaisesTamper(t *testing.T) {
	id := newTestIdentity(t)
	scanID := uuid.Must(uuid.NewV7())

	hb := makeHeartbeat(scanID, "agent.firewall", 1, id.ExpectedBinaryHash)
	hb.Signature = make([]byte, ed25519.SignatureSize) // all-zero bytes — valid length, invalid signature

	st := &fakeStore{hbs: []model.ProbeHeartbeat{hb}}
	rec := NewReconciler(id, st, config.CanaryConfig{}, slog.Default())

	res, err := rec.ReconcileScan(context.Background(), scanID)
	require.NoError(t, err)
	assert.Equal(t, 1, res.BadSignatures)
	assert.Equal(t, 1, res.IncidentsRaised)
	require.Len(t, st.incidents, 1)
	assert.Equal(t, model.IncidentTamperDetected, st.incidents[0].IncidentType)
	assert.Equal(t, "observability.reconciler", st.incidents[0].Component)
}

func TestReconcile_BinaryHashDrift_RaisesTamper(t *testing.T) {
	id := newTestIdentity(t)
	scanID := uuid.Must(uuid.NewV7())

	// Heartbeat is correctly signed but reports a different binary hash —
	// the canonical payload includes binary_hash so the signature still
	// verifies; the drift detector catches it.
	hb := makeHeartbeat(scanID, "agent.firewall", 1, "sha256:rogue")
	signWith(id, &hb)

	st := &fakeStore{hbs: []model.ProbeHeartbeat{hb}}
	rec := NewReconciler(id, st, config.CanaryConfig{}, slog.Default())

	res, err := rec.ReconcileScan(context.Background(), scanID)
	require.NoError(t, err)
	assert.Equal(t, 0, res.BadSignatures)
	assert.Equal(t, 1, res.BinaryHashDrift)
	assert.Equal(t, 1, res.IncidentsRaised)
	require.Len(t, st.incidents, 1)
	assert.Equal(t, model.IncidentTamperDetected, st.incidents[0].IncidentType)
}

func TestReconcile_MissingCollector_RaisesCanaryDrift(t *testing.T) {
	id := newTestIdentity(t)
	scanID := uuid.Must(uuid.NewV7())

	// Only firewall reported; canary expects firewall AND processes.
	hb := makeHeartbeat(scanID, "agent.firewall", 1, id.ExpectedBinaryHash)
	signWith(id, &hb)

	st := &fakeStore{hbs: []model.ProbeHeartbeat{hb}}
	rec := NewReconciler(id, st, config.CanaryConfig{
		ExpectedCollectors: []string{"agent.firewall", "agent.processes"},
	}, slog.Default())

	res, err := rec.ReconcileScan(context.Background(), scanID)
	require.NoError(t, err)
	assert.Equal(t, []string{"agent.processes"}, res.MissingCollectors)
	assert.Empty(t, res.ExtraCollectors)
	require.Len(t, st.incidents, 1)
	assert.Equal(t, model.IncidentCanaryDrift, st.incidents[0].IncidentType)
	assert.Contains(t, st.incidents[0].ErrorMessage, "agent.processes")
}

func TestReconcile_ExtraCollector_IgnoredUnlessStrict(t *testing.T) {
	id := newTestIdentity(t)
	scanID := uuid.Must(uuid.NewV7())

	hb1 := makeHeartbeat(scanID, "agent.firewall", 1, id.ExpectedBinaryHash)
	hb2 := makeHeartbeat(scanID, "agent.processes", 1, id.ExpectedBinaryHash)
	signWith(id, &hb1)
	signWith(id, &hb2)

	// Non-strict — extras silently accepted.
	st := &fakeStore{hbs: []model.ProbeHeartbeat{hb1, hb2}}
	rec := NewReconciler(id, st, config.CanaryConfig{
		ExpectedCollectors: []string{"agent.firewall"},
		Strict:             false,
	}, slog.Default())
	res, err := rec.ReconcileScan(context.Background(), scanID)
	require.NoError(t, err)
	assert.Empty(t, res.ExtraCollectors)
	assert.Empty(t, st.incidents)

	// Strict — extras raise drift.
	st2 := &fakeStore{hbs: []model.ProbeHeartbeat{hb1, hb2}}
	rec2 := NewReconciler(id, st2, config.CanaryConfig{
		ExpectedCollectors: []string{"agent.firewall"},
		Strict:             true,
	}, slog.Default())
	res, err = rec2.ReconcileScan(context.Background(), scanID)
	require.NoError(t, err)
	assert.Equal(t, []string{"agent.processes"}, res.ExtraCollectors)
	require.Len(t, st2.incidents, 1)
	assert.Equal(t, model.IncidentCanaryDrift, st2.incidents[0].IncidentType)
}

func TestReconcile_EmptyBaseline_DisablesCanaryCheck(t *testing.T) {
	id := newTestIdentity(t)
	scanID := uuid.Must(uuid.NewV7())

	hb := makeHeartbeat(scanID, "agent.firewall", 1, id.ExpectedBinaryHash)
	signWith(id, &hb)

	st := &fakeStore{hbs: []model.ProbeHeartbeat{hb}}
	rec := NewReconciler(id, st, config.CanaryConfig{}, slog.Default())

	res, err := rec.ReconcileScan(context.Background(), scanID)
	require.NoError(t, err)
	assert.Empty(t, res.MissingCollectors)
	assert.Empty(t, res.ExtraCollectors)
	assert.Empty(t, st.incidents)
}

func TestRecorder_SignsAndPersists(t *testing.T) {
	id := newTestIdentity(t)
	scanID := uuid.Must(uuid.NewV7())

	st := &fakeStore{}
	r := NewRecorder(scanID, id, st, slog.Default())
	require.NoError(t, r.Record(context.Background(), "agent.firewall", model.HeartbeatOK, 7, 80*time.Millisecond))

	require.Len(t, st.hbs, 1)
	hb := st.hbs[0]
	assert.Equal(t, scanID, hb.ScanRunID)
	assert.Equal(t, "agent.firewall", hb.Source)
	assert.Equal(t, model.HeartbeatOK, hb.Status)
	assert.Equal(t, 7, hb.ItemsEmitted)
	assert.Equal(t, int64(80), hb.DurationMS)
	assert.Equal(t, id.BinaryHash, hb.BinaryHash)
	assert.True(t, identity.Verify(id.PublicKey, hb.CanonicalPayload(), hb.Signature),
		"recorder must produce a signature that verifies against the install pubkey")
}
