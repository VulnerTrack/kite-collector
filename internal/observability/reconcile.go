package observability

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/identity"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// ReconcilerStore is the slice of store.Store the reconciler depends on.
// Declared inline so reconcile_test.go can substitute a stub without
// pulling the whole Store interface.
type ReconcilerStore interface {
	ListHeartbeats(ctx context.Context, filter store.HeartbeatFilter) ([]model.ProbeHeartbeat, error)
	InsertRuntimeIncident(ctx context.Context, incident model.RuntimeIncident) error
}

// Reconciler runs after every scan to convert heartbeat anomalies into
// RuntimeIncidents the existing dashboard already surfaces. It is the
// detector half of the synthetic-finding system; the Recorder is the
// emitter half.
type Reconciler struct {
	store    ReconcilerStore
	identity *identity.Identity
	logger   *slog.Logger
	canary   config.CanaryConfig
}

// NewReconciler binds the reconciler to its dependencies. logger may be nil.
func NewReconciler(id *identity.Identity, st ReconcilerStore, canary config.CanaryConfig, logger *slog.Logger) *Reconciler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reconciler{
		identity: id,
		store:    st,
		canary:   canary,
		logger:   logger,
	}
}

// ReconcileResult summarises everything the reconciler did for one scan.
// Useful both for tests and for the dashboard's "last reconcile" panel.
type ReconcileResult struct {
	MissingCollectors []string
	ExtraCollectors   []string
	HeartbeatsChecked int
	BadSignatures     int
	BinaryHashDrift   int
	IncidentsRaised   int
}

// ReconcileScan processes every heartbeat recorded under scanID. Returns
// errors from the store; per-incident insert failures are logged but
// recorded in the result counter so the caller can decide.
func (r *Reconciler) ReconcileScan(ctx context.Context, scanID uuid.UUID) (ReconcileResult, error) {
	res := ReconcileResult{}

	r.logger.Info(
		"reconcile starting",
		"code", string(LogCodeReconcileStart),
		"scan_id", scanID,
		"canary_expected", len(r.canary.ExpectedCollectors),
		"canary_strict", r.canary.Strict,
	)

	hbs, err := r.store.ListHeartbeats(ctx, store.HeartbeatFilter{ScanRunID: &scanID})
	if err != nil {
		return res, fmt.Errorf("list heartbeats for scan %s: %w", scanID, err)
	}
	res.HeartbeatsChecked = len(hbs)

	// Snapshot the pubkey + expected hash once so a concurrent identity
	// reload (we don't do that today, but future-proof) cannot give one
	// heartbeat verified and the next rejected by a different key.
	pub := r.identity.PublicKey
	expectedHash := r.identity.ExpectedBinaryHash

	actualSources := make(map[string]struct{}, len(hbs))
	for _, hb := range hbs {
		actualSources[hb.Source] = struct{}{}

		// Signature check — a tampered binary that knows the wire layout
		// can still produce records, but only the install's private key
		// produces a signature that verifies.
		if !identity.Verify(pub, hb.CanonicalPayload(), hb.Signature) {
			res.BadSignatures++
			r.logger.Warn(
				"heartbeat signature failed verification",
				"code", string(LogCodeTamperBadSignature),
				"scan_id", scanID,
				"source", hb.Source,
			)
			r.raiseIncident(ctx, scanID, model.IncidentTamperDetected,
				fmt.Sprintf("heartbeat from source %q has invalid Ed25519 signature", hb.Source),
				&res)
			continue
		}

		// Binary hash drift. Empty expectedHash means "tamper check
		// disabled" (LoadOrCreate could not compute on first boot, or
		// admin wiped the field) — skip silently.
		if expectedHash != "" && hb.BinaryHash != "" && hb.BinaryHash != expectedHash {
			res.BinaryHashDrift++
			r.logger.Warn(
				"running binary hash diverges from expected",
				"code", string(LogCodeTamperBinaryDrift),
				"scan_id", scanID,
				"source", hb.Source,
				"expected", expectedHash,
				"actual", hb.BinaryHash,
			)
			r.raiseIncident(ctx, scanID, model.IncidentTamperDetected,
				fmt.Sprintf("binary hash drift in source %q: expected %s, got %s",
					hb.Source, expectedHash, hb.BinaryHash),
				&res)
		}
	}

	// Canary baseline drift. The expected set is taken verbatim from
	// config; an empty list disables the check entirely so an operator can
	// install kite-collector without committing to a baseline upfront.
	if len(r.canary.ExpectedCollectors) > 0 {
		expected := make(map[string]struct{}, len(r.canary.ExpectedCollectors))
		for _, s := range r.canary.ExpectedCollectors {
			expected[s] = struct{}{}
		}

		for s := range expected {
			if _, ok := actualSources[s]; !ok {
				res.MissingCollectors = append(res.MissingCollectors, s)
			}
		}
		if r.canary.Strict {
			for s := range actualSources {
				if _, ok := expected[s]; !ok {
					res.ExtraCollectors = append(res.ExtraCollectors, s)
				}
			}
		}
		sort.Strings(res.MissingCollectors)
		sort.Strings(res.ExtraCollectors)

		if len(res.MissingCollectors) > 0 {
			r.logger.Warn(
				"canary baseline drift: missing collectors",
				"code", string(LogCodeCanaryMissing),
				"scan_id", scanID,
				"missing", res.MissingCollectors,
			)
			r.raiseIncident(ctx, scanID, model.IncidentCanaryDrift,
				"canary drift: missing collectors: "+strings.Join(res.MissingCollectors, ", "),
				&res)
		}
		if len(res.ExtraCollectors) > 0 {
			r.logger.Warn(
				"canary baseline drift: extra collectors",
				"code", string(LogCodeCanaryExtra),
				"scan_id", scanID,
				"extra", res.ExtraCollectors,
			)
			r.raiseIncident(ctx, scanID, model.IncidentCanaryDrift,
				"canary drift: unexpected collectors: "+strings.Join(res.ExtraCollectors, ", "),
				&res)
		}
	}

	r.logger.Info(
		"reconcile complete",
		"code", string(LogCodeReconcileComplete),
		"scan_id", scanID,
		"heartbeats_checked", res.HeartbeatsChecked,
		"bad_signatures", res.BadSignatures,
		"binary_hash_drift", res.BinaryHashDrift,
		"missing_collectors", len(res.MissingCollectors),
		"extra_collectors", len(res.ExtraCollectors),
		"incidents_raised", res.IncidentsRaised,
	)
	return res, nil
}

// raiseIncident persists one RuntimeIncident. A failure to insert is
// logged but tallied in BadSignatures/etc remains accurate because the
// res counter is incremented at the call site before this runs. Errors
// from InsertRuntimeIncident are deliberately swallowed: a downstream
// store outage must not block subsequent reconciliation work.
func (r *Reconciler) raiseIncident(
	ctx context.Context,
	scanID uuid.UUID,
	kind model.IncidentType,
	message string,
	res *ReconcileResult,
) {
	scanRunID := scanID
	inc := model.RuntimeIncident{
		ID:           uuid.Must(uuid.NewV7()),
		IncidentType: kind,
		Component:    "observability.reconciler",
		ErrorMessage: message,
		ScanRunID:    &scanRunID,
		Severity:     string(model.SeverityHigh),
		Recovered:    false,
		CreatedAt:    time.Now().UTC(),
	}
	if err := r.store.InsertRuntimeIncident(ctx, inc); err != nil {
		r.logger.Error(
			"reconciler incident persist failed",
			"code", string(LogCodeReconcileIncidentPersistFailed),
			"scan_id", scanID,
			"incident_type", kind,
			"error", err,
		)
		return
	}
	res.IncidentsRaised++
}
