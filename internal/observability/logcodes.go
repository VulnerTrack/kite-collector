// Package observability holds the synthetic-finding plumbing (heartbeat
// recording, canary baseline reconciliation, tamper detection) that turns
// silent collector failure into a loud signal.
package observability

// LogCode is the structured-log identifier for observability events. Same
// immutability rules as internal/safety/logcodes: codes are part of the
// public alerting contract and never renamed in place.
type LogCode string

const (
	LogCodeHeartbeatEmitted    LogCode = "observability.heartbeat.emitted"
	LogCodeHeartbeatPersistErr LogCode = "observability.heartbeat.persist_failed"
	LogCodeHeartbeatEmitErr    LogCode = "observability.heartbeat.emit_failed"

	LogCodeReconcileStart                 LogCode = "observability.reconcile.start"
	LogCodeReconcileComplete              LogCode = "observability.reconcile.complete"
	LogCodeReconcileIncidentPersistFailed LogCode = "observability.reconcile.incident_persist_failed"

	LogCodeTamperBadSignature LogCode = "observability.tamper.bad_signature"
	LogCodeTamperBinaryDrift  LogCode = "observability.tamper.binary_hash_drift"

	LogCodeCanaryMissing LogCode = "observability.canary.missing_collector"
	LogCodeCanaryExtra   LogCode = "observability.canary.extra_collector"
)
