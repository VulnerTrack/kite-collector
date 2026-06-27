package enrollment

// LogCode is the typed identifier attached to every structured log
// entry the enrollment package emits. Convention:
// `enrollment.<surface>.<event>` so downstream tooling can pivot on
// a stable identifier without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// renewal surface — periodic cert-renewal manager
	LogCodeEnrollmentCertCheckFailed LogCode = "enrollment.renewal.cert_check_failed"

	// client surface — PKI enrollment client
	LogCodeEnrollmentStarting LogCode = "enrollment.client.starting"

	// keybackend surface — key-backend policy enforcement
	LogCodeEnrollmentKeyBackendBelowPolicy LogCode = "enrollment.keybackend.below_policy"
	LogCodeEnrollmentKeyBackendOK          LogCode = "enrollment.keybackend.meets_policy"
)
