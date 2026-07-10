package identity

// LogCode is the typed identifier attached to every structured log
// entry the identity package emits. Convention:
// `identity.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// detect surface — key backend auto-detection / preference resolution
	LogCodeDetectTPMUnavailable     LogCode = "identity.detect.tpm_unavailable"
	LogCodeDetectKeyringUnavailable LogCode = "identity.detect.keyring_unavailable"

	// harden_linux surface — process hardening syscalls
	LogCodeHardenDumpableFailed LogCode = "identity.harden_linux.set_dumpable_failed"
	LogCodeHardenMlockallFailed LogCode = "identity.harden_linux.mlockall_failed"

	// lifecycle surface — LoadOrCreate / generate / populateBinaryHash
	LogCodeLifecycleStampExpectedHashFailed LogCode = "identity.lifecycle.stamp_expected_hash_failed"
	LogCodeLifecycleBinaryHashUnavailable   LogCode = "identity.lifecycle.binary_hash_unavailable"
	LogCodeLifecycleExpectedHashUnavailable LogCode = "identity.lifecycle.expected_hash_unavailable_first_boot"
)
