package safenet

// LogCode is the typed identifier attached to every structured log
// entry the safenet package emits. Convention:
// `safenet.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// tls surface — TLS configuration warnings
	LogCodeTLSVerificationDisabled LogCode = "safenet.tls.verification_disabled"

	// env surface — env-var parse failures and goroutine panic recovery
	LogCodeEnvInvalidBool    LogCode = "safenet.env.invalid_bool"
	LogCodeEnvInvalidInt     LogCode = "safenet.env.invalid_int"
	LogCodeEnvGoroutinePanic LogCode = "safenet.env.goroutine_panic_recovered"

	// scope_guard surface — runtime scanner safety clamps
	LogCodeScopeGuardConcurrencyClamped LogCode = "safenet.scope_guard.concurrency_clamped"
	LogCodeScopeGuardInvalidIntEnv      LogCode = "safenet.scope_guard.invalid_int_env"
)
