package connectorkit

// LogCode is the typed identifier attached to structured log records emitted
// by connectorkit, following the component.process.event convention pinned
// by the logcodes tests in other packages.
type LogCode string

const (
	// LogCodeEnvUnresolved is emitted when a declared *_env indirection
	// (RFC-0153) names an environment variable that is unset or empty at
	// credential-load time. The connector proceeds with its normal
	// missing-credential skip; this warning is the operator's signal that a
	// deployment forgot to inject the secret.
	LogCodeEnvUnresolved LogCode = "connectorkit.credentials.env_unresolved"

	// LogCodeEnvWhitespace is emitted when a credential resolved through
	// *_env indirection carries leading or trailing whitespace — almost
	// always a trailing newline from file-based injection (echo/cat into
	// EnvironmentFile). The value is used verbatim, so downstream auth
	// failures with this warning present point at the injection pipeline.
	LogCodeEnvWhitespace LogCode = "connectorkit.credentials.env_whitespace"
)
