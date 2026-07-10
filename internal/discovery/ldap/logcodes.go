package ldap

// LogCode is the typed identifier attached to every structured log
// entry the LDAP discovery package emits. Convention:
// `ldap.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- search surface (computer object enumeration) ----------------
	LogCodeSearchSkipMalformedEntry LogCode = "ldap.search.skip_malformed_entry"
	LogCodeSearchMaxObjectsTripped  LogCode = "ldap.search.max_objects_tripped"

	// --- dial surface (DC connection attempts) -----------------------
	LogCodeDialFailedNextDC LogCode = "ldap.dial.failed_next_dc"
)
