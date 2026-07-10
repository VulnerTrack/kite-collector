package wazuh

// LogCode is the typed identifier attached to every structured log
// entry the Wazuh discovery package emits. Convention:
// `wazuh.<surface>.<event>` so downstream tooling (Loki/Splunk
// queries, alerting rules, runbooks) can pivot on a stable identifier
// without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- auth surface ------------------------------------------------
	LogCodeAuthDefaultCredentials LogCode = "wazuh.auth.default_credentials" //#nosec G101 -- log code identifier signalling default Wazuh API credentials are in use, not a credential value

	// --- enrich surface (per-agent enrichment fetches) ---------------
	LogCodeEnrichPackagesFailed        LogCode = "wazuh.enrich.packages_failed"
	LogCodeEnrichVulnerabilitiesFailed LogCode = "wazuh.enrich.vulnerabilities_failed"
	LogCodeEnrichSCAPoliciesFailed     LogCode = "wazuh.enrich.sca_policies_failed"
	LogCodeEnrichSCAChecksFailed       LogCode = "wazuh.enrich.sca_checks_failed"
	LogCodeEnrichPortsFailed           LogCode = "wazuh.enrich.ports_failed"
	LogCodeEnrichInterfacesFailed      LogCode = "wazuh.enrich.interfaces_failed"
	LogCodeEnrichAddressesFailed       LogCode = "wazuh.enrich.addresses_failed"

	// --- agents surface (agent listing) ------------------------------
	LogCodeAgentsSkipInvalidJSON LogCode = "wazuh.agents.skip_invalid_json"
)
