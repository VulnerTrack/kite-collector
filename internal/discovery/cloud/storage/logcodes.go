package storage

// LogCode is the typed identifier attached to every structured log
// entry the cloud storage fingerprint discovery package emits.
// Convention: `cloud_storage.<surface>.<event>` so downstream tooling
// (Loki/Splunk queries, alerting rules, runbooks) can pivot on a
// stable identifier without parsing freeform message text.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- signatures surface (signature catalogue loading) ------------
	LogCodeSignaturesLoadFailed LogCode = "cloud_storage.signatures.load_failed"

	// --- crawl surface (page + direct-target probing) ----------------
	LogCodeCrawlPageFailed        LogCode = "cloud_storage.crawl.page_failed"
	LogCodeCrawlScriptProbeFailed LogCode = "cloud_storage.crawl.script_probe_failed"
	LogCodeCrawlDirectProbeFailed LogCode = "cloud_storage.crawl.direct_probe_failed"
)
