// Package correlation provides a shared CPE-to-CVE matching library
// used by both the kite-collector agent (for local correlation) and
// the SaaS API (for server-side matching). See RFC-0077 §5.2.1.
package correlation

import "time"

// Request is a deduplicated set of CPE 2.3 identifiers submitted for
// CVE matching. Contains no asset identity — only software identifiers.
type Request struct {
	CPEs []string `json:"cpes"`
}

// Response contains CVE matches returned for a correlation request,
// grouped by CPE, with severity, exploitation status, and EPSS scores.
type Response struct {
	ComputedAt  time.Time  `json:"computed_at"`
	MaxSeverity string     `json:"max_severity"`
	Matches     []CPEMatch `json:"matches"`
	TotalCVEs   int        `json:"total_cves"`
}

// CPEMatch represents CVE matches for a single CPE 2.3 URI.
type CPEMatch struct {
	CPE         string   `json:"cpe"`
	MaxSeverity string   `json:"max_severity"`
	EOLDate     string   `json:"eol_date,omitempty"`
	CVEIDs      []string `json:"cve_ids"`
	MaxCVSSBase float64  `json:"max_cvss_base"`
	MaxEPSS     float64  `json:"max_epss"`
	CVECount    int      `json:"cve_count"`
	KEVFlagged  bool     `json:"kev_flagged"`
}

// LocalCorrelation maps API-returned CPE matches to a specific local host.
// The SaaS never sees this structure — it exists only on the agent.
type LocalCorrelation struct {
	Hostname    string     `json:"hostname"`
	AssetID     string     `json:"asset_id"`
	MaxSeverity string     `json:"max_severity"`
	Matches     []CPEMatch `json:"matches"`
	TotalCVEs   int        `json:"total_cves"`
}

// AggregateStats summarises correlation results for OTLP emission.
// Only these counts leave the agent — no asset identity data.
type AggregateStats struct {
	MaxSeverity     string `json:"max_severity"`
	TotalAssets     int    `json:"total_assets"`
	CriticalCVEs    int    `json:"critical_cves"`
	HighCVEs        int    `json:"high_cves"`
	MediumCVEs      int    `json:"medium_cves"`
	LowCVEs         int    `json:"low_cves"`
	KEVCount        int    `json:"kev_count"`
	AffectedAssets  int    `json:"affected_assets"`
	TotalUniqueCVEs int    `json:"total_unique_cves"`
}

// SeverityFromCVSS returns a severity label for a CVSS v3.1 base score.
func SeverityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}
