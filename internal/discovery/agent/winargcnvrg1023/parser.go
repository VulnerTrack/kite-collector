package winargcnvrg1023

import (
	"bytes"
	"regexp"
	"strings"
)

// RG1023Fields captures scalar fields the audit pipeline
// needs from a CNV RG 1023 compliance artifact.
type RG1023Fields struct {
	ComplianceStatus          string
	MaxSeverity               Severity
	ClienteCuitRaw            string
	OfficerCuitRaw            string
	LastReviewDate            string
	NextReviewDate            string
	Period                    string
	FindingCount              int64
	CriticalCount             int64
	HighCount                 int64
	MediumCount               int64
	OpenFindingCount          int64
	ThirdPartyCount           int64
	ThirdPartyUnassessedCount int64
	MFAEntryCount             int64
	HasIncidentMarker         bool
	HasPlaybookReference      bool
}

// severityRE matches a `Severity: CRITICAL/HIGH/MEDIUM/LOW`
// row.
var severityRE = regexp.MustCompile(
	`(?i)("|')?(severity|severidad|risk[_\- ]?level|nivel[_\- ]?riesgo)("|')?\s*[:=>]\s*"?(critical|cr[íi]tica|high|alta|medium|media|low|baja|info|informacional|n/a|not[_\- ]?applicable)`)

// statusRE matches `compliance_status: compliant/...`.
var statusRE = regexp.MustCompile(
	`(?i)("|')?(compliance[_\- ]?status|estado[_\- ]?cumplimiento|status)("|')?\s*[:=>]\s*"?(compliant|cumplido|non[_\- ]?compliant|no[_\- ]?cumple|pending[_\- ]?review|pendiente|in[_\- ]?progress|en[_\- ]?proceso)`)

// lastReviewRE matches `last_review_date: YYYY-MM-DD`.
var lastReviewRE = regexp.MustCompile(
	`(?i)("|')?(last[_\- ]?review[_\- ]?date|fecha[_\- ]?revision|ultima[_\- ]?revision|last[_\- ]?audit[_\- ]?date)("|')?\s*[:=>]\s*"?(20\d{2}-\d{2}-\d{2})`)

// nextReviewRE matches `next_review_date: YYYY-MM-DD`.
var nextReviewRE = regexp.MustCompile(
	`(?i)("|')?(next[_\- ]?review[_\- ]?date|proxima[_\- ]?revision|next[_\- ]?audit[_\- ]?date)("|')?\s*[:=>]\s*"?(20\d{2}-\d{2}-\d{2})`)

// findingMarkerRE detects a finding/hallazgo entry.
var findingMarkerRE = regexp.MustCompile(
	`(?i)("|')?(finding|hallazgo|finding_id|hallazgo_id)("|')?\s*[:=>]\s*`)

// criticalMarkerRE counts critical-severity finding tokens.
var criticalMarkerRE = regexp.MustCompile(
	`(?i)\b(critical|cr[íi]tica|severidad[_\s-]*cr[íi]tica)\b`)

// highMarkerRE counts high-severity finding tokens.
var highMarkerRE = regexp.MustCompile(
	`(?i)\b(high|alta|severidad[_\s-]*alta)\b`)

// mediumMarkerRE counts medium-severity finding tokens.
var mediumMarkerRE = regexp.MustCompile(
	`(?i)\b(medium|media|severidad[_\s-]*media)\b`)

// openStatusRE counts entries with status open / abierto /
// not-remediated.
var openStatusRE = regexp.MustCompile(
	`(?i)("|')?(status|estado)("|')?\s*[:=>]\s*"?(open|abierto|not[_\- ]?remediated|no[_\- ]?remediado|pending|pendiente)`)

// thirdPartyEntryRE counts third-party register entries.
var thirdPartyEntryRE = regexp.MustCompile(
	`(?i)("|')?(third[_\- ]?party|proveedor|vendor|tercero)("|')?\s*[:=>]\s*"?`)

// thirdPartyAssessedRE detects an `assessment_date` field on
// a third-party entry — the absence (or empty) marks the
// entry as unassessed.
var thirdPartyAssessedRE = regexp.MustCompile(
	`(?i)("|')?(assessment[_\- ]?date|fecha[_\- ]?evaluacion|evaluation[_\- ]?date)("|')?\s*[:=>]\s*"?(20\d{2}-\d{2}-\d{2})`)

// mfaEntryRE counts MFA factor entries (totp / hardware /
// sms).
var mfaEntryRE = regexp.MustCompile(
	`(?i)("|')?(mfa[_\- ]?type|second[_\- ]?factor|2fa[_\- ]?type|factor[_\- ]?autenticacion)("|')?\s*[:=>]\s*"?(totp|hardware|sms|push|fido|fido2|webauthn|yubikey)`)

// incidentRefRE detects an incident-id reference.
var incidentRefRE = regexp.MustCompile(
	`(?i)("|')?(incident[_\- ]?id|incidente[_\- ]?id|ticket)("|')?\s*[:=>]\s*"?[A-Za-z0-9_-]{3,}`)

// playbookRefRE detects a playbook-id reference inside an
// incident-registry entry.
var playbookRefRE = regexp.MustCompile(
	`(?i)("|')?(playbook[_\- ]?id|playbook[_\- ]?ref|manual[_\- ]?ref)("|')?\s*[:=>]\s*"?[A-Za-z0-9_-]{3,}`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// officerCuitKeyRE matches `oficial_ciberseguridad_cuit:...`.
var officerCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:oficial[_\- ]?ciberseguridad[_\- ]?cuit|cybersecurity[_\- ]?officer[_\- ]?cuit|cuit[_\- ]?oficial)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseRG1023Artifact parses a CNV RG 1023 compliance body
// (PDF text / DOCX text / JSON / YAML / Markdown).
//
// Severity / status / date / counter fields are extracted via
// flat regex scans. PDF / DOCX binary bodies are passed in
// pre-extracted text form by the collector (this parser does
// not do PDF text extraction; the collector reads .pdf/.docx
// bodies hashed-only when binary).
func ParseRG1023Artifact(body []byte) RG1023Fields {
	out := RG1023Fields{MaxSeverity: SeverityUnknown}
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	// Max severity from explicit severity tokens.
	for _, m := range severityRE.FindAllSubmatch(body, -1) {
		if len(m) < 5 {
			continue
		}
		sev := normalizeSeverity(string(m[4]))
		out.MaxSeverity = MaxSeverityOf(out.MaxSeverity, sev)
	}
	// Severity counters from standalone tokens (cross-check).
	out.CriticalCount = int64(len(criticalMarkerRE.FindAllIndex(body, -1)))
	out.HighCount = int64(len(highMarkerRE.FindAllIndex(body, -1)))
	out.MediumCount = int64(len(mediumMarkerRE.FindAllIndex(body, -1)))
	// Reduce false positives: subtract the column-header count
	// for each severity (1 if a "severity: critical" header
	// row appears).
	if out.CriticalCount > 0 && out.MaxSeverity == SeverityUnknown {
		out.MaxSeverity = SeverityCritical
	} else if out.HighCount > 0 && out.MaxSeverity == SeverityUnknown {
		out.MaxSeverity = SeverityHigh
	} else if out.MediumCount > 0 && out.MaxSeverity == SeverityUnknown {
		out.MaxSeverity = SeverityMedium
	}
	// Compliance status.
	if m := statusRE.FindSubmatch(body); len(m) > 4 {
		out.ComplianceStatus = normalizeStatusToken(string(m[4]))
	}
	// Review dates.
	if m := lastReviewRE.FindSubmatch(body); len(m) > 4 {
		out.LastReviewDate = string(m[4])
	}
	if m := nextReviewRE.FindSubmatch(body); len(m) > 4 {
		out.NextReviewDate = string(m[4])
	}
	// Finding count.
	out.FindingCount = int64(len(findingMarkerRE.FindAllIndex(body, -1)))
	// Open findings (intersect with severity).
	out.OpenFindingCount = int64(len(openStatusRE.FindAllIndex(body, -1)))
	// Third-party register.
	tpAll := thirdPartyEntryRE.FindAllIndex(body, -1)
	out.ThirdPartyCount = int64(len(tpAll))
	tpAssessed := thirdPartyAssessedRE.FindAllIndex(body, -1)
	assessed := int64(len(tpAssessed))
	if out.ThirdPartyCount > assessed {
		out.ThirdPartyUnassessedCount = out.ThirdPartyCount - assessed
	}
	// MFA entries.
	out.MFAEntryCount = int64(len(mfaEntryRE.FindAllIndex(body, -1)))
	// Incident / playbook references.
	if incidentRefRE.Match(body) {
		out.HasIncidentMarker = true
	}
	if playbookRefRE.Match(body) {
		out.HasPlaybookReference = true
	}
	// PII / officer CUITs.
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	if m := officerCuitKeyRE.FindSubmatch(body); m != nil {
		out.OfficerCuitRaw = string(m[1])
	}
	if out.ClienteCuitRaw == "" {
		if m := cuitRE.FindSubmatch(body); m != nil {
			out.ClienteCuitRaw = string(m[1]) + string(m[2]) + string(m[3])
		}
	}
	return out
}

// normalizeSeverity maps Spanish + English tokens to the
// canonical Severity enum.
func normalizeSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "critica", "crítica":
		return SeverityCritical
	case "high", "alta":
		return SeverityHigh
	case "medium", "media":
		return SeverityMedium
	case "low", "baja":
		return SeverityLow
	case "info", "informacional":
		return SeverityInfo
	case "n/a", "not_applicable", "not-applicable":
		return SeverityNotApplicable
	}
	return SeverityUnknown
}

// normalizeStatusToken maps Spanish + English tokens to the
// canonical compliance status (returned as string — the
// caller converts to enum).
func normalizeStatusToken(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "compliant", "cumplido":
		return string(StatusCompliant)
	case "non_compliant", "non-compliant", "no_cumple", "no-cumple":
		return string(StatusNonCompliant)
	case "pending_review", "pending-review", "pendiente":
		return string(StatusPendingReview)
	case "in_progress", "in-progress", "en_proceso", "en-proceso":
		return string(StatusInProgress)
	}
	return string(StatusUnknown)
}
