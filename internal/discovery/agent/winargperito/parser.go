package winargperito

import (
	"regexp"
	"strconv"
	"strings"
)

// PeritoFields captures scalar fields the audit pipeline needs
// from a perito artifact.
type PeritoFields struct {
	EngagementID           string
	ClientName             string
	ClienteEmisorCuitRaw   string
	AuditorCuilRaw         string
	AuditFirm              AuditFirm
	ClientClass            ClientClass
	AuditPhase             AuditPhase
	ConfirmationCount      int64
	DeficiencyCount        int64
	AuditFeeARSMillions    int64
	NonAuditFeeARSMillions int64
	WorkpaperCount         int64
	HasPassword            bool
	HasDraftMarker         bool
	HasCrossListedUSIssuer bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|auditor[_\-]?password|portal[_\-]?password|workpaper[_\-]?password)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|auditor[_\-]?password|portal[_\-]?password|workpaper[_\-]?password)\b"?\s*[:=]\s*["'][^"']{1,}["']`)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|auditor[_\-]?password|portal[_\-]?password)\s*>([^<]{1,})<\s*/`)

// engagementIDRE matches an engagement identifier.
var engagementIDRE = regexp.MustCompile(
	`(?i)"?(?:engagement[_\- ]?id|nro[_\- ]?engagement|engagement[_\- ]?number|client[_\- ]?engagement)"?\s*[:=>]\s*"?([A-Z0-9\-]{4,32})"?`)

// clientNameRE matches the client name.
var clientNameRE = regexp.MustCompile(
	`(?i)"?(?:client[_\- ]?name|nombre[_\- ]?cliente|client|cliente)"?\s*[:=>]\s*"?([A-Za-zÀ-ÿ0-9 .\-_&,]{4,80})"?`)

// auditFirmRE matches the audit-firm self-identification.
var auditFirmRE = regexp.MustCompile(
	`(?i)"?(?:audit[_\- ]?firm|auditor[_\- ]?firm|firma[_\- ]?auditora|estudio[_\- ]?contable)"?\s*[:=>]\s*"?([A-Za-z0-9 .\-_&]{3,40})`)

// clientClassRE matches the client-class field.
var clientClassRE = regexp.MustCompile(
	`(?i)"?(?:client[_\- ]?class|tipo[_\- ]?cliente|asset[_\- ]?class)"?\s*[:=>]\s*"?([A-Za-z\-_ ]{4,40})`)

// auditPhaseRE matches an audit-phase indicator.
var auditPhaseRE = regexp.MustCompile(
	`(?i)"?(?:audit[_\- ]?phase|fase[_\- ]?auditoria|phase|fase)"?\s*[:=>]\s*"?([A-Za-z\-_ ]{4,30})`)

// draftMarkerRE matches DRAFT / RESERVADO / CONFIDENCIAL / etc.
var draftMarkerRE = regexp.MustCompile(
	`(?im)\b(?:DRAFT|BORRADOR|RESERVADO|RESTRICTED|CONFIDENCIAL|CONFIDENTIAL|FOR[_\- ]?INTERNAL[_\- ]?USE[_\- ]?ONLY|NOT[_\- ]?FOR[_\- ]?DISTRIBUTION|NO[_\- ]?CIRCULAR|PRELIMINARY|PRELIMINAR|INTERNO|INTERNAL[_\- ]?ONLY|EYES[_\- ]?ONLY)\b`)

// confirmationCountRE matches a confirmation count field.
var confirmationCountRE = regexp.MustCompile(
	`(?i)"?(?:confirmation[_\- ]?count|cantidad[_\- ]?confirmaciones|nro[_\- ]?confirmaciones)"?\s*[:=>]\s*"?(\d{1,12})`)

// confirmationRowRE matches a per-confirmation CSV row.
var confirmationRowRE = regexp.MustCompile(
	`(?im)^(?:CONF|CONFIRM)[_\- ]?\d+,`)

// deficiencyCountRE matches an internal-control-deficiency count.
var deficiencyCountRE = regexp.MustCompile(
	`(?i)"?(?:deficiency[_\- ]?count|deficiencias[_\- ]?count|nro[_\- ]?deficiencias|control[_\- ]?weakness[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`)

// deficiencyRowRE matches a per-deficiency CSV row.
var deficiencyRowRE = regexp.MustCompile(
	`(?im)^(?:DEF|DEFICIENCY)[_\- ]?\d+,`)

// auditFeeRE matches the audit fee amount. Word-boundary
// anchored to avoid matching `non_audit_fee` as `audit_fee`.
var auditFeeRE = regexp.MustCompile(
	`(?i)"?\b(?:audit[_\- ]?fee|honorarios[_\- ]?auditoria)\b"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`)

// nonAuditFeeRE matches the non-audit fee amount (tax-advisory,
// consulting, M&A advisory side-engagement).
var nonAuditFeeRE = regexp.MustCompile(
	`(?i)"?\b(?:non[_\- ]?audit[_\- ]?fee|tax[_\- ]?advisory[_\- ]?fee|consulting[_\- ]?fee|advisory[_\- ]?fee|honorarios[_\- ]?asesoria|honorarios[_\- ]?consultoria)\b"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`)

// workpaperCountRE matches a workpaper count.
var workpaperCountRE = regexp.MustCompile(
	`(?i)"?(?:workpaper[_\- ]?count|papeles[_\- ]?trabajo[_\- ]?count|cantidad[_\- ]?papeles)"?\s*[:=>]\s*"?(\d{1,12})`)

// clienteEmisorCuitKeyRE matches `cliente_emisor_cuit: NN-NNNNNNNN-N`.
var clienteEmisorCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cliente[_\- ]?emisor[_\- ]?cuit|emisor[_\- ]?cuit|client[_\- ]?cuit|cuit[_\- ]?cliente|cuit[_\- ]?emisor|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// auditorCuilKeyRE matches `auditor_cuil: NN-NNNNNNNN-N`.
var auditorCuilKeyRE = regexp.MustCompile(
	`(?i)"?(?:auditor[_\- ]?cuil|cuil[_\- ]?auditor|engagement[_\- ]?partner[_\- ]?cuil|partner[_\- ]?cuil|cuil)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// crossListedRE matches a marker for US-cross-listed issuers
// (PCAOB-relevant).
var crossListedRE = regexp.MustCompile(
	`(?i)\b(?:NYSE|NASDAQ|ADR|PCAOB|SOX|SARBANES[_\- ]?OXLEY|cross[_\- ]?listed|us[_\- ]?listed)\b`)

// ParseWorkpaper parses a working paper body.
func ParseWorkpaper(body []byte) PeritoFields {
	out := parseCommon(body)
	if m := workpaperCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.WorkpaperCount = v
		}
	}
	return out
}

// ParseEngagementLetter parses an engagement letter body.
func ParseEngagementLetter(body []byte) PeritoFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, auditFeeRE); ok {
		out.AuditFeeARSMillions = v
	}
	if v, ok := sumARSMillions(body, nonAuditFeeRE); ok {
		out.NonAuditFeeARSMillions = v
	}
	return out
}

// ParseInternalControlAssessment parses an ICA body.
func ParseInternalControlAssessment(body []byte) PeritoFields {
	return parseCommon(body)
}

// ParseConfirmationBank parses a bank confirmation response body.
func ParseConfirmationBank(body []byte) PeritoFields {
	out := parseCommon(body)
	if m := confirmationCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.ConfirmationCount = v
		}
	}
	if out.ConfirmationCount == 0 {
		out.ConfirmationCount = int64(len(confirmationRowRE.FindAllIndex(body, -1)))
	}
	return out
}

// ParseConfirmationBrokerage parses a brokerage confirmation body.
func ParseConfirmationBrokerage(body []byte) PeritoFields {
	return ParseConfirmationBank(body)
}

// ParseConfirmationLegal parses a legal-counsel confirmation body.
func ParseConfirmationLegal(body []byte) PeritoFields {
	return ParseConfirmationBank(body)
}

// ParseLetterRepresentations parses a management rep letter body.
func ParseLetterRepresentations(body []byte) PeritoFields {
	return parseCommon(body)
}

// ParseInternalControlDeficiency parses an ICDR body.
func ParseInternalControlDeficiency(body []byte) PeritoFields {
	out := parseCommon(body)
	if m := deficiencyCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.DeficiencyCount = v
		}
	}
	if out.DeficiencyCount == 0 {
		out.DeficiencyCount = int64(len(deficiencyRowRE.FindAllIndex(body, -1)))
	}
	return out
}

// ParseAuditFeeSchedule parses an audit fee schedule body.
func ParseAuditFeeSchedule(body []byte) PeritoFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, auditFeeRE); ok {
		out.AuditFeeARSMillions = v
	}
	if v, ok := sumARSMillions(body, nonAuditFeeRE); ok {
		out.NonAuditFeeARSMillions = v
	}
	return out
}

// ParseAuditCommitteeMinutes parses an AC minutes body.
func ParseAuditCommitteeMinutes(body []byte) PeritoFields {
	return parseCommon(body)
}

// ParseManagementLetter parses a mgmt letter body.
func ParseManagementLetter(body []byte) PeritoFields {
	return parseCommon(body)
}

// ParseAuditPlan parses an audit plan body.
func ParseAuditPlan(body []byte) PeritoFields {
	out := parseCommon(body)
	if m := workpaperCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.WorkpaperCount = v
		}
	}
	return out
}

// ParseGoingConcernOpinion parses a going-concern opinion body.
func ParseGoingConcernOpinion(body []byte) PeritoFields {
	return parseCommon(body)
}

// ParseSOCRelianceReport parses an SOC 1/2 reliance report body.
func ParseSOCRelianceReport(body []byte) PeritoFields {
	return parseCommon(body)
}

// ParseSubsequentEventsReview parses a SE review body.
func ParseSubsequentEventsReview(body []byte) PeritoFields {
	return parseCommon(body)
}

// ParseConfig parses a generic auditor-tool config body.
func ParseConfig(body []byte) PeritoFields {
	return parseCommon(body)
}

// parseCommon extracts the cross-cutting fields.
func parseCommon(body []byte) PeritoFields {
	var out PeritoFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := engagementIDRE.FindSubmatch(body); len(m) > 1 {
		out.EngagementID = string(m[1])
	}
	if m := clientNameRE.FindSubmatch(body); len(m) > 1 {
		out.ClientName = strings.TrimSpace(string(m[1]))
	}
	if m := auditFirmRE.FindSubmatch(body); len(m) > 1 {
		out.AuditFirm = detectAuditFirm(string(m[1]))
	}
	if m := clientClassRE.FindSubmatch(body); len(m) > 1 {
		out.ClientClass = detectClientClass(string(m[1]))
	}
	if m := auditPhaseRE.FindSubmatch(body); len(m) > 1 {
		out.AuditPhase = detectAuditPhase(string(m[1]))
	}
	if draftMarkerRE.Match(body) {
		out.HasDraftMarker = true
	}
	if crossListedRE.Match(body) {
		out.HasCrossListedUSIssuer = true
	}
	if c := clienteEmisorCuitFromBody(body); c != "" {
		out.ClienteEmisorCuitRaw = c
	}
	if c := auditorCuilFromBody(body); c != "" {
		out.AuditorCuilRaw = c
	}
	return out
}

// clienteEmisorCuitFromBody returns the first issuer CUIT match.
func clienteEmisorCuitFromBody(body []byte) string {
	if m := clienteEmisorCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// auditorCuilFromBody returns the first auditor CUIL match.
func auditorCuilFromBody(body []byte) string {
	if m := auditorCuilKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectAuditFirm sniffs the audit-firm name string.
func detectAuditFirm(s string) AuditFirm {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "pwc") ||
		strings.Contains(t, "pricewaterhousecoopers"):
		return FirmPwCArgentina
	case strings.Contains(t, "deloitte"):
		return FirmDeloitteArgentina
	case strings.Contains(t, "ernst") ||
		strings.Contains(t, "ernst young") ||
		strings.Contains(t, "ey "):
		return FirmEYArgentina
	case strings.Contains(t, "kpmg"):
		return FirmKPMGArgentina
	case strings.Contains(t, "bdo"):
		return FirmBDOArgentina
	case strings.Contains(t, "grant thornton"):
		return FirmGrantThorntonArgentina
	case strings.Contains(t, "crowe"):
		return FirmCroweArgentina
	case strings.Contains(t, "baker tilly"):
		return FirmBakerTillyArgentina
	case strings.Contains(t, "estudio"):
		return FirmLocalMidTier
	}
	return FirmUnknown
}

// detectClientClass sniffs the client-class string.
func detectClientClass(s string) ClientClass {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "fideicomiso") ||
		strings.Contains(t, "trust"):
		return ClientFideicomisoFinanciero
	case strings.Contains(t, "alyc") ||
		strings.Contains(t, "broker dealer") ||
		strings.Contains(t, "broker-dealer"):
		return ClientALYCBrokerDealer
	case strings.Contains(t, "insurance") ||
		strings.Contains(t, "seguros") ||
		strings.Contains(t, "aseguradora"):
		return ClientInsuranceCompany
	case strings.Contains(t, "bank") || strings.Contains(t, "banco"):
		return ClientBank
	case strings.Contains(t, "fci") ||
		strings.Contains(t, "fondo comun"):
		return ClientFCIMutualFund
	case strings.Contains(t, "pyme"):
		return ClientPYME
	case strings.Contains(t, "cross listed") ||
		strings.Contains(t, "cross-listed") ||
		strings.Contains(t, "adr"):
		return ClientCrossListedUSIssuer
	case strings.Contains(t, "cnv") ||
		strings.Contains(t, "listed company") ||
		strings.Contains(t, "emisora cnv"):
		return ClientCNVListedCompany
	}
	return ClientUnknown
}

// detectAuditPhase sniffs the audit-phase string.
func detectAuditPhase(s string) AuditPhase {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "planning") || strings.Contains(t, "planificacion"):
		return PhasePlanning
	case strings.Contains(t, "interim") || strings.Contains(t, "intermedio"):
		return PhaseInterim
	case strings.Contains(t, "year-end") || strings.Contains(t, "year end") ||
		strings.Contains(t, "cierre"):
		return PhaseYearEnd
	case strings.Contains(t, "reporting") || strings.Contains(t, "reporte"):
		return PhaseReporting
	case strings.Contains(t, "subsequent") || strings.Contains(t, "posteriores"):
		return PhaseSubsequentEvents
	case strings.Contains(t, "quality review") ||
		strings.Contains(t, "revision calidad"):
		return PhaseQualityReview
	}
	return PhaseUnknown
}

// sumARSMillions totals ARS amounts (returns millions).
func sumARSMillions(body []byte, re *regexp.Regexp) (int64, bool) {
	var sum int64
	found := false
	for _, m := range re.FindAllSubmatch(body, -1) {
		if len(m) <= 1 {
			continue
		}
		raw := strings.ReplaceAll(string(m[1]), ".", "")
		raw = strings.ReplaceAll(raw, ",", "")
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			sum += v
			found = true
		}
	}
	return sum / 1_000_000, found
}
