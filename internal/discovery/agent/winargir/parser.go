package winargir

import (
	"regexp"
	"strconv"
	"strings"
)

// IRFields captures scalar fields the audit pipeline needs from
// an IR artifact.
type IRFields struct {
	CNVFilingID            string
	IssuerName             string
	ClienteEmisorCuitRaw   string
	InsiderCuilRaw         string
	IssuerClass            IssuerClass
	DisclosurePhase        DisclosurePhase
	InsiderCount           int64
	AnalystCount           int64
	HasPassword            bool
	HasPrePublicationDraft bool
	HasCrossListedUSIssuer bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|ir[_\-]?password|autopista[_\-]?password|portal[_\-]?password)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|ir[_\-]?password|autopista[_\-]?password|portal[_\-]?password)\b"?\s*[:=]\s*["'][^"']{1,}["']`)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|ir[_\-]?password|autopista[_\-]?password)\s*>([^<]{1,})<\s*/`)

// cnvFilingIDRE matches a CNV Autopista filing-id field.
var cnvFilingIDRE = regexp.MustCompile(
	`(?i)"?(?:cnv[_\- ]?filing[_\- ]?id|nro[_\- ]?presentacion|filing[_\- ]?id|autopista[_\- ]?id|nro[_\- ]?autopista)"?\s*[:=>]\s*"?([A-Z0-9\-]{4,32})"?`)

// issuerNameRE matches the issuer name.
var issuerNameRE = regexp.MustCompile(
	`(?i)"?(?:issuer[_\- ]?name|emisor|company[_\- ]?name|denominacion|razon[_\- ]?social)"?\s*[:=>]\s*"?([A-Za-zÀ-ÿ0-9 .\-_&,']{4,80})"?`)

// issuerClassRE matches the issuer-class field.
var issuerClassRE = regexp.MustCompile(
	`(?i)"?(?:issuer[_\- ]?class|tipo[_\- ]?emisor|asset[_\- ]?class|panel)"?\s*[:=>]\s*"?([A-Za-z\-_ ]{4,40})`)

// disclosurePhaseRE matches an earnings-cycle phase field.
var disclosurePhaseRE = regexp.MustCompile(
	`(?i)"?(?:disclosure[_\- ]?phase|earnings[_\- ]?phase|quarter|fase[_\- ]?disclosure)"?\s*[:=>]\s*"?([A-Za-z0-9\-_ ]{1,30})`)

// prePublicationDraftRE matches DRAFT / RESERVADO / EYES-ONLY
// markers in pre-publication IR documents.
var prePublicationDraftRE = regexp.MustCompile(
	`(?im)\b(?:DRAFT|BORRADOR|PRELIMINARY|PRELIMINAR|FOR[_\- ]?DISCUSSION[_\- ]?ONLY|FOR[_\- ]?INTERNAL[_\- ]?USE|NOT[_\- ]?FOR[_\- ]?DISTRIBUTION|NO[_\- ]?CIRCULAR|INTERNO|INTERNAL[_\- ]?ONLY|EYES[_\- ]?ONLY|CONFIDENCIAL|CONFIDENTIAL|RESERVADO|EMBARGOED|BAJO[_\- ]?EMBARGO|MNPI)\b`)

// crossListedRE matches a cross-listed-issuer marker.
var crossListedRE = regexp.MustCompile(
	`(?i)\b(?:NYSE|NASDAQ|ADR|SEC[_\- ]?REGISTERED|20[_\- ]?F|6[_\- ]?K|REG[_\- ]?FD|SOX|cross[_\- ]?listed|us[_\- ]?listed|sec[_\- ]?filing)\b`)

// insiderCountRE matches an insider-count field.
var insiderCountRE = regexp.MustCompile(
	`(?i)"?(?:insider[_\- ]?count|cantidad[_\- ]?iniciados|nro[_\- ]?iniciados|total[_\- ]?insiders)"?\s*[:=>]\s*"?(\d{1,12})`)

// insiderRowRE matches a per-insider CSV row.
var insiderRowRE = regexp.MustCompile(
	`(?im)^[A-Z0-9\-]+,\d{2}-?\d{8}-?\d,`)

// analystCountRE matches an analyst-count field.
var analystCountRE = regexp.MustCompile(
	`(?i)"?(?:analyst[_\- ]?count|cantidad[_\- ]?analistas|nro[_\- ]?analistas)"?\s*[:=>]\s*"?(\d{1,12})`)

// clienteEmisorCuitKeyRE matches `cliente_emisor_cuit:
// NN-NNNNNNNN-N`.
var clienteEmisorCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?emisor[_\- ]?cuit|emisor[_\- ]?cuit|issuer[_\- ]?cuit|cuit[_\- ]?emisor|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// insiderCuilKeyRE matches `insider_cuil: NN-NNNNNNNN-N`.
var insiderCuilKeyRE = regexp.MustCompile(
	`(?i)"?(?:insider[_\- ]?cuil|iniciado[_\- ]?cuil|director[_\- ]?cuil|officer[_\- ]?cuil|cuil)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseHechoRelevanteDraft parses a hecho relevante draft body.
func ParseHechoRelevanteDraft(body []byte) IRFields {
	out := parseCommon(body)
	// HR drafts are always pre-publication.
	out.HasPrePublicationDraft = true
	return out
}

// ParseInsiderList parses an insider list body.
func ParseInsiderList(body []byte) IRFields {
	out := parseCommon(body)
	if m := insiderCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.InsiderCount = v
		}
	}
	if out.InsiderCount == 0 {
		out.InsiderCount = int64(len(insiderRowRE.FindAllIndex(body, -1)))
	}
	return out
}

// ParseEarningsCallScript parses an earnings call script body.
func ParseEarningsCallScript(body []byte) IRFields {
	return parseCommon(body)
}

// ParseEarningsCallQA parses an earnings call Q&A body.
func ParseEarningsCallQA(body []byte) IRFields {
	return parseCommon(body)
}

// ParsePressRelease parses a press release body.
func ParsePressRelease(body []byte) IRFields {
	return parseCommon(body)
}

// ParseAnalystReport parses an analyst report body.
func ParseAnalystReport(body []byte) IRFields {
	return parseCommon(body)
}

// ParseAnalystCoverageList parses an analyst coverage list body.
func ParseAnalystCoverageList(body []byte) IRFields {
	out := parseCommon(body)
	if m := analystCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.AnalystCount = v
		}
	}
	if out.AnalystCount == 0 {
		out.AnalystCount = int64(len(insiderRowRE.FindAllIndex(body, -1)))
	}
	return out
}

// ParseRoadshow parses a roadshow material body.
func ParseRoadshow(body []byte) IRFields {
	return parseCommon(body)
}

// ParseConferenceCallRecording parses a conference call recording.
//
// Audio bodies are typically opaque; we extract metadata only.
func ParseConferenceCallRecording(body []byte) IRFields {
	return parseCommon(body)
}

// ParseSustainabilityReport parses a sustainability report body.
func ParseSustainabilityReport(body []byte) IRFields {
	return parseCommon(body)
}

// ParseESGDisclosure parses an ESG disclosure body.
func ParseESGDisclosure(body []byte) IRFields {
	return parseCommon(body)
}

// ParseMemoriaAnual parses an annual report body.
func ParseMemoriaAnual(body []byte) IRFields {
	return parseCommon(body)
}

// ParseEstadosContablesPublic parses a public financials body.
func ParseEstadosContablesPublic(body []byte) IRFields {
	return parseCommon(body)
}

// ParseConflictDisclosure parses a conflict-of-interest letter
// body.
func ParseConflictDisclosure(body []byte) IRFields {
	return parseCommon(body)
}

// ParseConfig parses a generic IR-tool config body.
func ParseConfig(body []byte) IRFields {
	return parseCommon(body)
}

// parseCommon extracts the cross-cutting fields.
func parseCommon(body []byte) IRFields {
	var out IRFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := cnvFilingIDRE.FindSubmatch(body); len(m) > 1 {
		out.CNVFilingID = string(m[1])
	}
	if m := issuerNameRE.FindSubmatch(body); len(m) > 1 {
		out.IssuerName = strings.TrimSpace(string(m[1]))
	}
	if m := issuerClassRE.FindSubmatch(body); len(m) > 1 {
		out.IssuerClass = detectIssuerClass(string(m[1]))
	}
	if m := disclosurePhaseRE.FindSubmatch(body); len(m) > 1 {
		out.DisclosurePhase = detectDisclosurePhase(string(m[1]))
	}
	if prePublicationDraftRE.Match(body) {
		out.HasPrePublicationDraft = true
	}
	if crossListedRE.Match(body) {
		out.HasCrossListedUSIssuer = true
	}
	if c := clienteEmisorCuitFromBody(body); c != "" {
		out.ClienteEmisorCuitRaw = c
	}
	if c := insiderCuilFromBody(body); c != "" {
		out.InsiderCuilRaw = c
	}
	return out
}

// clienteEmisorCuitFromBody returns the first emisor CUIT match.
func clienteEmisorCuitFromBody(body []byte) string {
	if m := clienteEmisorCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// insiderCuilFromBody returns the first insider CUIL match.
func insiderCuilFromBody(body []byte) string {
	if m := insiderCuilKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectIssuerClass sniffs the issuer-class string.
func detectIssuerClass(s string) IssuerClass {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "panel lider") ||
		strings.Contains(t, "panel-lider") ||
		strings.Contains(t, "panel líder"):
		return IssuerPanelLider
	case strings.Contains(t, "panel general") ||
		strings.Contains(t, "panel-general"):
		return IssuerPanelGeneral
	case strings.Contains(t, "cedear"):
		return IssuerCEDEARIssuer
	case strings.Contains(t, "sub-sovereign") ||
		strings.Contains(t, "subnacional") ||
		strings.Contains(t, "provincia"):
		return IssuerSubSovereign
	case strings.Contains(t, "sovereign") ||
		strings.Contains(t, "soberano"):
		return IssuerSovereign
	case strings.Contains(t, "financial institution") ||
		strings.Contains(t, "bank") ||
		strings.Contains(t, "banco"):
		return IssuerFinancialInstitution
	case strings.Contains(t, "insurance") ||
		strings.Contains(t, "seguros") ||
		strings.Contains(t, "aseguradora"):
		return IssuerInsuranceCompany
	case strings.Contains(t, "fideicomiso") ||
		strings.Contains(t, "trust"):
		return IssuerFideicomisoFinanciero
	case strings.Contains(t, "pyme"):
		return IssuerPYME
	case strings.Contains(t, "cross listed") ||
		strings.Contains(t, "cross-listed") ||
		strings.Contains(t, "adr"):
		return IssuerCrossListedUSIssuer
	}
	return IssuerUnknown
}

// detectDisclosurePhase sniffs the phase string.
func detectDisclosurePhase(s string) DisclosurePhase {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "q1") || strings.Contains(t, "first quarter") ||
		strings.Contains(t, "primer trimestre"):
		return PhaseQ1
	case strings.Contains(t, "q2") || strings.Contains(t, "second quarter") ||
		strings.Contains(t, "segundo trimestre"):
		return PhaseQ2
	case strings.Contains(t, "q3") || strings.Contains(t, "third quarter") ||
		strings.Contains(t, "tercer trimestre"):
		return PhaseQ3
	case strings.Contains(t, "q4") || strings.Contains(t, "fourth quarter") ||
		strings.Contains(t, "cuarto trimestre"):
		return PhaseQ4
	case strings.Contains(t, "annual") || strings.Contains(t, "anual"):
		return PhaseAnnual
	case strings.Contains(t, "event") || strings.Contains(t, "evento"):
		return PhaseEventDriven
	case strings.Contains(t, "roadshow"):
		return PhaseRoadshow
	}
	return PhaseUnknown
}
