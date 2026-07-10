package winargacdi

import (
	"regexp"
	"strconv"
	"strings"
)

// ACDIFields captures scalar fields the audit pipeline needs.
type ACDIFields struct {
	ACDILicenseID                 string
	ClienteCuitRaw                string
	ClienteDNIRaw                 string
	FCIManager                    FCIManager
	ClientClassification          ClientClassification
	PLAFTRiskClass                PLAFTRiskClass
	SubscriptionAmountARSMillions int64
	RetrocessionBPS               int64
	CommissionTotalARSMillions    int64
	HasPassword                   bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|acdi[_\-]?password|distributor[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|acdi[_\-]?password|distributor[_\-]?password)\b"?\s*[:=]\s*["'][^"']{1,}["']`,
)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|acdi[_\-]?password|distributor[_\-]?password)\s*>([^<]{1,})<\s*/`,
)

// acdiLicenseIDRE matches CNV ACDI license identifier.
var acdiLicenseIDRE = regexp.MustCompile(
	`(?i)"?(?:acdi[_\- ]?license[_\- ]?id|cnv[_\- ]?acdi|nro[_\- ]?acdi|acdi[_\- ]?nro|license[_\- ]?id)"?\s*[:=>]\s*"?([A-Z0-9\-]{3,32})"?`,
)

// fciManagerRE matches an FCI manager name field.
var fciManagerRE = regexp.MustCompile(
	`(?i)"?(?:fci[_\- ]?manager|administradora|sociedad[_\- ]?gerente|asset[_\- ]?manager|administrador[_\- ]?fci)"?\s*[:=>]\s*"?([A-Za-z0-9 .\-_&]{3,60})`,
)

// classificationRE matches a client-classification field.
var classificationRE = regexp.MustCompile(
	`(?i)"?(?:client[_\- ]?classification|tipo[_\- ]?cliente|investor[_\- ]?type|categoria[_\- ]?cliente)"?\s*[:=>]\s*"?([A-Za-z\-_ ]{4,40})`,
)

// plaftRiskRE matches a PLA/FT risk-class field.
var plaftRiskRE = regexp.MustCompile(
	`(?i)"?(?:plaft[_\- ]?risk|uif[_\- ]?risk|riesgo[_\- ]?plaft|riesgo[_\- ]?uif|aml[_\- ]?risk)"?\s*[:=>]\s*"?([A-Za-z\-_ ]{3,30})`,
)

// subscriptionAmountRE matches subscription amount in ARS.
var subscriptionAmountRE = regexp.MustCompile(
	`(?i)"?(?:subscription[_\- ]?amount|monto[_\- ]?suscripcion|monto[_\- ]?suscripción|importe[_\- ]?suscripcion)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`,
)

// retrocessionBPSRE matches retrocession-fee basis points.
var retrocessionBPSRE = regexp.MustCompile(
	`(?i)"?(?:retrocession[_\- ]?bps|retrocesion[_\- ]?bps|retrocession[_\- ]?fee[_\- ]?bps|retro[_\- ]?bps)"?\s*[:=>]\s*"?(\d{1,5})(?:\s*bps)?`,
)

// commissionTotalRE matches a total-commission amount field.
var commissionTotalRE = regexp.MustCompile(
	`(?i)"?(?:commission[_\- ]?total|comision[_\- ]?total|honorarios[_\- ]?total|total[_\- ]?comisiones)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|titular[_\- ]?cuit|cuit[_\- ]?cliente|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// clienteDNIKeyRE matches `cliente_dni: NNNNNNNN`.
var clienteDNIKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?dni|titular[_\- ]?dni|dni[_\- ]?cliente|dni|documento)"?\s*[:=>]\s*"?(\d{7,8})"?`,
)

// ParseClientKYC parses a client KYC body.
func ParseClientKYC(body []byte) ACDIFields {
	return parseCommon(body)
}

// ParseSuitabilityAssessment parses a suitability body.
func ParseSuitabilityAssessment(body []byte) ACDIFields {
	return parseCommon(body)
}

// ParseFCISubscriptionOrder parses a subscription order body.
func ParseFCISubscriptionOrder(body []byte) ACDIFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, subscriptionAmountRE); ok {
		out.SubscriptionAmountARSMillions = v
	}
	return out
}

// ParseRetrocessionAgreement parses a retrocession agreement.
func ParseRetrocessionAgreement(body []byte) ACDIFields {
	out := parseCommon(body)
	if m := retrocessionBPSRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.RetrocessionBPS = v
		}
	}
	return out
}

// ParseDistributionAgreement parses a distribution agreement.
func ParseDistributionAgreement(body []byte) ACDIFields {
	return parseCommon(body)
}

// ParseQuarterlyCommissionReport parses a commission report.
func ParseQuarterlyCommissionReport(body []byte) ACDIFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, commissionTotalRE); ok {
		out.CommissionTotalARSMillions = v
	}
	return out
}

// ParseClientRiskProfile parses a risk-profile questionnaire.
func ParseClientRiskProfile(body []byte) ACDIFields {
	return parseCommon(body)
}

// ParsePLAFTClassification parses a PLA/FT classification body.
func ParsePLAFTClassification(body []byte) ACDIFields {
	return parseCommon(body)
}

// ParseConfig parses a generic ACDI-tool config body.
func ParseConfig(body []byte) ACDIFields {
	return parseCommon(body)
}

// parseCommon extracts the cross-cutting fields.
func parseCommon(body []byte) ACDIFields {
	var out ACDIFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := acdiLicenseIDRE.FindSubmatch(body); len(m) > 1 {
		out.ACDILicenseID = string(m[1])
	}
	if m := fciManagerRE.FindSubmatch(body); len(m) > 1 {
		out.FCIManager = detectFCIManager(string(m[1]))
	}
	if m := classificationRE.FindSubmatch(body); len(m) > 1 {
		out.ClientClassification = detectClassification(string(m[1]))
	}
	if m := plaftRiskRE.FindSubmatch(body); len(m) > 1 {
		out.PLAFTRiskClass = detectPLAFTRiskClass(string(m[1]))
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	if c := dniFromBody(body); c != "" {
		out.ClienteDNIRaw = c
	}
	return out
}

// cuitFromBody returns the first cliente CUIT match.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// dniFromBody returns the first cliente DNI match.
func dniFromBody(body []byte) string {
	if m := clienteDNIKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectFCIManager sniffs the FCI-manager name string.
func detectFCIManager(s string) FCIManager {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "cohen am") ||
		strings.Contains(t, "cohen asset"):
		return FCICohenAM
	case strings.Contains(t, "galileo"):
		return FCIGalileoAM
	case strings.Contains(t, "pellegrini"):
		return FCIPellegriniAM
	case strings.Contains(t, "sintesis"):
		return FCISintesisManaged
	case strings.Contains(t, "bbva"):
		return FCIBBVAAM
	case strings.Contains(t, "galicia"):
		return FCIGaliciaAM
	case strings.Contains(t, "santander"):
		return FCISantanderAM
	case strings.Contains(t, "itau") || strings.Contains(t, "itaú"):
		return FCIItauAM
	case strings.Contains(t, "adcap"):
		return FCIAdcapAM
	case strings.Contains(t, "mariva"):
		return FCIMarivaAM
	case strings.Contains(t, "schweber"):
		return FCISchweber
	}
	return FCIUnknown
}

// detectClassification sniffs the client-classification string.
func detectClassification(s string) ClientClassification {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "retail") || strings.Contains(t, "minorista"):
		return ClassRetail
	case strings.Contains(t, "professional") ||
		strings.Contains(t, "profesional"):
		return ClassProfessional
	case strings.Contains(t, "qualified") ||
		strings.Contains(t, "calificado"):
		return ClassQualifiedInvestor
	case strings.Contains(t, "institutional") ||
		strings.Contains(t, "institucional"):
		return ClassInstitutional
	case strings.Contains(t, "knowledgeable") ||
		strings.Contains(t, "informado"):
		return ClassKnowledgeableCounterparty
	}
	return ClassUnknown
}

// detectPLAFTRiskClass sniffs the PLA/FT risk-class string.
func detectPLAFTRiskClass(s string) PLAFTRiskClass {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "peps") || strings.Contains(t, "pep"):
		return PLAFTPEPs
	case strings.Contains(t, "high") || strings.Contains(t, "alto"):
		return PLAFTHigh
	case strings.Contains(t, "medium") || strings.Contains(t, "medio"):
		return PLAFTMedium
	case strings.Contains(t, "low") || strings.Contains(t, "bajo"):
		return PLAFTLow
	case strings.Contains(t, "beneficial") || strings.Contains(t, "beneficiario"):
		return PLAFTBeneficialOwnerUnclear
	}
	return PLAFTUnknown
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
