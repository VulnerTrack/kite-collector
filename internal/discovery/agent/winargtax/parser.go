package winargtax

import (
	"regexp"
	"strconv"
	"strings"
)

// TaxFields captures scalar fields the audit pipeline needs.
type TaxFields struct {
	EngagementID            string
	ClientName              string
	AFIPFilingID            string
	ClienteCuitRaw          string
	LawyerCuilRaw           string
	TaxFirm                 TaxFirm
	TaxRole                 TaxRole
	TaxRegime               TaxRegime
	BillableHoursCount      int64
	HNWThresholdARSMillions int64
	TaxReserveARSMillions   int64
	HasPassword             bool
	HasPrePublicationDraft  bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|tax[_\-]?password|afip[_\-]?password|taxit[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|tax[_\-]?password|afip[_\-]?password|taxit[_\-]?password)\b"?\s*[:=]\s*["'][^"']{1,}["']`,
)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|tax[_\-]?password|afip[_\-]?password)\s*>([^<]{1,})<\s*/`,
)

// engagementIDRE matches a tax engagement identifier.
var engagementIDRE = regexp.MustCompile(
	`(?i)"?(?:engagement[_\- ]?id|nro[_\- ]?engagement|client[_\- ]?engagement|tax[_\- ]?engagement[_\- ]?id)"?\s*[:=>]\s*"?([A-Z0-9\-]{4,32})"?`,
)

// clientNameRE matches the client name.
var clientNameRE = regexp.MustCompile(
	`(?i)"?(?:client[_\- ]?name|nombre[_\- ]?cliente|client|cliente)"?\s*[:=>]\s*"?([A-Za-zÀ-ÿ0-9 .\-_&,]{4,80})"?`,
)

// afipFilingIDRE matches an AFIP filing-receipt identifier.
var afipFilingIDRE = regexp.MustCompile(
	`(?i)"?(?:afip[_\- ]?filing[_\- ]?id|presentacion[_\- ]?afip|nro[_\- ]?afip|afip[_\- ]?receipt)"?\s*[:=>]\s*"?([A-Z0-9\-]{4,32})"?`,
)

// taxFirmRE matches the tax-firm self-identification.
var taxFirmRE = regexp.MustCompile(
	`(?i)"?(?:tax[_\- ]?firm|tax[_\- ]?advisor|firma[_\- ]?fiscal|estudio[_\- ]?fiscal)"?\s*[:=>]\s*"?([A-Za-z0-9 .\-_&]{3,60})`,
)

// taxRoleRE matches the tax-role field.
var taxRoleRE = regexp.MustCompile(
	`(?i)"?(?:tax[_\- ]?role|rol[_\- ]?fiscal|role)"?\s*[:=>]\s*"?([A-Za-z\-_ ]{4,40})`,
)

// taxRegimeRE matches a tax-regime field. Char class includes
// `.` for "Ley 23.576" / "Ley 27.430" patterns.
var taxRegimeRE = regexp.MustCompile(
	`(?i)"?(?:tax[_\- ]?regime|regimen[_\- ]?fiscal|régimen[_\- ]?fiscal|impuesto)"?\s*[:=>]\s*"?([A-Za-z0-9\-_. ]{4,40})`,
)

// prePublicationDraftRE matches DRAFT / RESERVADO / EYES-ONLY
// markers in pre-publication tax documents.
var prePublicationDraftRE = regexp.MustCompile(
	`(?im)\b(?:DRAFT|BORRADOR|RESERVADO|RESTRICTED|CONFIDENCIAL|CONFIDENTIAL|FOR[_\- ]?DISCUSSION[_\- ]?ONLY|FOR[_\- ]?INTERNAL[_\- ]?USE|NOT[_\- ]?FOR[_\- ]?DISTRIBUTION|NO[_\- ]?CIRCULAR|PRELIMINARY|PRELIMINAR|INTERNO|EYES[_\- ]?ONLY|PRIVILEGED|TAX[_\- ]?ADVICE[_\- ]?ONLY)\b`,
)

// billableHoursRE matches a billable-hours total field.
var billableHoursRE = regexp.MustCompile(
	`(?i)"?(?:billable[_\- ]?hours|horas[_\- ]?facturables|total[_\- ]?hours|hours[_\- ]?total)"?\s*[:=>]\s*"?(\d{1,6}(?:[.,]\d+)?)`,
)

// hnwThresholdRE matches the BP filing total wealth amount.
var hnwThresholdRE = regexp.MustCompile(
	`(?i)"?(?:bp[_\- ]?total|bienes[_\- ]?personales[_\- ]?total|total[_\- ]?bienes|patrimonio[_\- ]?total|total[_\- ]?patrimonio)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`,
)

// taxReserveRE matches a FIN 48 / IAS 12 tax-reserve field.
var taxReserveRE = regexp.MustCompile(
	`(?i)"?(?:tax[_\- ]?reserve|reserva[_\- ]?fiscal|provision[_\- ]?fiscal|fin[_\- ]?48[_\- ]?reserve)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|titular[_\- ]?cuit|cuit[_\- ]?cliente|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// lawyerCuilKeyRE matches `lawyer_cuil: NN-NNNNNNNN-N`.
var lawyerCuilKeyRE = regexp.MustCompile(
	`(?i)"?(?:tax[_\- ]?advisor[_\- ]?cuil|lawyer[_\- ]?cuil|partner[_\- ]?cuil|asesor[_\- ]?cuil|cuil)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseFiscalOpinion parses a fiscal opinion body.
func ParseFiscalOpinion(body []byte) TaxFields {
	return parseCommon(body)
}

// ParseTransferPricingMemo parses a TP memo body.
func ParseTransferPricingMemo(body []byte) TaxFields {
	return parseCommon(body)
}

// ParseAFIPRG5193Filing parses an RG 5193 filing body.
func ParseAFIPRG5193Filing(body []byte) TaxFields {
	return parseCommon(body)
}

// ParseBienesPersonalesFiling parses a BP filing body.
func ParseBienesPersonalesFiling(body []byte) TaxFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, hnwThresholdRE); ok {
		out.HNWThresholdARSMillions = v
	}
	return out
}

// ParseAFIPF8125 parses an F.8125 cross-border body.
func ParseAFIPF8125(body []byte) TaxFields {
	return parseCommon(body)
}

// ParseArgentinaFATCA parses an AR FATCA filing body.
func ParseArgentinaFATCA(body []byte) TaxFields {
	return parseCommon(body)
}

// ParseRegimenIndustrial parses a RIPRO tax-position body.
func ParseRegimenIndustrial(body []byte) TaxFields {
	return parseCommon(body)
}

// ParseTaxLitigationDefense parses a tax-litigation defense body.
func ParseTaxLitigationDefense(body []byte) TaxFields {
	return parseCommon(body)
}

// ParseFiscalizacionResponse parses an AFIP audit response body.
func ParseFiscalizacionResponse(body []byte) TaxFields {
	return parseCommon(body)
}

// ParseTaxPositionUncertainty parses a FIN 48 reserve body.
func ParseTaxPositionUncertainty(body []byte) TaxFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, taxReserveRE); ok {
		out.TaxReserveARSMillions = v
	}
	return out
}

// ParseEngagementLetterTax parses a tax engagement letter body.
func ParseEngagementLetterTax(body []byte) TaxFields {
	return parseCommon(body)
}

// ParseBillableHoursTax parses a tax billable-hours CSV body.
func ParseBillableHoursTax(body []byte) TaxFields {
	out := parseCommon(body)
	if m := billableHoursRE.FindSubmatch(body); len(m) > 1 {
		raw := strings.ReplaceAll(string(m[1]), ",", "")
		if dotIdx := strings.IndexByte(raw, '.'); dotIdx >= 0 {
			raw = raw[:dotIdx]
		}
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			out.BillableHoursCount = v
		}
	}
	return out
}

// ParseConfig parses a generic tax-tool config body.
func ParseConfig(body []byte) TaxFields {
	return parseCommon(body)
}

// parseCommon extracts the cross-cutting fields.
func parseCommon(body []byte) TaxFields {
	var out TaxFields
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
	if m := afipFilingIDRE.FindSubmatch(body); len(m) > 1 {
		out.AFIPFilingID = string(m[1])
	}
	if m := taxFirmRE.FindSubmatch(body); len(m) > 1 {
		out.TaxFirm = detectTaxFirm(string(m[1]))
	}
	if m := taxRoleRE.FindSubmatch(body); len(m) > 1 {
		out.TaxRole = detectTaxRole(string(m[1]))
	}
	if m := taxRegimeRE.FindSubmatch(body); len(m) > 1 {
		out.TaxRegime = detectTaxRegime(string(m[1]))
	}
	if prePublicationDraftRE.Match(body) {
		out.HasPrePublicationDraft = true
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	if c := cuilFromBody(body); c != "" {
		out.LawyerCuilRaw = c
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

// cuilFromBody returns the first lawyer CUIL match.
func cuilFromBody(body []byte) string {
	if m := lawyerCuilKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectTaxFirm sniffs the tax-firm name string.
func detectTaxFirm(s string) TaxFirm {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "pwc") ||
		strings.Contains(t, "pricewaterhousecoopers"):
		return FirmPwCTaxArgentina
	case strings.Contains(t, "deloitte"):
		return FirmDeloitteTaxArgentina
	case strings.Contains(t, "ernst") || strings.Contains(t, "ey "):
		return FirmEYTaxArgentina
	case strings.Contains(t, "kpmg"):
		return FirmKPMGTaxArgentina
	case strings.Contains(t, "bdo"):
		return FirmBDOTaxArgentina
	case strings.Contains(t, "beccar varela") ||
		strings.Contains(t, "beccar-varela"):
		return FirmBeccarVarelaTax
	case strings.Contains(t, "bruchou"):
		return FirmBruchouTax
	case strings.Contains(t, "pagbam") ||
		strings.Contains(t, "perez alati") ||
		strings.Contains(t, "pérez alati"):
		return FirmPAGBAMTax
	case strings.Contains(t, "lisicki"):
		return FirmLisickiLitvin
	case strings.Contains(t, "pistrelli") ||
		strings.Contains(t, "henry martin"):
		return FirmPistrelliHenryMartin
	case strings.Contains(t, "diaz sieiro") ||
		strings.Contains(t, "díaz sieiro"):
		return FirmDiazSieiro
	case strings.Contains(t, "estudio"):
		return FirmLocalMidTier
	}
	return FirmUnknown
}

// detectTaxRole sniffs the tax-role string.
func detectTaxRole(s string) TaxRole {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "litigation"):
		return RoleTaxLitigationPartner
	case strings.Contains(t, "transfer pricing"):
		return RoleTransferPricingSpecialist
	case strings.Contains(t, "cross border") ||
		strings.Contains(t, "cross-border"):
		return RoleCrossBorderSpecialist
	case strings.Contains(t, "crs") || strings.Contains(t, "fatca"):
		return RoleCRSFATCASpecialist
	case strings.Contains(t, "billing"):
		return RoleBillingClerk
	case strings.Contains(t, "compliance"):
		return RoleComplianceOfficer
	case strings.Contains(t, "senior manager"):
		return RoleTaxSeniorManager
	case strings.Contains(t, "partner"):
		return RoleTaxPartner
	case strings.Contains(t, "manager"):
		return RoleTaxManager
	case strings.Contains(t, "senior"):
		return RoleTaxSenior
	case strings.Contains(t, "staff"):
		return RoleTaxStaff
	}
	return RoleUnknown
}

// detectTaxRegime sniffs the tax-regime string.
func detectTaxRegime(s string) TaxRegime {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "ganancias"):
		return RegimeImpuestoGanancias
	case strings.Contains(t, "bienes personales"):
		return RegimeBienesPersonales
	case strings.Contains(t, "iva"):
		return RegimeIVA
	case strings.Contains(t, "transfer pricing") ||
		strings.Contains(t, "precios transferencia"):
		return RegimeTransferPricing
	case strings.Contains(t, "credito debito"):
		return RegimeImpCredDebBancarios
	case strings.Contains(t, "sellos"):
		return RegimeImpSellos
	case strings.Contains(t, "ingresos brutos"):
		return RegimeIngresosBrutos
	case strings.Contains(t, "ripro"):
		return RegimeRIPRO
	case strings.Contains(t, "tierra del fuego"):
		return RegimeTierraDelFuego
	case strings.Contains(t, "mineria") || strings.Contains(t, "minería"):
		return RegimeMineria
	case strings.Contains(t, "ley 23.576") || strings.Contains(t, "on exempt"):
		return RegimeLey23576ONExempt
	case strings.Contains(t, "ley 27.430") || strings.Contains(t, "fci"):
		return RegimeLey27430FCI
	case strings.Contains(t, "cedear"):
		return RegimeCEDEAR
	case strings.Contains(t, "sov bond") ||
		strings.Contains(t, "soberano"):
		return RegimeSovBondExempt
	case strings.Contains(t, "crs") || strings.Contains(t, "fatca"):
		return RegimeCRSFATCA
	}
	return RegimeUnknown
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
