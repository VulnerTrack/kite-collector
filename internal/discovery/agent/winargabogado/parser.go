package winargabogado

import (
	"regexp"
	"strconv"
	"strings"
)

// AbogadoFields captures scalar fields the audit pipeline needs
// from a securities-law-firm artifact.
type AbogadoFields struct {
	MatterID               string
	MatterName             string
	BarNumber              string
	ClienteEmisorCuitRaw   string
	LawyerCuilRaw          string
	LawFirm                LawFirm
	MatterClass            MatterClass
	BillableHoursCount     int64
	HourlyRateARS          int64
	RetainerARSMillions    int64
	HasPassword            bool
	HasPrivilegedMarker    bool
	HasPrePublicationDraft bool
	HasCovenantBreach      bool
	HasCrossBorderMatter   bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|legal[_\-]?password|legalsuite[_\-]?password|firm[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|legal[_\-]?password|legalsuite[_\-]?password|firm[_\-]?password)\b"?\s*[:=]\s*["'][^"']{1,}["']`,
)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|legal[_\-]?password|firm[_\-]?password)\s*>([^<]{1,})<\s*/`,
)

// matterIDRE matches a matter identifier.
var matterIDRE = regexp.MustCompile(
	`(?i)"?(?:matter[_\- ]?id|case[_\- ]?id|expediente|nro[_\- ]?expediente|file[_\- ]?id)"?\s*[:=>]\s*"?([A-Z0-9\-]{4,32})"?`,
)

// matterNameRE matches the matter name.
var matterNameRE = regexp.MustCompile(
	`(?i)"?(?:matter[_\- ]?name|case[_\- ]?name|matter|caratula)"?\s*[:=>]\s*"?([A-Za-zÀ-ÿ0-9 .\-_,&]{4,80})"?`,
)

// barNumberRE matches an attorney bar (matrícula) number.
//
// AR attorneys are matriculated at the Colegio Público de
// Abogados de la Capital Federal (CPACF) or provincial bars.
var barNumberRE = regexp.MustCompile(
	`(?i)"?(?:bar[_\- ]?number|matricula|matrícula|tomo[_\- ]?folio|cpacf|nro[_\- ]?matricula)"?\s*[:=>]\s*"?(T?\s*\d{1,5}[\s\-]?F?\s*\d{1,5}|CPACF[\s\-]?\d{1,12})"?`,
)

// lawFirmRE matches the law-firm self-identification.
var lawFirmRE = regexp.MustCompile(
	`(?i)"?(?:law[_\- ]?firm|estudio|firm[_\- ]?name|firma)"?\s*[:=>]\s*"?([A-Za-z0-9 .\-_&']{4,80})`,
)

// matterClassRE matches a matter-class field. Char class
// includes `&` for "M&A" patterns.
var matterClassRE = regexp.MustCompile(
	`(?i)"?(?:matter[_\- ]?class|tipo[_\- ]?asunto|practice[_\- ]?area)"?\s*[:=>]\s*"?([A-Za-z\-_ &]{2,40})`,
)

// privilegedMarkerRE matches attorney-client privilege markers.
var privilegedMarkerRE = regexp.MustCompile(
	`(?im)\b(?:ATTORNEY[_\- ]?CLIENT|ATTORNEY[_\- ]?WORK[_\- ]?PRODUCT|WORK[_\- ]?PRODUCT|SUBJECT[_\- ]?TO[_\- ]?LEGAL[_\- ]?PRIVILEGE|PRIVILEGED[_\- ]?AND[_\- ]?CONFIDENTIAL|PRIVILEGED|SECRETO[_\- ]?PROFESIONAL|COMUNICACI[ÓO]N[_\- ]?PRIVILEGIADA)\b`,
)

// prePublicationDraftRE matches pre-publication / draft markers.
var prePublicationDraftRE = regexp.MustCompile(
	`(?im)\b(?:DRAFT|BORRADOR|RESTRICTED|CONFIDENCIAL|CONFIDENTIAL|FOR[_\- ]?DISCUSSION[_\- ]?ONLY|FOR[_\- ]?INTERNAL[_\- ]?USE|NOT[_\- ]?FOR[_\- ]?DISTRIBUTION|NO[_\- ]?CIRCULAR|PRELIMINARY|PRELIMINAR|INTERNO|INTERNAL[_\- ]?ONLY|EYES[_\- ]?ONLY|PRE[_\- ]?DECISIONAL)\b`,
)

// covenantBreachRE matches a covenant-breach marker in covenant
// compliance memos.
var covenantBreachRE = regexp.MustCompile(
	`(?im)\b(?:COVENANT[_\- ]?BREACH|COVENANT[_\- ]?VIOLATION|INCUMPLIMIENTO[_\- ]?COVENANT|EVENT[_\- ]?OF[_\- ]?DEFAULT|EOD|DEFAULT[_\- ]?TRIGGER|CROSS[_\- ]?DEFAULT|ACELERAMIENTO|ACCELERATION)\b`,
)

// crossBorderRE matches cross-border matter markers.
var crossBorderRE = regexp.MustCompile(
	`(?i)\b(?:cross[_\- ]?border|cross[_\- ]?jurisdiction|foreign[_\- ]?law|us[_\- ]?counsel|local[_\- ]?counsel|new[_\- ]?york[_\- ]?law|english[_\- ]?law|delaware[_\- ]?law|sec[_\- ]?filing|pcaob)\b`,
)

// billableHoursCountRE matches a billable-hours total.
var billableHoursCountRE = regexp.MustCompile(
	`(?i)"?(?:billable[_\- ]?hours|horas[_\- ]?facturables|total[_\- ]?hours|hours[_\- ]?total)"?\s*[:=>]\s*"?(\d{1,6}(?:[.,]\d+)?)`,
)

// billableHoursRowRE matches a per-hours CSV row.
var billableHoursRowRE = regexp.MustCompile(
	`(?im)^\d{2}[/-]\d{2}[/-]\d{4},`,
)

// hourlyRateRE matches the hourly rate in ARS.
var hourlyRateRE = regexp.MustCompile(
	`(?i)"?(?:hourly[_\- ]?rate|tarifa[_\- ]?hora|tarifa[_\- ]?horaria|rate[_\- ]?per[_\- ]?hour)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`,
)

// retainerRE matches the engagement retainer in ARS.
var retainerRE = regexp.MustCompile(
	`(?i)"?(?:retainer|anticipo[_\- ]?honorarios|monto[_\- ]?retainer)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`,
)

// clienteEmisorCuitKeyRE matches `cliente_emisor_cuit:
// NN-NNNNNNNN-N`.
var clienteEmisorCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cliente[_\- ]?emisor[_\- ]?cuit|emisor[_\- ]?cuit|client[_\- ]?cuit|cuit[_\- ]?cliente|cuit[_\- ]?emisor|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// lawyerCuilKeyRE matches `lawyer_cuil: NN-NNNNNNNN-N`.
var lawyerCuilKeyRE = regexp.MustCompile(
	`(?i)"?(?:lawyer[_\- ]?cuil|abogado[_\- ]?cuil|partner[_\- ]?cuil|attorney[_\- ]?cuil|cuil)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseLegalOpinion parses a legal opinion body.
func ParseLegalOpinion(body []byte) AbogadoFields {
	return parseCommon(body)
}

// ParseTrueSaleOpinion parses a true-sale opinion body.
func ParseTrueSaleOpinion(body []byte) AbogadoFields {
	return parseCommon(body)
}

// Parse10b5Letter parses a SEC Rule 10b-5 letter body.
func Parse10b5Letter(body []byte) AbogadoFields {
	out := parseCommon(body)
	out.HasCrossBorderMatter = true
	return out
}

// ParseNoActionLetter parses a no-action letter body.
func ParseNoActionLetter(body []byte) AbogadoFields {
	return parseCommon(body)
}

// ParseEngagementLetter parses an engagement letter body.
func ParseEngagementLetter(body []byte) AbogadoFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, retainerRE); ok {
		out.RetainerARSMillions = v
	}
	if m := hourlyRateRE.FindSubmatch(body); len(m) > 1 {
		raw := strings.ReplaceAll(strings.ReplaceAll(
			string(m[1]), ".", "",
		), ",", "")
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			out.HourlyRateARS = v
		}
	}
	return out
}

// ParseBillableHours parses a billable-hours CSV body.
func ParseBillableHours(body []byte) AbogadoFields {
	out := parseCommon(body)
	if m := billableHoursCountRE.FindSubmatch(body); len(m) > 1 {
		raw := strings.ReplaceAll(string(m[1]), ",", "")
		if dotIdx := strings.IndexByte(raw, '.'); dotIdx >= 0 {
			raw = raw[:dotIdx]
		}
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			out.BillableHoursCount = v
		}
	}
	if out.BillableHoursCount == 0 {
		out.BillableHoursCount = int64(len(billableHoursRowRE.FindAllIndex(body, -1)))
	}
	return out
}

// ParseProspectoLegalReview parses a prospecto markup body.
func ParseProspectoLegalReview(body []byte) AbogadoFields {
	return parseCommon(body)
}

// ParseCovenantComplianceMemo parses a covenant memo body.
func ParseCovenantComplianceMemo(body []byte) AbogadoFields {
	out := parseCommon(body)
	if covenantBreachRE.Match(body) {
		out.HasCovenantBreach = true
	}
	return out
}

// ParseBondholderConsent parses a consent solicitation body.
func ParseBondholderConsent(body []byte) AbogadoFields {
	return parseCommon(body)
}

// ParseRestructuringPlan parses a Ley 24.522 plan body.
func ParseRestructuringPlan(body []byte) AbogadoFields {
	return parseCommon(body)
}

// ParseEnforcementDefense parses a CNV sanción defense body.
func ParseEnforcementDefense(body []byte) AbogadoFields {
	return parseCommon(body)
}

// ParsePrivilegedCommunication parses a privileged email/memo
// body.
func ParsePrivilegedCommunication(body []byte) AbogadoFields {
	out := parseCommon(body)
	out.HasPrivilegedMarker = true
	return out
}

// ParseClassActionDefense parses a class-action defense body.
func ParseClassActionDefense(body []byte) AbogadoFields {
	return parseCommon(body)
}

// ParseConfig parses a generic legal-tool config body.
func ParseConfig(body []byte) AbogadoFields {
	return parseCommon(body)
}

// parseCommon extracts the cross-cutting fields.
func parseCommon(body []byte) AbogadoFields {
	var out AbogadoFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := matterIDRE.FindSubmatch(body); len(m) > 1 {
		out.MatterID = string(m[1])
	}
	if m := matterNameRE.FindSubmatch(body); len(m) > 1 {
		out.MatterName = strings.TrimSpace(string(m[1]))
	}
	if m := barNumberRE.FindSubmatch(body); len(m) > 1 {
		out.BarNumber = strings.TrimSpace(string(m[1]))
	}
	if m := lawFirmRE.FindSubmatch(body); len(m) > 1 {
		out.LawFirm = detectLawFirm(string(m[1]))
	}
	if m := matterClassRE.FindSubmatch(body); len(m) > 1 {
		out.MatterClass = detectMatterClass(string(m[1]))
	}
	if privilegedMarkerRE.Match(body) {
		out.HasPrivilegedMarker = true
	}
	if prePublicationDraftRE.Match(body) {
		out.HasPrePublicationDraft = true
	}
	if crossBorderRE.Match(body) {
		out.HasCrossBorderMatter = true
	}
	if c := clienteEmisorCuitFromBody(body); c != "" {
		out.ClienteEmisorCuitRaw = c
	}
	if c := lawyerCuilFromBody(body); c != "" {
		out.LawyerCuilRaw = c
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

// lawyerCuilFromBody returns the first lawyer CUIL match.
func lawyerCuilFromBody(body []byte) string {
	if m := lawyerCuilKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectLawFirm sniffs the law-firm name string.
func detectLawFirm(s string) LawFirm {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "marval"):
		return FirmMarvalOFarrellMairal
	case strings.Contains(t, "bruchou") ||
		strings.Contains(t, "funes de rioja") ||
		strings.Contains(t, "funes-de-rioja"):
		return FirmBruchouFunesDeRioja
	case strings.Contains(t, "pagbam") ||
		strings.Contains(t, "perez alati") ||
		strings.Contains(t, "pérez alati") ||
		strings.Contains(t, "grondona"):
		return FirmPAGBAM
	case strings.Contains(t, "allende") || strings.Contains(t, "brea"):
		return FirmAllendeBrea
	case strings.Contains(t, "beccar varela") ||
		strings.Contains(t, "beccar-varela") ||
		strings.Contains(t, "beccar_varela"):
		return FirmBeccarVarela
	case strings.Contains(t, "tanoira") || strings.Contains(t, "cassagne"):
		return FirmTanoiraCassagne
	case strings.Contains(t, "mitrani") || strings.Contains(t, "caballero") ||
		strings.Contains(t, "ruiz moreno"):
		return FirmMitraniCaballeroRuizMoreno
	case strings.Contains(t, "cabanellas") || strings.Contains(t, "etchebarne"):
		return FirmCabanellasEtchebarneKelly
	case strings.Contains(t, "pereyra sentenac") ||
		strings.Contains(t, "pereyra-sentenac"):
		return FirmEstudioPereyraSentenac
	case strings.Contains(t, "solo") || strings.Contains(t, "unico"):
		return FirmSoloPractitioner
	case strings.Contains(t, "estudio"):
		return FirmLocalMidTier
	}
	return FirmUnknown
}

// detectMatterClass sniffs the matter-class string.
func detectMatterClass(s string) MatterClass {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "m&a") || strings.Contains(t, "ma transactional") ||
		strings.Contains(t, "merger"):
		return MatterMATransactional
	case strings.Contains(t, "capital markets") ||
		strings.Contains(t, "capital-markets") ||
		strings.Contains(t, "issuance") ||
		strings.Contains(t, "emisión"):
		return MatterCapitalMarketsIssuance
	case strings.Contains(t, "securitization") ||
		strings.Contains(t, "fideicomiso") ||
		strings.Contains(t, "true sale"):
		return MatterSecuritizationFF
	case strings.Contains(t, "restructuring") ||
		strings.Contains(t, "reestructuracion") ||
		strings.Contains(t, "concurso"):
		return MatterRestructuring
	case strings.Contains(t, "enforcement") ||
		strings.Contains(t, "sancion") ||
		strings.Contains(t, "sanción"):
		return MatterEnforcementDefense
	case strings.Contains(t, "class action") ||
		strings.Contains(t, "class-action") ||
		strings.Contains(t, "demanda colectiva"):
		return MatterClassAction
	case strings.Contains(t, "tax advisory") ||
		strings.Contains(t, "tax-advisory") ||
		strings.Contains(t, "asesoria fiscal"):
		return MatterTaxAdvisory
	case strings.Contains(t, "cross border") ||
		strings.Contains(t, "cross-border"):
		return MatterCrossBorder
	case strings.Contains(t, "corporate") ||
		strings.Contains(t, "corporativo"):
		return MatterGeneralCorporate
	}
	return MatterUnknown
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
