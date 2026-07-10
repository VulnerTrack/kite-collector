package winargssn

import (
	"regexp"
	"strconv"
	"strings"
)

// SSNFields captures scalar fields the audit pipeline needs from
// an SSN artifact.
type SSNFields struct {
	SSNEntityCode             string
	SSNReceiptID              string
	ClienteCuitRaw            string
	TrabajadorCuilRaw         string
	LineOfBusiness            LineOfBusiness
	PortfolioInstrumentsCount int64
	SovBondPositionCount      int64
	FCIPositionCount          int64
	EquityPositionCount       int64
	CEDEARPositionCount       int64
	PortfolioTotalARSMillions int64
	PremiumTotalARSMillions   int64
	ClaimCount                int64
	HasPassword               bool
	HasLimitBreach            bool
	HasCrossBorderReinsurance bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|ssn[_\-]?password|portal[_\-]?password|filing[_\-]?password|aseguradora[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|ssn[_\-]?password|portal[_\-]?password|filing[_\-]?password)\b"?\s*[:=]\s*["'][^"']{1,}["']`,
)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|ssn[_\-]?password|portal[_\-]?password)\s*>([^<]{1,})<\s*/`,
)

// ssnEntityCodeRE matches the SSN-assigned 4-5 digit aseguradora
// code. SSN assigns each licensed insurer a numeric code.
var ssnEntityCodeRE = regexp.MustCompile(
	`(?i)"?(?:ssn[_\- ]?entity[_\- ]?code|ssn[_\- ]?code|entidad[_\- ]?ssn|nro[_\- ]?entidad|cod[_\- ]?entidad)"?\s*[:=>]\s*"?(\d{3,6})"?`,
)

// ssnReceiptIDRE matches the SSN filing-receipt confirmation
// number.
var ssnReceiptIDRE = regexp.MustCompile(
	`(?i)"?(?:ssn[_\- ]?receipt|presentacion[_\- ]?id|filing[_\- ]?id|nro[_\- ]?presentacion|confirmation[_\- ]?id)"?\s*[:=>]\s*"?([A-Z0-9\-]{6,32})"?`,
)

// portfolioInstrumentRE matches `<Instrumento>` or `<Position>`
// repetition in SSN investment XMLs.
var portfolioInstrumentRE = regexp.MustCompile(
	`(?i)<(?:ssn:|inversion:)?(?:Instrumento|Position|Inversion|Tenencia)\b`,
)

// portfolioInstrumentJSONRE matches `"position":[{...}]` JSON
// array repetition.
var portfolioInstrumentJSONRE = regexp.MustCompile(
	`(?im)^\s*\{[^}]*"?(?:especie|symbol|ticker|instrumento|isin)"?\s*[:=]\s*"?[A-Z][A-Z0-9.\-]{1,12}`,
)

// limitBreachRE matches `limite_excedido=true` / `<LimitBreach>
// true</LimitBreach>` — Inversiones No Admitidas indicator.
var limitBreachRE = regexp.MustCompile(
	`(?i)(?:limite[_\- ]?excedido|limit[_\- ]?breach|inversion[_\- ]?no[_\- ]?admitida|limit[_\- ]?exceeded)\s*[:=>]\s*"?(?:true|1|si|sí|exceeded)"?`,
)

// limitBreachXMLRE matches XML-form limit breach.
var limitBreachXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:LimitBreach|LimiteExcedido|InversionNoAdmitida)\s*>\s*(?:true|1|si|sí|exceeded)\s*<`,
)

// crossBorderReinsurerRE matches a non-AR reinsurer indicator
// in reinsurance treaty bodies.
var crossBorderReinsurerRE = regexp.MustCompile(
	`(?i)(?:reinsurer[_\- ]?country|country[_\- ]?reinsurer|pais[_\- ]?reasegurador|reasegurador[_\- ]?pais)\s*[:=>]\s*"?([A-Z]{2,3})"?`,
)

// premiumTotalRE matches a total premium amount field in ARS.
var premiumTotalRE = regexp.MustCompile(
	`(?i)"?(?:prima[_\- ]?total|premium[_\- ]?total|total[_\- ]?primas|prima[_\- ]?emitida[_\- ]?total)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`,
)

// portfolioTotalRE matches a total portfolio amount field in ARS.
var portfolioTotalRE = regexp.MustCompile(
	`(?i)"?(?:portfolio[_\- ]?total|cartera[_\- ]?total|inversiones[_\- ]?total|total[_\- ]?inversiones)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`,
)

// claimRowRE matches a per-claim CSV row in claims/ART reports.
// AR siniestro CSVs have header `Fecha,Trabajador,Importe,Estado,
// ...`. Data rows start with a date.
var claimRowRE = regexp.MustCompile(
	`(?im)^\d{2}[/-]\d{2}[/-]\d{4},`,
)

// lineOfBusinessRE matches a line-of-business field.
var lineOfBusinessRE = regexp.MustCompile(
	`(?i)"?(?:rama|line[_\- ]?of[_\- ]?business|linea[_\- ]?negocio|ramo)"?\s*[:=>]\s*"?([A-Za-z\-]{3,40})`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// trabajadorCuilKeyRE matches `trabajador_cuil: NN-NNNNNNNN-N`.
var trabajadorCuilKeyRE = regexp.MustCompile(
	`(?i)"?(?:trabajador[_\- ]?cuil|cuil[_\- ]?trabajador|empleado[_\- ]?cuil|cuil)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// symbolEntryRE matches a per-symbol entry in investment XMLs.
var symbolEntryRE = regexp.MustCompile(
	`(?im)(?:"?(?:especie|symbol|sym|ticker|instrumento|isin)"?\s*[:=]\s*"?|<(?:especie|symbol|instrumento)[^>]*>)([A-Z][A-Z0-9_\-\./]{0,11})`,
)

// ParseInvestmentPortfolio parses an SSN investment XML / XLSX
// body.
func ParseInvestmentPortfolio(body []byte) SSNFields {
	out := parseCommon(body)
	out.PortfolioInstrumentsCount = int64(len(portfolioInstrumentRE.FindAllIndex(body, -1)))
	if out.PortfolioInstrumentsCount == 0 {
		out.PortfolioInstrumentsCount = int64(len(portfolioInstrumentJSONRE.FindAllIndex(body, -1)))
	}
	if v, ok := sumARSMillions(body, portfolioTotalRE); ok {
		out.PortfolioTotalARSMillions = v
	}
	sov, fci, eq, cedear := classifyPositions(body)
	out.SovBondPositionCount = sov
	out.FCIPositionCount = fci
	out.EquityPositionCount = eq
	out.CEDEARPositionCount = cedear
	if limitBreachRE.Match(body) || limitBreachXMLRE.Match(body) {
		out.HasLimitBreach = true
	}
	return out
}

// ParseCustodyProof parses a Caja de Valores custody PDF body.
func ParseCustodyProof(body []byte) SSNFields {
	return parseCommon(body)
}

// ParseFinancialStatement parses an estados contables body.
func ParseFinancialStatement(body []byte) SSNFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, portfolioTotalRE); ok {
		out.PortfolioTotalARSMillions = v
	}
	return out
}

// ParsePremiumReport parses a primas emitidas body.
func ParsePremiumReport(body []byte) SSNFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, premiumTotalRE); ok {
		out.PremiumTotalARSMillions = v
	}
	return out
}

// ParseClaimReport parses a siniestros body.
func ParseClaimReport(body []byte) SSNFields {
	out := parseCommon(body)
	out.ClaimCount = int64(len(claimRowRE.FindAllIndex(body, -1)))
	return out
}

// ParseReserveReport parses an encaje técnico body.
func ParseReserveReport(body []byte) SSNFields {
	return parseCommon(body)
}

// ParseCyberPolicyReport parses an SSN Res. 32/2024 cyber
// policy body.
func ParseCyberPolicyReport(body []byte) SSNFields {
	out := parseCommon(body)
	out.ClaimCount = int64(len(claimRowRE.FindAllIndex(body, -1)))
	out.LineOfBusiness = LOBCyber
	return out
}

// ParseReinsuranceTreaty parses a reinsurance treaty body.
func ParseReinsuranceTreaty(body []byte) SSNFields {
	out := parseCommon(body)
	out.LineOfBusiness = LOBReaseguro
	if m := crossBorderReinsurerRE.FindSubmatch(body); len(m) > 1 {
		cc := strings.ToUpper(string(m[1]))
		if cc != "AR" && cc != "ARG" {
			out.HasCrossBorderReinsurance = true
		}
	}
	return out
}

// ParseARTClaim parses an ART claim record body.
func ParseARTClaim(body []byte) SSNFields {
	out := parseCommon(body)
	out.ClaimCount = int64(len(claimRowRE.FindAllIndex(body, -1)))
	out.LineOfBusiness = LOBRiesgosTrabajo
	if m := trabajadorCuilKeyRE.FindSubmatch(body); len(m) > 1 {
		out.TrabajadorCuilRaw = string(m[1])
	}
	return out
}

// ParseFilingReceipt parses an SSN filing receipt body.
func ParseFilingReceipt(body []byte) SSNFields {
	return parseCommon(body)
}

// ParseConfig parses a generic SSN-tool config body.
func ParseConfig(body []byte) SSNFields {
	return parseCommon(body)
}

// parseCommon extracts the cross-cutting fields.
func parseCommon(body []byte) SSNFields {
	var out SSNFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := ssnEntityCodeRE.FindSubmatch(body); len(m) > 1 {
		out.SSNEntityCode = string(m[1])
	}
	if m := ssnReceiptIDRE.FindSubmatch(body); len(m) > 1 {
		out.SSNReceiptID = string(m[1])
	}
	if m := lineOfBusinessRE.FindSubmatch(body); len(m) > 1 {
		out.LineOfBusiness = detectLineOfBusiness(string(m[1]))
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	if c := cuilFromBody(body); c != "" {
		out.TrabajadorCuilRaw = c
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

// cuilFromBody returns the first trabajador CUIL match.
func cuilFromBody(body []byte) string {
	if m := trabajadorCuilKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectLineOfBusiness sniffs the LOB string for category.
func detectLineOfBusiness(s string) LineOfBusiness {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "vida individual") ||
		strings.Contains(t, "vida-individual") ||
		strings.Contains(t, "vida_individual"):
		return LOBVidaIndividual
	case strings.Contains(t, "vida colectivo") ||
		strings.Contains(t, "vida-colectivo") ||
		strings.Contains(t, "vida_colectivo"):
		return LOBVidaColectivo
	case strings.Contains(t, "retiro"):
		return LOBRetiro
	case strings.Contains(t, "automotor"):
		return LOBAutomotor
	case strings.Contains(t, "incendio"):
		return LOBIncendio
	case strings.Contains(t, "combinado"):
		return LOBCombinado
	case strings.Contains(t, "caucion") || strings.Contains(t, "caución"):
		return LOBCaucion
	case strings.Contains(t, "responsabilidad civil") ||
		strings.Contains(t, "responsabilidad-civil") ||
		strings.Contains(t, "resp civil"):
		return LOBRespCivil
	case strings.Contains(t, "transporte"):
		return LOBTransporte
	case strings.Contains(t, "salud"):
		return LOBSalud
	case strings.Contains(t, "cyber") || strings.Contains(t, "ciber"):
		return LOBCyber
	case strings.Contains(t, "riesgos del trabajo") ||
		strings.Contains(t, "riesgos-del-trabajo") ||
		strings.Contains(t, "art") || strings.Contains(t, "rt"):
		return LOBRiesgosTrabajo
	case strings.Contains(t, "agropecuario"):
		return LOBAgropecuario
	case strings.Contains(t, "reaseguro") || strings.Contains(t, "reinsurance"):
		return LOBReaseguro
	}
	return LOBUnknown
}

// sumARSMillions totals ARS-denominated amounts (returns
// millions). Inputs come from SSN XML/JSON which use a comma
// decimal separator in AR locale; we treat both `.` and `,` as
// separators.
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

// classifyPositions returns counts of (sov bond, FCI, equity,
// CEDEAR) positions.
func classifyPositions(body []byte) (sov, fci, eq, cedear int64) {
	sovSet := map[string]struct{}{}
	fciSet := map[string]struct{}{}
	eqSet := map[string]struct{}{}
	cedearSet := map[string]struct{}{}
	for _, m := range symbolEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" {
			continue
		}
		if IsARSovereignBondStem(s) {
			sovSet[s] = struct{}{}
		}
		if IsAREquityStem(s) {
			eqSet[s] = struct{}{}
		}
		if strings.HasPrefix(s, "FCI") || strings.Contains(s, ".FCI") {
			fciSet[s] = struct{}{}
		}
		// CEDEAR symbols on BYMA are typically the US ticker
		// suffixed with `.BA` or matched by length 4-5 + listed
		// US issuer. The Cohen iter has a curated CEDEAR list;
		// here we use a lightweight prefix match.
		switch s {
		case "AAPL", "MSFT", "AMZN", "GOOGL", "META",
			"TSLA", "NVDA", "AMD", "INTC", "MELI",
			"BIOX", "GLOB", "DESP":
			cedearSet[s] = struct{}{}
		}
	}
	return int64(len(sovSet)), int64(len(fciSet)),
		int64(len(eqSet)), int64(len(cedearSet))
}
