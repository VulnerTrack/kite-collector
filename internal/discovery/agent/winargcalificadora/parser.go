package winargcalificadora

import (
	"regexp"
	"strconv"
	"strings"
)

// CalFields captures scalar fields the audit pipeline needs from
// a calificadora artifact.
type CalFields struct {
	RatingID                 string
	MethodologyVersion       string
	SeriesID                 string
	ClienteEmisorCuitRaw     string
	ClienteAnalystCuilRaw    string
	CalificadoraID           CalificadoraID
	RatingClass              RatingClass
	WatchStatus              WatchStatus
	IssuerClass              IssuerClass
	IssuerCount              int64
	WatchIssuerCount         int64
	DissentingOpinionCount   int64
	ModelInputParamCount     int64
	FeeTotalARSMillions      int64
	HasPassword              bool
	HasMethodologyChange     bool
	HasCrossIssuerComparable bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|calificadora[_\-]?password|portal[_\-]?password|rating[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|calificadora[_\-]?password|portal[_\-]?password|rating[_\-]?password)\b"?\s*[:=]\s*["'][^"']{1,}["']`,
)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|calificadora[_\-]?password|portal[_\-]?password)\s*>([^<]{1,})<\s*/`,
)

// ratingIDRE matches a rating action identifier (e.g.
// "CAL-2026-0123").
var ratingIDRE = regexp.MustCompile(
	`(?i)"?(?:rating[_\- ]?id|calificacion[_\- ]?id|nro[_\- ]?calificacion|rating[_\- ]?action[_\- ]?id)"?\s*[:=>]\s*"?([A-Z0-9\-]{4,32})"?`,
)

// methodologyVersionRE matches a methodology version identifier
// (calificadoras version their methodology docs: "v2.3.1").
var methodologyVersionRE = regexp.MustCompile(
	`(?i)"?(?:methodology[_\- ]?version|version[_\- ]?metodologia|metodologia[_\- ]?version|version)"?\s*[:=>]\s*"?(v?\d+\.\d+(?:\.\d+)?)"?`,
)

// seriesIDRE matches the series being rated (often references the
// issuer's series ID; for FFs this is the trust certificate
// tranche).
var seriesIDRE = regexp.MustCompile(
	`(?i)"?(?:series[_\- ]?id|nro[_\- ]?serie|serie[_\- ]?nro)"?\s*[:=>]\s*"?([A-Z0-9\-]{1,32})"?`,
)

// ratingRE matches a credit-rating string.
var ratingRE = regexp.MustCompile(
	`(?i)"?(?:rating|calificacion|calificación|nota)"?\s*[:=>]\s*"?(AAA|AA[+\-]?|A[+\-]?|BBB[+\-]?|BB[+\-]?|B[+\-]?|CCC[+\-]?|CC|C|D|NR|withdrawn)\b`,
)

// watchStatusRE matches a watch / outlook status field.
var watchStatusRE = regexp.MustCompile(
	`(?i)"?(?:watch[_\- ]?status|outlook|perspectiva|tendencia)"?\s*[:=>]\s*"?(positive|positiva|negative|negativa|developing|en[_\- ]?desarrollo|stable|estable|under[_\- ]?review|en[_\- ]?revision)`,
)

// issuerClassRE matches the issuer-class field.
var issuerClassRE = regexp.MustCompile(
	`(?i)"?(?:issuer[_\- ]?class|tipo[_\- ]?emisor|asset[_\- ]?class|clase[_\- ]?emisor)"?\s*[:=>]\s*"?([A-Za-z\-_ ]{4,40})`,
)

// calificadoraIDRE matches the rating-agency self-identification.
var calificadoraIDRE = regexp.MustCompile(
	`(?i)"?(?:calificadora|rating[_\- ]?agency|agency[_\- ]?name)"?\s*[:=>]\s*"?([A-Za-z0-9 .\-_]{4,40})`,
)

// issuerCountRE matches an issuer count field (used on roster).
var issuerCountRE = regexp.MustCompile(
	`(?i)"?(?:issuer[_\- ]?count|cantidad[_\- ]?emisores|nro[_\- ]?emisores)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// watchIssuerCountRE matches the watch-list issuer count.
var watchIssuerCountRE = regexp.MustCompile(
	`(?i)"?(?:watch[_\- ]?issuer[_\- ]?count|watch[_\- ]?count|cantidad[_\- ]?watch)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// dissentRE matches a dissenting-opinion count or marker.
var dissentRE = regexp.MustCompile(
	`(?i)"?(?:dissent(?:ing)?[_\- ]?(?:opinion[_\- ]?)?count|disidentes[_\- ]?count|votos[_\- ]?disidentes|opiniones[_\- ]?disidentes)"?\s*[:=>]\s*"?(\d{1,4})`,
)

// methodologyChangeRE matches a methodology-change marker
// (CHANGE / CHANGED / NUEVA_VERSION).
var methodologyChangeRE = regexp.MustCompile(
	`(?im)\b(?:METHODOLOGY[_\- ]?CHANG(?:E|ED)|CAMBIO[_\- ]?DE[_\- ]?METODOLOGIA|NUEVA[_\- ]?VERSION[_\- ]?METODOLOGIA|REVISED[_\- ]?METHODOLOGY)\b`,
)

// crossIssuerComparableRE matches a cross-issuer comparable
// section marker.
var crossIssuerComparableRE = regexp.MustCompile(
	`(?i)\b(?:cross[_\- ]?issuer[_\- ]?comparable|peer[_\- ]?analysis|comparable[_\- ]?cohort|analisis[_\- ]?comparativo|peer[_\- ]?group)\b`,
)

// feeAmountRE matches the per-issuer fee amount in ARS.
var feeAmountRE = regexp.MustCompile(
	`(?i)"?(?:fee[_\- ]?total|honorarios[_\- ]?total|monto[_\- ]?fee|fee[_\- ]?amount|honorarios[_\- ]?amount)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`,
)

// modelInputParamRE matches model-input-parameter rows (PD/LGD
// model XLSX exports). Each row corresponds to one risk factor.
var modelInputParamRE = regexp.MustCompile(
	`(?im)^\s*(?:param[_\-]?\d+|input[_\-]?\d+|factor[_\-]?\d+|risk[_\-]?factor[_\-]?\d+),`,
)

// modelInputParamCountRE matches an explicit input-param count.
var modelInputParamCountRE = regexp.MustCompile(
	`(?i)"?(?:model[_\- ]?input[_\- ]?count|input[_\- ]?param[_\- ]?count|cantidad[_\- ]?parametros|nro[_\- ]?factores)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// issuerRosterRowRE matches a per-issuer roster row (CUIT-anchored).
var issuerRosterRowRE = regexp.MustCompile(
	`(?im)^[A-Z0-9\-]+,\d{2}-?\d{8}-?\d,`,
)

// clienteEmisorCuitKeyRE matches `cliente_emisor_cuit: NN-NNNNNNNN-N`.
var clienteEmisorCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?emisor[_\- ]?cuit|emisor[_\- ]?cuit|issuer[_\- ]?cuit|cuit[_\- ]?emisor|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// clienteAnalystCuilKeyRE matches `analyst_cuil: NN-NNNNNNNN-N`.
var clienteAnalystCuilKeyRE = regexp.MustCompile(
	`(?i)"?(?:analyst[_\- ]?cuil|analista[_\- ]?cuil|lead[_\- ]?analyst[_\- ]?cuil|cuil)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseRatingLetter parses a final rating letter body.
func ParseRatingLetter(body []byte) CalFields {
	out := parseCommon(body)
	if m := ratingIDRE.FindSubmatch(body); len(m) > 1 {
		out.RatingID = string(m[1])
	}
	if m := ratingRE.FindSubmatch(body); len(m) > 1 {
		out.RatingClass = detectRating(string(m[1]))
	}
	if m := watchStatusRE.FindSubmatch(body); len(m) > 1 {
		out.WatchStatus = detectWatchStatus(string(m[1]))
	}
	if m := seriesIDRE.FindSubmatch(body); len(m) > 1 {
		out.SeriesID = string(m[1])
	}
	return out
}

// ParseMethodologyDoc parses a methodology document body.
func ParseMethodologyDoc(body []byte) CalFields {
	out := parseCommon(body)
	if m := methodologyVersionRE.FindSubmatch(body); len(m) > 1 {
		out.MethodologyVersion = string(m[1])
	}
	if methodologyChangeRE.Match(body) {
		out.HasMethodologyChange = true
	}
	if crossIssuerComparableRE.Match(body) {
		out.HasCrossIssuerComparable = true
	}
	return out
}

// ParseCommitteeMinutes parses a rating-committee minutes body.
func ParseCommitteeMinutes(body []byte) CalFields {
	out := parseCommon(body)
	if m := ratingIDRE.FindSubmatch(body); len(m) > 1 {
		out.RatingID = string(m[1])
	}
	if m := ratingRE.FindSubmatch(body); len(m) > 1 {
		out.RatingClass = detectRating(string(m[1]))
	}
	if m := dissentRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.DissentingOpinionCount = v
		}
	}
	return out
}

// ParseMonitoringReport parses a per-issuer monitoring report
// body.
func ParseMonitoringReport(body []byte) CalFields {
	out := parseCommon(body)
	if m := ratingRE.FindSubmatch(body); len(m) > 1 {
		out.RatingClass = detectRating(string(m[1]))
	}
	if m := watchStatusRE.FindSubmatch(body); len(m) > 1 {
		out.WatchStatus = detectWatchStatus(string(m[1]))
	}
	return out
}

// ParseWatchlist parses a watch-list body.
func ParseWatchlist(body []byte) CalFields {
	out := parseCommon(body)
	if m := watchIssuerCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.WatchIssuerCount = v
		}
	}
	if out.WatchIssuerCount == 0 {
		out.WatchIssuerCount = int64(len(issuerRosterRowRE.FindAllIndex(body, -1)))
	}
	if m := watchStatusRE.FindSubmatch(body); len(m) > 1 {
		out.WatchStatus = detectWatchStatus(string(m[1]))
	}
	return out
}

// ParseConflictOfInterestDoc parses a COI disclosure body.
func ParseConflictOfInterestDoc(body []byte) CalFields {
	return parseCommon(body)
}

// ParseFeeSchedule parses a fee schedule body.
func ParseFeeSchedule(body []byte) CalFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, feeAmountRE); ok {
		out.FeeTotalARSMillions = v
	}
	return out
}

// ParseInternalCreditModel parses an internal PD/LGD/EAD model
// body.
func ParseInternalCreditModel(body []byte) CalFields {
	out := parseCommon(body)
	if m := modelInputParamCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.ModelInputParamCount = v
		}
	}
	if out.ModelInputParamCount == 0 {
		out.ModelInputParamCount = int64(len(modelInputParamRE.FindAllIndex(body, -1)))
	}
	if m := methodologyVersionRE.FindSubmatch(body); len(m) > 1 {
		out.MethodologyVersion = string(m[1])
	}
	return out
}

// ParseDissentingOpinion parses a dissenting opinion body.
func ParseDissentingOpinion(body []byte) CalFields {
	out := parseCommon(body)
	out.DissentingOpinionCount = 1
	if m := dissentRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.DissentingOpinionCount = v
		}
	}
	return out
}

// ParseIssuerRoster parses an issuer roster body.
func ParseIssuerRoster(body []byte) CalFields {
	out := parseCommon(body)
	if m := issuerCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.IssuerCount = v
		}
	}
	if out.IssuerCount == 0 {
		out.IssuerCount = int64(len(issuerRosterRowRE.FindAllIndex(body, -1)))
	}
	return out
}

// ParseCNVFiling parses a CNV regulatory filing body.
func ParseCNVFiling(body []byte) CalFields {
	return parseCommon(body)
}

// ParseSOCReport parses an SOC 1/2 compliance report body.
func ParseSOCReport(body []byte) CalFields {
	return parseCommon(body)
}

// ParseConfig parses a generic calificadora-tool config body.
func ParseConfig(body []byte) CalFields {
	return parseCommon(body)
}

// parseCommon extracts the cross-cutting fields.
func parseCommon(body []byte) CalFields {
	var out CalFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := calificadoraIDRE.FindSubmatch(body); len(m) > 1 {
		out.CalificadoraID = detectCalificadora(string(m[1]))
	}
	if m := issuerClassRE.FindSubmatch(body); len(m) > 1 {
		out.IssuerClass = detectIssuerClass(string(m[1]))
	}
	if c := clienteEmisorCuitFromBody(body); c != "" {
		out.ClienteEmisorCuitRaw = c
	}
	if c := clienteAnalystCuilFromBody(body); c != "" {
		out.ClienteAnalystCuilRaw = c
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

// clienteAnalystCuilFromBody returns the first analyst CUIL.
func clienteAnalystCuilFromBody(body []byte) string {
	if m := clienteAnalystCuilKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectCalificadora sniffs the calificadora name string.
func detectCalificadora(s string) CalificadoraID {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "fix scr") ||
		strings.Contains(t, "fix-scr") ||
		strings.Contains(t, "fix_scr"):
		return CalFIXSCRArgentina
	case strings.Contains(t, "moody"):
		return CalMoodysLocalArgentina
	case strings.Contains(t, "evaluadora") ||
		strings.Contains(t, "latinoamericana"):
		return CalEvaluadoraLatinoamericana
	case strings.Contains(t, "untref"):
		return CalUntref
	case strings.Contains(t, "acr") ||
		strings.Contains(t, "argentine credit rating"):
		return CalACR
	case strings.Contains(t, "standard") ||
		strings.Contains(t, "s&p") ||
		strings.Contains(t, "s and p"):
		return CalStandardAndPoorsArgentina
	}
	return CalUnknown
}

// detectIssuerClass sniffs the issuer-class string.
func detectIssuerClass(s string) IssuerClass {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "sub-sovereign") ||
		strings.Contains(t, "sub sovereign") ||
		strings.Contains(t, "subnacional") ||
		strings.Contains(t, "provincia") ||
		strings.Contains(t, "municipal"):
		return IssuerSubSovereign
	case strings.Contains(t, "sovereign") ||
		strings.Contains(t, "soberano"):
		return IssuerSovereign
	case strings.Contains(t, "fideicomiso") ||
		strings.Contains(t, "structured") ||
		strings.Contains(t, "securitiz"):
		return IssuerFideicomisoFinanciero
	case strings.Contains(t, "financial institution") ||
		strings.Contains(t, "bank") ||
		strings.Contains(t, "banco"):
		return IssuerFinancialInstitution
	case strings.Contains(t, "insurance") ||
		strings.Contains(t, "seguros") ||
		strings.Contains(t, "aseguradora"):
		return IssuerInsurance
	case strings.Contains(t, "pyme"):
		return IssuerPYMEOn
	case strings.Contains(t, "covered bond") ||
		strings.Contains(t, "covered-bond"):
		return IssuerCoveredBond
	case strings.Contains(t, "project finance") ||
		strings.Contains(t, "project-finance"):
		return IssuerProjectFinance
	case strings.Contains(t, "corporate") ||
		strings.Contains(t, "on corporativa") ||
		strings.Contains(t, "corporativo"):
		return IssuerCorporateBond
	}
	return IssuerUnknown
}

// detectWatchStatus normalizes a watch status string.
func detectWatchStatus(s string) WatchStatus {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "positive") || strings.Contains(t, "positiva"):
		return WatchPositive
	case strings.Contains(t, "negative") || strings.Contains(t, "negativa"):
		return WatchNegative
	case strings.Contains(t, "developing") ||
		strings.Contains(t, "desarrollo"):
		return WatchDeveloping
	case strings.Contains(t, "stable") || strings.Contains(t, "estable"):
		return WatchStable
	case strings.Contains(t, "review") || strings.Contains(t, "revision"):
		return WatchUnderReview
	}
	return WatchUnknown
}

// detectRating normalizes a rating string to the pinned enum.
func detectRating(s string) RatingClass {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "NR" {
		return RatingNoRating
	}
	if t == "WITHDRAWN" {
		return RatingWithdrawn
	}
	t = strings.TrimRight(t, "+-")
	switch t {
	case "AAA":
		return RatingAAA
	case "AA":
		return RatingAA
	case "A":
		return RatingA
	case "BBB":
		return RatingBBB
	case "BB":
		return RatingBB
	case "B":
		return RatingB
	case "CCC":
		return RatingCCC
	case "CC":
		return RatingCC
	case "C":
		return RatingC
	case "D":
		return RatingD
	}
	return RatingUnknown
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
