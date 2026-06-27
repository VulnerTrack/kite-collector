package winargfideicomiso

import (
	"regexp"
	"strconv"
	"strings"
)

// FFFields captures scalar fields the audit pipeline needs from
// an FF artifact.
type FFFields struct {
	SeriesID                   string
	CNVAuthorizationID         string
	FFName                     string
	ClienteCuitRaw             string
	OriginadorCuitRaw          string
	FiduciarioCuitRaw          string
	UnderlyingClass            UnderlyingClass
	TrancheClass               TrancheClass
	RatingClass                RatingClass
	ReceivableCount            int64
	CollectionTotalARSMillions int64
	MoraCount                  int64
	MoraAmountARSMillions      int64
	InvestorCount              int64
	IssuanceAmountARSMillions  int64
	HasPassword                bool
	HasPreIssuanceDraft        bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|ff[_\-]?password|fiduciario[_\-]?password|bacs[_\-]?password|tmf[_\-]?password)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|ff[_\-]?password|fiduciario[_\-]?password)\b"?\s*[:=]\s*["'][^"']{1,}["']`)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|ff[_\-]?password|fiduciario[_\-]?password)\s*>([^<]{1,})<\s*/`)

// seriesIDRE matches an FF series identifier.
var seriesIDRE = regexp.MustCompile(
	`(?i)"?(?:series[_\- ]?id|nro[_\- ]?serie|serie[_\- ]?nro|series|serie)"?\s*[:=>]\s*"?([A-Z0-9\-]{1,32})"?`)

// cnvAuthIDRE matches a CNV authorization ID.
var cnvAuthIDRE = regexp.MustCompile(
	`(?i)"?(?:cnv[_\- ]?authorization|cnv[_\- ]?id|cnv[_\- ]?aut|cnv[_\- ]?registro|authorization[_\- ]?cnv)"?\s*[:=>]\s*"?([A-Z0-9\-]{4,32})"?`)

// ffNameRE matches the trust name itself (e.g. "FF Tarjeta
// Naranja Trust XXIV").
var ffNameRE = regexp.MustCompile(
	`(?i)"?(?:fideicomiso[_\- ]?nombre|ff[_\- ]?name|trust[_\- ]?name|denominacion)"?\s*[:=>]\s*"?([A-Za-zÀ-ÿ0-9 .\-_]{4,80})"?`)

// preIssuanceMarkerRE matches "DRAFT" / "BORRADOR" / "CONFIDENCIAL"
// stamps in pre-issuance documents.
var preIssuanceMarkerRE = regexp.MustCompile(
	`(?im)\b(?:DRAFT|BORRADOR|PRELIMINARY|PRELIMINAR|CONFIDENCIAL|CONFIDENTIAL|NOT[_\- ]?FOR[_\- ]?DISTRIBUTION|NO[_\- ]?CIRCULAR|INTERNO|INTERNAL[_\- ]?ONLY)\b`)

// receivableCountRE matches a per-receivable CSV row. AR cobranza
// CSVs have header `Fecha,CUIT,Cuota,Importe,Estado`. Data rows
// start with a date in `dd/mm/YYYY` form.
var receivableRowRE = regexp.MustCompile(
	`(?im)^\d{2}[/-]\d{2}[/-]\d{4},\d{2}-?\d{8}-?\d,`)

// receivableCountKeyRE matches a `receivable_count: N` field.
var receivableCountKeyRE = regexp.MustCompile(
	`(?i)"?(?:receivable[_\- ]?count|cantidad[_\- ]?creditos|creditos[_\- ]?total|nro[_\- ]?creditos)"?\s*[:=>]\s*"?(\d{1,12})`)

// collectionTotalRE matches a `collection_total: ARS N` field.
var collectionTotalRE = regexp.MustCompile(
	`(?i)"?(?:collection[_\- ]?total|cobranza[_\- ]?total|total[_\- ]?cobrado|recaudado[_\- ]?total)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`)

// moraCountRE matches a `mora_count: N` field.
var moraCountRE = regexp.MustCompile(
	`(?i)"?(?:mora[_\- ]?count|cantidad[_\- ]?mora|nro[_\- ]?moras|defaulted[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`)

// moraAmountRE matches a `mora_amount: ARS N` field.
var moraAmountRE = regexp.MustCompile(
	`(?i)"?(?:mora[_\- ]?amount|monto[_\- ]?mora|importe[_\- ]?mora|defaulted[_\- ]?amount)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`)

// investorCountRE matches an investor count field.
var investorCountRE = regexp.MustCompile(
	`(?i)"?(?:investor[_\- ]?count|cantidad[_\- ]?inversores|nro[_\- ]?inversores)"?\s*[:=>]\s*"?(\d{1,12})`)

// issuanceAmountRE matches the per-series issuance amount.
var issuanceAmountRE = regexp.MustCompile(
	`(?i)"?(?:issuance[_\- ]?amount|monto[_\- ]?emision|vn[_\- ]?serie|valor[_\- ]?nominal[_\- ]?serie)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`)

// trancheRE matches a tranche-class field.
var trancheRE = regexp.MustCompile(
	`(?i)"?(?:tranche|tramo|clase[_\- ]?titulo|class)"?\s*[:=>]\s*"?(VRD[_\- ]?(?:Senior|Mezzanine|Subordinated|Sr|Mez|Sub)|CP[_\- ]?(?:Equity|Senior|Eq|Sr))`)

// ratingRE matches a credit-rating field.
var ratingRE = regexp.MustCompile(
	`(?i)"?(?:rating|calificacion|calificación)"?\s*[:=>]\s*"?(AAA|AA[+\-]?|A[+\-]?|BBB[+\-]?|BB[+\-]?|B[+\-]?|CCC[+\-]?|CC|C|D)\b`)

// underlyingRE matches an underlying-asset-class field.
var underlyingRE = regexp.MustCompile(
	`(?i)"?(?:underlying|activo[_\- ]?subyacente|tipo[_\- ]?activo|asset[_\- ]?class)"?\s*[:=>]\s*"?([A-Za-z\-_ ]{4,40})`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|deudor[_\- ]?cuit|titular[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// originadorCuitKeyRE matches `originador_cuit: NN-NNNNNNNN-N`.
var originadorCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:originador[_\- ]?cuit|cuit[_\- ]?originador|emisor[_\- ]?cuit|originator[_\- ]?cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// fiduciarioCuitKeyRE matches `fiduciario_cuit: NN-NNNNNNNN-N`.
var fiduciarioCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:fiduciario[_\- ]?cuit|cuit[_\- ]?fiduciario|trustee[_\- ]?cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseProspecto parses a base prospecto body.
func ParseProspecto(body []byte) FFFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, issuanceAmountRE); ok {
		out.IssuanceAmountARSMillions = v
	}
	if preIssuanceMarkerRE.Match(body) {
		out.HasPreIssuanceDraft = true
	}
	return out
}

// ParseSuplemento parses a per-series supplement body.
func ParseSuplemento(body []byte) FFFields {
	out := parseCommon(body)
	if m := trancheRE.FindSubmatch(body); len(m) > 1 {
		out.TrancheClass = detectTranche(string(m[1]))
	}
	if m := ratingRE.FindSubmatch(body); len(m) > 1 {
		out.RatingClass = detectRating(string(m[1]))
	}
	if v, ok := sumARSMillions(body, issuanceAmountRE); ok {
		out.IssuanceAmountARSMillions = v
	}
	if preIssuanceMarkerRE.Match(body) {
		out.HasPreIssuanceDraft = true
	}
	return out
}

// ParseEscritura parses a trust deed body.
func ParseEscritura(body []byte) FFFields {
	out := parseCommon(body)
	if preIssuanceMarkerRE.Match(body) {
		out.HasPreIssuanceDraft = true
	}
	return out
}

// ParseContratoFiduciario parses a trust contract body.
func ParseContratoFiduciario(body []byte) FFFields {
	return ParseEscritura(body)
}

// ParseCobranzaCSV parses a collections cohort CSV body.
func ParseCobranzaCSV(body []byte) FFFields {
	out := parseCommon(body)
	out.ReceivableCount = int64(len(receivableRowRE.FindAllIndex(body, -1)))
	if out.ReceivableCount == 0 {
		if m := receivableCountKeyRE.FindSubmatch(body); len(m) > 1 {
			if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
				out.ReceivableCount = v
			}
		}
	}
	if v, ok := sumARSMillions(body, collectionTotalRE); ok {
		out.CollectionTotalARSMillions = v
	}
	return out
}

// ParseMoraCSV parses a default cohort CSV body.
func ParseMoraCSV(body []byte) FFFields {
	out := parseCommon(body)
	out.MoraCount = int64(len(receivableRowRE.FindAllIndex(body, -1)))
	if out.MoraCount == 0 {
		if m := moraCountRE.FindSubmatch(body); len(m) > 1 {
			if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
				out.MoraCount = v
			}
		}
	}
	if v, ok := sumARSMillions(body, moraAmountRE); ok {
		out.MoraAmountARSMillions = v
	}
	return out
}

// ParsePrecancelacionCSV parses a prepayment cohort CSV body.
func ParsePrecancelacionCSV(body []byte) FFFields {
	return ParseCobranzaCSV(body)
}

// ParseTituloSerie parses a trust certificate body.
func ParseTituloSerie(body []byte) FFFields {
	out := parseCommon(body)
	if m := trancheRE.FindSubmatch(body); len(m) > 1 {
		out.TrancheClass = detectTranche(string(m[1]))
	}
	if m := ratingRE.FindSubmatch(body); len(m) > 1 {
		out.RatingClass = detectRating(string(m[1]))
	}
	return out
}

// ParseInvestorList parses an investor-list body.
func ParseInvestorList(body []byte) FFFields {
	out := parseCommon(body)
	out.InvestorCount = int64(len(receivableRowRE.FindAllIndex(body, -1)))
	if out.InvestorCount == 0 {
		if m := investorCountRE.FindSubmatch(body); len(m) > 1 {
			if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
				out.InvestorCount = v
			}
		}
	}
	return out
}

// ParseCalificacionReport parses a rating report body.
func ParseCalificacionReport(body []byte) FFFields {
	out := parseCommon(body)
	if m := ratingRE.FindSubmatch(body); len(m) > 1 {
		out.RatingClass = detectRating(string(m[1]))
	}
	return out
}

// ParseAdministratorReport parses a fiduciario admin report body.
func ParseAdministratorReport(body []byte) FFFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, collectionTotalRE); ok {
		out.CollectionTotalARSMillions = v
	}
	if v, ok := sumARSMillions(body, moraAmountRE); ok {
		out.MoraAmountARSMillions = v
	}
	if preIssuanceMarkerRE.Match(body) {
		out.HasPreIssuanceDraft = true
	}
	return out
}

// ParseAuditReport parses an Agente de Control output body.
func ParseAuditReport(body []byte) FFFields {
	out := parseCommon(body)
	if preIssuanceMarkerRE.Match(body) {
		out.HasPreIssuanceDraft = true
	}
	return out
}

// ParseFilingReceipt parses a CNV / AFIP filing receipt body.
func ParseFilingReceipt(body []byte) FFFields {
	return parseCommon(body)
}

// ParseConfig parses a generic fiduciario-tool config body.
func ParseConfig(body []byte) FFFields {
	return parseCommon(body)
}

// parseCommon extracts the cross-cutting fields.
func parseCommon(body []byte) FFFields {
	var out FFFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := seriesIDRE.FindSubmatch(body); len(m) > 1 {
		out.SeriesID = string(m[1])
	}
	if m := cnvAuthIDRE.FindSubmatch(body); len(m) > 1 {
		out.CNVAuthorizationID = string(m[1])
	}
	if m := ffNameRE.FindSubmatch(body); len(m) > 1 {
		out.FFName = strings.TrimSpace(string(m[1]))
	}
	if m := underlyingRE.FindSubmatch(body); len(m) > 1 {
		out.UnderlyingClass = detectUnderlying(string(m[1]))
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	if c := originadorCuitFromBody(body); c != "" {
		out.OriginadorCuitRaw = c
	}
	if c := fiduciarioCuitFromBody(body); c != "" {
		out.FiduciarioCuitRaw = c
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

// originadorCuitFromBody returns the first originador CUIT match.
func originadorCuitFromBody(body []byte) string {
	if m := originadorCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// fiduciarioCuitFromBody returns the first fiduciario CUIT match.
func fiduciarioCuitFromBody(body []byte) string {
	if m := fiduciarioCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectUnderlying sniffs the underlying asset class string.
func detectUnderlying(s string) UnderlyingClass {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "tarjeta") || strings.Contains(t, "credit card"):
		return UnderlyingTarjetaCredito
	case strings.Contains(t, "hipotecario") || strings.Contains(t, "mortgage"):
		return UnderlyingMortgage
	case strings.Contains(t, "prendario"):
		return UnderlyingPrendario
	case strings.Contains(t, "leasing"):
		return UnderlyingLeasing
	case strings.Contains(t, "pyme"):
		return UnderlyingPYMELoan
	case strings.Contains(t, "sgr"):
		return UnderlyingSGRPool
	case strings.Contains(t, "real estate") ||
		strings.Contains(t, "inmobiliario") ||
		strings.Contains(t, "real-estate"):
		return UnderlyingRealEstateDev
	case strings.Contains(t, "agro") || strings.Contains(t, "commodity"):
		return UnderlyingAgroCommodity
	case strings.Contains(t, "export pre") ||
		strings.Contains(t, "export_pre") ||
		strings.Contains(t, "export-pre"):
		return UnderlyingExportPreFinance
	case strings.Contains(t, "export bill") ||
		strings.Contains(t, "factura export"):
		return UnderlyingExportBill
	case strings.Contains(t, "consumer") || strings.Contains(t, "personal"):
		return UnderlyingConsumerCredit
	}
	return UnderlyingUnknown
}

// detectTranche normalizes a tranche string.
func detectTranche(s string) TrancheClass {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "vrd"):
		switch {
		case strings.Contains(t, "senior") || strings.Contains(t, "sr"):
			return TrancheVRDSenior
		case strings.Contains(t, "mezzanine") || strings.Contains(t, "mez"):
			return TrancheVRDMezzanine
		case strings.Contains(t, "subordinated") || strings.Contains(t, "sub"):
			return TrancheVRDSubordinated
		}
		return TrancheVRDSenior
	case strings.Contains(t, "cp"):
		switch {
		case strings.Contains(t, "senior") || strings.Contains(t, "sr"):
			return TrancheCPSenior
		case strings.Contains(t, "equity") || strings.Contains(t, "eq"):
			return TrancheCPEquity
		}
		return TrancheCPEquity
	}
	return TrancheUnknown
}

// detectRating normalizes a rating string to the pinned enum.
func detectRating(s string) RatingClass {
	t := strings.ToUpper(strings.TrimSpace(s))
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
