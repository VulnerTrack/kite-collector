package winargafiprg5193

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// AFIPFields captures scalar fields the audit pipeline needs
// from an AFIP artifact.
type AFIPFields struct {
	AFIPToken           string
	ReporterCuitRaw     string
	ClienteCuitRaw      string
	TransactionCount    int64
	CryptoTransactions  int64
	TotalVolumeARSCents int64
	TotalVolumeUSDCents int64
	DistinctClientes    int64
	HighValueCount      int64
	CrossBorderCount    int64
	HasPassword         bool
	HasGanancias        bool
	HasBienes           bool
	HasPIIBundle        bool
	HasCryptoMarker     bool
}

// afipTokenRE matches AFIP Clave Fiscal session token / JWT
// in INI / JSON form (`key: value` or `key=value`).
var afipTokenRE = regexp.MustCompile(
	`(?i)("|')?(?:clave[_\- ]?fiscal|afip[_\- ]?token|session[_\- ]?token|afip[_\- ]?sign|wsaa[_\- ]?token|ticket[_\- ]?acceso|sign[_\- ]?value)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{20,})`)

// afipTokenXMLRE matches XML-tag form `<clave_fiscal>X</...>`.
var afipTokenXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:clave[_\-]?fiscal|afip[_\-]?token|session[_\-]?token|wsaa[_\-]?token|ticket[_\-]?acceso|sign[_\-]?value)\s*>([A-Za-z0-9_\-\.\+/=]{20,})`)

// afipTokenFromBody extracts an AFIP token from either form.
func afipTokenFromBody(body []byte) string {
	if m := afipTokenRE.FindSubmatch(body); len(m) > 3 {
		return string(m[3])
	}
	if m := afipTokenXMLRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// passwordRE matches a password row (line-anchored INI/JSON/XML).
var passwordRE = regexp.MustCompile(
	`(?im)^\s*(?:<\s*)?"?(?:password|clave|pass|passwd|clave[_\- ]?fiscal)"?\s*(?:[:=>]|>)\s*\S+`)

// passwordXMLRE matches `<password>…</password>` on a single line.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|clave|clave[_\-]?fiscal)\s*>[^<\n]{1,}<\s*/\s*(?:password|clave|clave[_\-]?fiscal)\s*>`)

// reporterCuitRE matches a `reporter_cuit: NN-NNNNNNNN-N`.
var reporterCuitRE = regexp.MustCompile(
	`(?i)"?(?:reporter[_\- ]?cuit|cuit[_\- ]?informante|informante[_\- ]?cuit|alyc[_\- ]?cuit|broker[_\- ]?cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// reporterCuitXMLRE matches `<reporter_cuit>X</reporter_cuit>`.
var reporterCuitXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:reporter[_\-]?cuit|cuit[_\-]?informante|informante[_\-]?cuit|alyc[_\-]?cuit|broker[_\-]?cuit)\s*>(\d{2}-?\d{8}-?\d)`)

// reporterCuitFromBody extracts the reporter CUIT from either
// INI/JSON or XML-tag form.
func reporterCuitFromBody(body []byte) string {
	if m := reporterCuitRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	if m := reporterCuitXMLRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit|usuario[_\- ]?cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// clienteCuitXMLRE matches `<cliente_cuit>…</cliente_cuit>`.
var clienteCuitXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:cliente[_\-]?cuit|cuit[_\-]?cliente|titular[_\-]?cuit|cuit|usuario[_\-]?cuit)\s*>(\d{2}-?\d{8}-?\d)`)

// dniRE matches an Argentine DNI (7-8 digits).
var dniRE = regexp.MustCompile(
	`(?i)(?:^|\b)(?:dni|documento|d\.n\.i\.)\s*[:=#]?\s*(\d{7,8})\b`)

// fullNameRE matches an apellido + nombre PII bundle (loose).
var fullNameRE = regexp.MustCompile(
	`(?i)(?:apellido_nombre|apellido[\s_-]?y[\s_-]?nombre|nombre[\s_-]?completo|full[\s_-]?name|nombre[\s_-]?apellido)["'\s:=>]+([A-ZÁÉÍÓÚÑa-záéíóúñ\s,\.]{4,80})`)

// transactionEventRE matches a per-row transaction marker.
var transactionEventRE = regexp.MustCompile(
	`(?i)(?:operacion_id|operacion[_\- ]?id|transaction_id|transaccion[_\- ]?id|comprobante[_\- ]?id|nro[_\- ]?operacion|trade_id)`)

// cryptoMarkerRE detects crypto-asset reporting markers.
var cryptoMarkerRE = regexp.MustCompile(
	`(?i)(?:cripto|crypto|btc|eth|usdt|usdc|stablecoin|criptoactivo|criptomoneda|wallet[_\- ]?address|wallet_id|psav[_\- ]?id|exchange_id)`)

// gananciasRE detects income-tax retention markers.
var gananciasRE = regexp.MustCompile(
	`(?i)(?:ganancias[_\- ]?retencion|retencion[_\- ]?ganancias|impuesto[_\- ]?ganancias|rg830|rg[_\- ]?830|retencion[_\- ]?cuarta[_\- ]?categoria)`)

// bienesPersonalesRE detects bienes-personales markers.
var bienesPersonalesRE = regexp.MustCompile(
	`(?i)(?:bienes[_\- ]?personales|bienes[_\- ]?pers|wealth[_\- ]?tax|patrimonio[_\- ]?total|alicuota[_\- ]?bienes|patrimonio[_\- ]?neto)`)

// crossBorderRE detects cross-border transfer markers.
var crossBorderRE = regexp.MustCompile(
	`(?i)(?:cross[_\- ]?border|transferencia[_\- ]?exterior|foreign[_\- ]?transfer|external[_\- ]?wallet|exterior[_\- ]?cuit|cuenta[_\- ]?exterior|swift[_\- ]?code|iban|f8125|f_8125|f-8125)`)

// arsAmountRE captures an ARS-denominated amount row.
var arsAmountRE = regexp.MustCompile(
	`(?i)(?:importe[_\- ]?ars|monto[_\- ]?ars|valor[_\- ]?ars|amount[_\- ]?ars|ars[_\- ]?amount|notional[_\- ]?ars|importe|monto)"?\s*[:=]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// usdAmountRE captures a USD-denominated amount row.
var usdAmountRE = regexp.MustCompile(
	`(?i)(?:importe[_\- ]?usd|monto[_\- ]?usd|valor[_\- ]?usd|amount[_\- ]?usd|usd[_\- ]?amount|notional[_\- ]?usd|dolares?|dollar[_\- ]?amount)"?\s*[:=]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// ParseAFIPCredentials parses an api_key / clave-fiscal /
// config body.
func ParseAFIPCredentials(body []byte) AFIPFields {
	var out AFIPFields
	if len(body) == 0 {
		return out
	}
	if passwordXMLRE.Match(body) || passwordRE.Match(body) {
		out.HasPassword = true
	}
	out.AFIPToken = afipTokenFromBody(body)
	if r := reporterCuitFromBody(body); r != "" {
		out.ReporterCuitRaw = r
	}
	out.ClienteCuitRaw = cuitFromBody(body)
	return out
}

// ParseAFIPRG5193Daily parses a daily securities-transaction
// report under RG 5193.
func ParseAFIPRG5193Daily(body []byte) AFIPFields {
	var out AFIPFields
	if len(body) == 0 {
		return out
	}
	out.TransactionCount = int64(len(transactionEventRE.FindAllIndex(body, -1)))
	out.DistinctClientes = DistinctClientesInBody(body)
	if r := reporterCuitFromBody(body); r != "" {
		out.ReporterCuitRaw = r
	}
	out.HighValueCount = countHighValueTransactions(body)
	out.CrossBorderCount = int64(len(crossBorderRE.FindAllIndex(body, -1)))
	out.TotalVolumeARSCents = sumARSAmounts(body)
	out.TotalVolumeUSDCents = sumUSDAmounts(body)
	if hasPIINaturalPersonBundle(body) {
		out.HasPIIBundle = true
	}
	return out
}

// ParseAFIPRG5527Crypto parses a crypto-asset PSAV report
// under RG 5527.
func ParseAFIPRG5527Crypto(body []byte) AFIPFields {
	var out AFIPFields
	if len(body) == 0 {
		return out
	}
	out.HasCryptoMarker = cryptoMarkerRE.Match(body)
	out.CryptoTransactions = int64(len(transactionEventRE.FindAllIndex(body, -1)))
	if out.CryptoTransactions == 0 && out.HasCryptoMarker {
		out.CryptoTransactions = int64(len(cryptoMarkerRE.FindAllIndex(body, -1)))
	}
	out.DistinctClientes = DistinctClientesInBody(body)
	if r := reporterCuitFromBody(body); r != "" {
		out.ReporterCuitRaw = r
	}
	out.HighValueCount = countHighValueTransactions(body)
	out.CrossBorderCount = int64(len(crossBorderRE.FindAllIndex(body, -1)))
	out.TotalVolumeARSCents = sumARSAmounts(body)
	out.TotalVolumeUSDCents = sumUSDAmounts(body)
	if hasPIINaturalPersonBundle(body) {
		out.HasPIIBundle = true
	}
	return out
}

// ParseAFIPCOTI parses a COTI inversiones notice.
func ParseAFIPCOTI(body []byte) AFIPFields {
	var out AFIPFields
	if len(body) == 0 {
		return out
	}
	out.TransactionCount = int64(len(transactionEventRE.FindAllIndex(body, -1)))
	out.DistinctClientes = DistinctClientesInBody(body)
	if r := reporterCuitFromBody(body); r != "" {
		out.ReporterCuitRaw = r
	}
	out.TotalVolumeARSCents = sumARSAmounts(body)
	out.TotalVolumeUSDCents = sumUSDAmounts(body)
	out.HighValueCount = countHighValueTransactions(body)
	if hasPIINaturalPersonBundle(body) {
		out.HasPIIBundle = true
	}
	return out
}

// ParseAFIPGananciasRetenciones parses a ganancias retention.
func ParseAFIPGananciasRetenciones(body []byte) AFIPFields {
	var out AFIPFields
	if len(body) == 0 {
		return out
	}
	out.HasGanancias = gananciasRE.Match(body)
	out.TransactionCount = int64(len(transactionEventRE.FindAllIndex(body, -1)))
	out.DistinctClientes = DistinctClientesInBody(body)
	out.TotalVolumeARSCents = sumARSAmounts(body)
	if r := reporterCuitFromBody(body); r != "" {
		out.ReporterCuitRaw = r
	}
	if hasPIINaturalPersonBundle(body) {
		out.HasPIIBundle = true
	}
	return out
}

// ParseAFIPBienesPersonales parses a bienes-personales decl.
func ParseAFIPBienesPersonales(body []byte) AFIPFields {
	var out AFIPFields
	if len(body) == 0 {
		return out
	}
	out.HasBienes = bienesPersonalesRE.Match(body)
	out.TotalVolumeARSCents = sumARSAmounts(body)
	out.TotalVolumeUSDCents = sumUSDAmounts(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	if hasPIINaturalPersonBundle(body) {
		out.HasPIIBundle = true
	}
	return out
}

// ParseAFIPF8125Transfer parses an F.8125 transfer report.
func ParseAFIPF8125Transfer(body []byte) AFIPFields {
	var out AFIPFields
	if len(body) == 0 {
		return out
	}
	out.CrossBorderCount = int64(len(crossBorderRE.FindAllIndex(body, -1)))
	if out.CrossBorderCount == 0 {
		// F.8125 *is* the cross-border form — count rows as
		// transfer instances if no marker matched.
		out.CrossBorderCount = int64(len(transactionEventRE.FindAllIndex(body, -1)))
	}
	out.TotalVolumeARSCents = sumARSAmounts(body)
	out.TotalVolumeUSDCents = sumUSDAmounts(body)
	out.HighValueCount = countHighValueTransactions(body)
	out.DistinctClientes = DistinctClientesInBody(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	if hasPIINaturalPersonBundle(body) {
		out.HasPIIBundle = true
	}
	return out
}

// ParseAFIPExteriorizacion parses a foreign-asset declaration.
func ParseAFIPExteriorizacion(body []byte) AFIPFields {
	var out AFIPFields
	if len(body) == 0 {
		return out
	}
	out.TotalVolumeUSDCents = sumUSDAmounts(body)
	out.CrossBorderCount = int64(len(crossBorderRE.FindAllIndex(body, -1)))
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	if hasPIINaturalPersonBundle(body) {
		out.HasPIIBundle = true
	}
	return out
}

// ParseAFIPSessionToken parses a session-token / Clave Fiscal
// file.
func ParseAFIPSessionToken(body []byte) AFIPFields {
	var out AFIPFields
	if len(body) == 0 {
		return out
	}
	out.AFIPToken = afipTokenFromBody(body)
	if r := reporterCuitFromBody(body); r != "" {
		out.ReporterCuitRaw = r
	}
	return out
}

// cuitFromBody runs the key and XML form variants.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	if m := clienteCuitXMLRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// hasPIINaturalPersonBundle reports whether body contains a
// natural-person bundle (DNI + CUIT-natural + name) — the
// direct Ley 25.326 PII breach surface.
func hasPIINaturalPersonBundle(body []byte) bool {
	hasDNI := dniRE.Match(body)
	hasName := fullNameRE.Match(body)
	hasNaturalCuit := false
	for _, m := range cuitScanRE.FindAllSubmatch(body, -1) {
		if IsNaturalCuitPrefix(string(m[1])) {
			hasNaturalCuit = true
			break
		}
	}
	// Require ≥2 of {DNI, name, natural-CUIT} for bundle.
	count := 0
	if hasDNI {
		count++
	}
	if hasName {
		count++
	}
	if hasNaturalCuit {
		count++
	}
	return count >= 2
}

// sumARSAmounts sums all ARS-amount rows in body.
func sumARSAmounts(body []byte) int64 {
	var total int64
	for _, m := range arsAmountRE.FindAllSubmatch(body, -1) {
		if c := decimalToCents(string(m[1])); c > 0 {
			total += c
		}
	}
	return total
}

// sumUSDAmounts sums all USD-amount rows in body.
func sumUSDAmounts(body []byte) int64 {
	var total int64
	for _, m := range usdAmountRE.FindAllSubmatch(body, -1) {
		if c := decimalToCents(string(m[1])); c > 0 {
			total += c
		}
	}
	return total
}

// countHighValueTransactions counts USD-amount rows above the
// HighValueUSDCents threshold (F.8125 trigger).
func countHighValueTransactions(body []byte) int64 {
	var n int64
	for _, m := range usdAmountRE.FindAllSubmatch(body, -1) {
		if c := decimalToCents(string(m[1])); c >= HighValueUSDCents {
			n++
		}
	}
	for _, m := range arsAmountRE.FindAllSubmatch(body, -1) {
		if c := decimalToCents(string(m[1])); c >= HighValueARSCents {
			n++
		}
	}
	return n
}

// decimalToCents parses "1.234,56" or "1234.56" to cents.
func decimalToCents(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if strings.Count(s, ".") > 0 && strings.Count(s, ",") > 0 {
		s = strings.ReplaceAll(s, ".", "")
		s = strings.ReplaceAll(s, ",", ".")
	} else {
		s = strings.ReplaceAll(s, ",", ".")
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 {
		return 0
	}
	return int64(math.Round(f * 100))
}
