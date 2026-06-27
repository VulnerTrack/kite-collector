package winargsintesis

import (
	"regexp"
	"strconv"
	"strings"
)

// SintesisFields captures scalar fields the audit pipeline
// needs from a Sintesis FCI artifact.
type SintesisFields struct {
	DBConnString        string
	Username            string
	FCICode             string
	SociedadGerenteCUIT string
	ClienteCuitRaw      string
	ClienteDNI          string
	CuotapartistaCount  int64
	DistinctFCIsCount   int64
	NAVARSCents         int64
	AUMUSDCents         int64
	SuscripcionCount    int64
	RescateCount        int64
	MaxHolderPct        int
	PIISignalCount      int64
	HasPassword         bool
	HasDBCredentials    bool
	HasForeignResident  bool
}

// passwordRE matches a password row.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|sintesis[_\-]?password|db[_\-]?password|fci[_\-]?password)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|sintesis[_\-]?password|sintesis[_\-]?secret|db[_\-]?password|sql[_\-]?password|fci[_\-]?password)\s*=\s*["'][^"']{1,}["']`)

// dbConnRE detects a DB connection string. Sintesis backs onto
// SQL Server / Access / Oracle; connection strings carry
// either ODBC / ADO syntax or `Server=...;UID=...;Pwd=...`.
var dbConnRE = regexp.MustCompile(
	`(?i)(?:server|data\s*source|host)\s*=\s*[^;]+;.*?(?:uid|user\s*id|user)\s*=\s*[^;]+;.*?(?:pwd|password)\s*=\s*[^;]+`)

// usernameRE matches Sintesis / DB login.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:sintesis[_\-]?username|sintesis[_\-]?user|db[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`)

// fciCodeRE matches a CNV-registered FCI code in INI / JSON
// / XML form. The trailing separator class `[:=>]` covers
// `fci_code:`, `fci_code=`, and `<fci_code>` opening tag.
var fciCodeRE = regexp.MustCompile(
	`(?i)"?(?:fci[_\- ]?code|fci[_\- ]?codigo|fci[_\- ]?numero|cod[_\- ]?fci|codigo[_\- ]?fci|fci[_\- ]?id|nro[_\- ]?fci)"?\s*[:=>]\s*"?([A-Za-z0-9._\-]{1,32})`)

// sociedadGerenteRE matches the sociedad gerente CUIT in
// INI / JSON / XML form.
var sociedadGerenteRE = regexp.MustCompile(
	`(?i)"?(?:sociedad[_\- ]?gerente[_\- ]?cuit|sgte[_\- ]?cuit|gerente[_\- ]?cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// cuotapartistaRowRE matches a per-cuotapartista row marker.
// Also matches CSV data rows beginning with `\d+,NN-NNNNNNNN-N,`
// to count subscriber-detail rows even when the header keyword
// only appears once.
var cuotapartistaRowRE = regexp.MustCompile(
	`(?im)(?:cuotapartista[_\- ]?id|cuotapartista[_\- ]?nro|subscriber[_\- ]?id|holder[_\- ]?id|^\s*\d+,\d{2}-?\d{8}-?\d,)`)

// suscripcionRowRE matches per-row subscription marker. Also
// matches `s-\d+,` ID column on CSV data rows.
var suscripcionRowRE = regexp.MustCompile(
	`(?i)(?:suscripcion[_\- ]?id|suscripción[_\- ]?id|subscription[_\- ]?id|nuevo[_\- ]?aporte|orden[_\- ]?suscripcion|\bs-\d+,)`)

// rescateRowRE matches per-row redemption marker. Also matches
// `r-\d+,` CSV ID column and bare `rescate_id r-N` log entries.
var rescateRowRE = regexp.MustCompile(
	`(?i)(?:rescate[_\- ]?id|redemption[_\- ]?id|retiro[_\- ]?id|orden[_\- ]?rescate|\br-\d+,|rescate_id\s+r-\d+)`)

// navAmountRE matches a NAV (`vc` / `valor_cuota`) value.
var navAmountRE = regexp.MustCompile(
	`(?i)(?:valor[_\- ]?cuota|vc|valor[_\- ]?cuotaparte|nav)\s*[:=]\s*"?(\d+(?:[.,]\d+)?)`)

// aumUSDRE matches an AUM-in-USD field.
var aumUSDRE = regexp.MustCompile(
	`(?i)(?:aum[_\- ]?usd|patrimonio[_\- ]?usd|patrimonio[_\- ]?neto[_\- ]?usd|nav[_\- ]?total[_\- ]?usd)"?\s*[:=]\s*"?(\d+(?:[.,]\d+)?)`)

// maxHolderRE matches a max-holder concentration field
// (percentage 0-100).
var maxHolderRE = regexp.MustCompile(
	`(?i)(?:max[_\- ]?holder[_\- ]?pct|concentracion[_\- ]?max|concentración[_\- ]?max|top[_\- ]?holder[_\- ]?pct)"?\s*[:=]\s*"?(\d{1,3}(?:[.,]\d+)?)`)

// clienteDNIRE matches an AR DNI.
var clienteDNIRE = regexp.MustCompile(
	`(?i)\b(?:dni|documento|nro_documento|numero_documento)"?\s*[:=]\s*"?(\d{7,8})`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuotapartista[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// nameRE matches a name / nombre field.
var nameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:name|nombre|razon_social|razón_social|denominacion|denominación)"?\s*[:=]\s*"?[A-Za-zÁÉÍÓÚáéíóúÑñ]{2,40}`)

// cuitScanRE matches CUITs across body — for distinct count.
var cuitScanRE = regexp.MustCompile(`\b(\d{2})-?(\d{8})-?(\d)\b`)

// foreignResidentRE detects non-AR CUITs (55-prefix reserved).
var foreignResidentRE = regexp.MustCompile(
	`(?:^|\D)55-?\d{8}-?\d(?:\D|$)`)

// hrMarkerRE detects CNV Hecho Relevante content markers.
var hrMarkerRE = regexp.MustCompile(
	`(?i)(?:hecho[_\- ]?relevante|<hecho_relevante|<hecho>|cnv[_\- ]?hr|aif[_\- ]?submit|fecha[_\- ]?hecho)`)

// a5273MarkerRE detects BCRA A5273 report markers.
var a5273MarkerRE = regexp.MustCompile(
	`(?i)(?:a[_\-]?5273|composicion[_\- ]?cartera|composición[_\- ]?cartera|inversion[_\- ]?(?:fci|portfolio)|patrimonio[_\- ]?neto[_\- ]?diario)`)

// pagoRescateMarkerRE detects pago de rescate file markers.
var pagoRescateMarkerRE = regexp.MustCompile(
	`(?i)(?:pago[_\- ]?rescate|liquidacion[_\- ]?rescate|liquidación[_\- ]?rescate|sipap[_\- ]?settlement|bcra[_\- ]?settlement)`)

// ParseSintesisConfig parses sintesis.cfg / general cfg body.
func ParseSintesisConfig(body []byte) SintesisFields {
	var out SintesisFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := dbConnRE.FindString(string(body)); m != "" {
		out.DBConnString = m
		out.HasDBCredentials = true
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if m := fciCodeRE.FindSubmatch(body); len(m) > 1 {
		out.FCICode = string(m[1])
	}
	if m := sociedadGerenteRE.FindSubmatch(body); len(m) > 1 {
		out.SociedadGerenteCUIT = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	if m := clienteDNIRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteDNI = string(m[1])
	}
	out.PIISignalCount = piiBundleSignalCount(body, out.ClienteCuitRaw,
		out.ClienteDNI)
	return out
}

// ParseSintesisCredentials parses a credentials body.
func ParseSintesisCredentials(body []byte) SintesisFields {
	return ParseSintesisConfig(body)
}

// ParseSintesisFCIDatabase parses a Sintesis .sdb / .mdb body.
// We can't parse Access-format binaries — we just sniff the
// plaintext header for FCI code + cliente CUIT counts.
func ParseSintesisFCIDatabase(body []byte) SintesisFields {
	var out SintesisFields
	if len(body) == 0 {
		return out
	}
	if m := fciCodeRE.FindSubmatch(body); len(m) > 1 {
		out.FCICode = string(m[1])
	}
	if m := sociedadGerenteRE.FindSubmatch(body); len(m) > 1 {
		out.SociedadGerenteCUIT = string(m[1])
	}
	out.CuotapartistaCount = countDistinctCUITs(body)
	if foreignResidentRE.Match(body) {
		out.HasForeignResident = true
	}
	return out
}

// ParseSintesisNAVCalc parses a daily NAV body.
func ParseSintesisNAVCalc(body []byte) SintesisFields {
	var out SintesisFields
	if len(body) == 0 {
		return out
	}
	if m := fciCodeRE.FindSubmatch(body); len(m) > 1 {
		out.FCICode = string(m[1])
	}
	if m := navAmountRE.FindSubmatch(body); len(m) > 1 {
		raw := strings.ReplaceAll(strings.ReplaceAll(
			string(m[1]), ".", ""), ",", ".")
		v, err := strconv.ParseFloat(raw, 64)
		if err == nil {
			out.NAVARSCents = int64(v * 100)
		}
	}
	if m := aumUSDRE.FindSubmatch(body); len(m) > 1 {
		raw := strings.ReplaceAll(strings.ReplaceAll(
			string(m[1]), ".", ""), ",", ".")
		v, err := strconv.ParseFloat(raw, 64)
		if err == nil {
			out.AUMUSDCents = int64(v * 100)
		}
	}
	if m := maxHolderRE.FindSubmatch(body); len(m) > 1 {
		raw := strings.ReplaceAll(string(m[1]), ",", ".")
		v, err := strconv.ParseFloat(raw, 64)
		if err == nil {
			out.MaxHolderPct = int(v)
		}
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseSintesisCuotaparteLedger parses a per-cuotapartista
// holdings ledger.
func ParseSintesisCuotaparteLedger(body []byte) SintesisFields {
	var out SintesisFields
	if len(body) == 0 {
		return out
	}
	rows := int64(len(cuotapartistaRowRE.FindAllIndex(body, -1)))
	out.CuotapartistaCount = rows
	if rows == 0 {
		// Fallback — count distinct CUITs.
		out.CuotapartistaCount = countDistinctCUITs(body)
	}
	if m := fciCodeRE.FindSubmatch(body); len(m) > 1 {
		out.FCICode = string(m[1])
	}
	if m := maxHolderRE.FindSubmatch(body); len(m) > 1 {
		raw := strings.ReplaceAll(string(m[1]), ",", ".")
		v, err := strconv.ParseFloat(raw, 64)
		if err == nil {
			out.MaxHolderPct = int(v)
		}
	}
	if foreignResidentRE.Match(body) {
		out.HasForeignResident = true
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	if m := clienteDNIRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteDNI = string(m[1])
	}
	out.PIISignalCount = piiBundleSignalCount(body, out.ClienteCuitRaw,
		out.ClienteDNI)
	return out
}

// ParseSintesisSuscripcion parses a subscription file.
func ParseSintesisSuscripcion(body []byte) SintesisFields {
	var out SintesisFields
	if len(body) == 0 {
		return out
	}
	out.SuscripcionCount = int64(len(suscripcionRowRE.FindAllIndex(body, -1)))
	if m := fciCodeRE.FindSubmatch(body); len(m) > 1 {
		out.FCICode = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseSintesisRescate parses a redemption file.
func ParseSintesisRescate(body []byte) SintesisFields {
	var out SintesisFields
	if len(body) == 0 {
		return out
	}
	out.RescateCount = int64(len(rescateRowRE.FindAllIndex(body, -1)))
	if m := fciCodeRE.FindSubmatch(body); len(m) > 1 {
		out.FCICode = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseSintesisBCRAA5273 parses a BCRA A5273 composition report.
func ParseSintesisBCRAA5273(body []byte) SintesisFields {
	var out SintesisFields
	if len(body) == 0 {
		return out
	}
	if a5273MarkerRE.Match(body) {
		if m := sociedadGerenteRE.FindSubmatch(body); len(m) > 1 {
			out.SociedadGerenteCUIT = string(m[1])
		}
		if m := fciCodeRE.FindSubmatch(body); len(m) > 1 {
			out.FCICode = string(m[1])
		}
	}
	return out
}

// ParseSintesisCNVHR parses a CNV Hecho Relevante draft / submit
// body.
func ParseSintesisCNVHR(body []byte) SintesisFields {
	var out SintesisFields
	if len(body) == 0 {
		return out
	}
	if hrMarkerRE.Match(body) {
		if m := fciCodeRE.FindSubmatch(body); len(m) > 1 {
			out.FCICode = string(m[1])
		}
		if m := sociedadGerenteRE.FindSubmatch(body); len(m) > 1 {
			out.SociedadGerenteCUIT = string(m[1])
		}
	}
	return out
}

// ParseSintesisValuationFile parses an asset-valuation input.
func ParseSintesisValuationFile(body []byte) SintesisFields {
	return ParseSintesisNAVCalc(body)
}

// ParseSintesisPagoRescate parses a pago de rescate settlement
// file.
func ParseSintesisPagoRescate(body []byte) SintesisFields {
	var out SintesisFields
	if len(body) == 0 {
		return out
	}
	if pagoRescateMarkerRE.Match(body) {
		if m := fciCodeRE.FindSubmatch(body); len(m) > 1 {
			out.FCICode = string(m[1])
		}
	}
	out.RescateCount = int64(len(rescateRowRE.FindAllIndex(body, -1)))
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// cuitFromBody returns a cliente CUIT match.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// piiBundleSignalCount counts how many distinct PII signals
// the body carries.
func piiBundleSignalCount(body []byte, cuit, dni string) int64 {
	var n int64
	if cuit != "" {
		n++
	}
	if dni != "" {
		n++
	}
	if nameRE.Match(body) {
		n++
	}
	return n
}

// countDistinctCUITs returns the count of distinct cliente
// CUITs in the body (with a valid entity-prefix).
func countDistinctCUITs(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range cuitScanRE.FindAllSubmatch(body, -1) {
		prefix := string(m[1])
		if !IsValidCuitEntityPrefix(prefix) {
			continue
		}
		key := prefix + string(m[2]) + string(m[3])
		seen[key] = struct{}{}
	}
	return int64(len(seen))
}
