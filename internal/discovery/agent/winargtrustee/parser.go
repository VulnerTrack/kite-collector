package winargtrustee

import (
	"regexp"
	"strconv"
	"strings"
)

// TrusteeFields captures scalar fields the audit pipeline needs.
type TrusteeFields struct {
	TrusteeFirm             TrusteeFirm
	ONClass                 ONClass
	DefaultStatus           DefaultStatus
	IssuerCuitRaw           string
	TrusteeCuitRaw          string
	ONSeriesID              string
	BondholderCount         int64
	OutstandingPrincipalARS int64
	AccruedInterestARS      int64
	CovenantBreachCount     int64
	DaysPastDue             int64
	HasPassword             bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|trustee[_\-]?password|tmf[_\-]?password|api[_\-]?token|api[_\-]?key|api[_\-]?secret)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|trustee[_\-]?password|tmf[_\-]?password|bearer[_\-]?token)\b"?\s*[:=]\s*["'][^"']{1,}["']`)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|trustee[_\-]?password|tmf[_\-]?password)\s*>([^<]{1,})<\s*/`)

// trusteeFirmRE matches a trustee-firm marker in body.
var trusteeFirmRE = regexp.MustCompile(
	`(?i)\b(tmf trust|tmf-trust|tmf argentina|tmf-argentina|bny mellon|bny-mellon|first trust|first-trust|equity trust|equity-trust|bice fideicomisos|bice-fideicomisos|rosario administradora|cohen trustee|cohen-trustee|hsbc trust|santander trust|aval federal trust|aval-federal-trust)\b`)

// onClassRE matches an ON-class field.
var onClassRE = regexp.MustCompile(
	`(?i)"?(?:on[_\- ]?class|tipo[_\- ]?on|on[_\- ]?type|obligacion[_\- ]?tipo)"?\s*[:=>]\s*"?(on[_\- ]?simple|simple|on[_\- ]?convertible|convertible|on[_\- ]?subordinated|subordinated|on[_\- ]?secured|secured|on[_\- ]?vrd[_\- ]?mixed|vrd[_\- ]?mixed|on[_\- ]?pyme|pyme|green[_\- ]?bond|social[_\- ]?bond|sustainability[_\- ]?linked|slb)"?`)

// defaultStatusRE matches a default-status field.
var defaultStatusRE = regexp.MustCompile(
	`(?i)"?(?:default[_\- ]?status|estado[_\- ]?incumplimiento|status)"?\s*[:=>]\s*"?(performing|cumpliendo|covenant[_\- ]?breach|incumplimiento[_\- ]?covenant|payment[_\- ]?default|default[_\- ]?pago|cross[_\- ]?default|acceleration|aceleracion|restructured|reestructurada|collateral[_\- ]?execution|ejecucion[_\- ]?garantia)"?`)

// issuerCuitKeyRE matches issuer CUIT field.
var issuerCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:issuer[_\- ]?cuit|emisor[_\- ]?cuit|deudor[_\- ]?cuit|cuit[_\- ]?emisor)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// trusteeCuitKeyRE matches trustee firm CUIT field.
var trusteeCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:trustee[_\- ]?cuit|fiduciario[_\- ]?cuit|representante[_\- ]?cuit|cuit[_\- ]?fiduciario|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// onSeriesIDRE matches ON series identifier (e.g., "YPF-Serie-12").
var onSeriesIDRE = regexp.MustCompile(
	`(?i)"?(?:on[_\- ]?series[_\- ]?id|on[_\- ]?series|serie[_\- ]?on|obligacion[_\- ]?serie|series[_\- ]?id)"?\s*[:=>]\s*"?([A-Z0-9][A-Z0-9\-\._]{1,64})"?`)

// bondholderCountRE matches bondholder count.
var bondholderCountRE = regexp.MustCompile(
	`(?i)"?(?:bondholder[_\- ]?count|obligacionistas[_\- ]?count|titulares[_\- ]?count|holders[_\- ]?total)"?\s*[:=>]\s*"?(\d{1,12})`)

// outstandingPrincipalRE matches outstanding principal in ARS.
var outstandingPrincipalRE = regexp.MustCompile(
	`(?i)"?(?:outstanding[_\- ]?principal[_\- ]?ars|principal[_\- ]?vivo[_\- ]?ars|capital[_\- ]?vivo[_\- ]?ars|vn[_\- ]?vivo[_\- ]?ars)"?\s*[:=>]\s*"?(\d{1,15})`)

// accruedInterestRE matches accrued interest in ARS.
var accruedInterestRE = regexp.MustCompile(
	`(?i)"?(?:accrued[_\- ]?interest[_\- ]?ars|intereses[_\- ]?devengados[_\- ]?ars|intereses[_\- ]?acumulados[_\- ]?ars)"?\s*[:=>]\s*"?(\d{1,15})`)

// covenantBreachCountRE matches covenant-breach count.
var covenantBreachCountRE = regexp.MustCompile(
	`(?i)"?(?:covenant[_\- ]?breach[_\- ]?count|breach[_\- ]?count|incumplimiento[_\- ]?covenant[_\- ]?count|covenants[_\- ]?en[_\- ]?breach)"?\s*[:=>]\s*"?(\d{1,12})`)

// daysPastDueRE matches days past due field.
var daysPastDueRE = regexp.MustCompile(
	`(?i)"?(?:days[_\- ]?past[_\- ]?due|dias[_\- ]?en[_\- ]?mora|dpd|days[_\- ]?in[_\- ]?arrears)"?\s*[:=>]\s*"?(\d{1,7})`)

// ParseTrustee parses any trustee artifact body (shared parser).
func ParseTrustee(body []byte) TrusteeFields {
	var out TrusteeFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := trusteeFirmRE.FindSubmatch(body); len(m) > 1 {
		out.TrusteeFirm = detectTrusteeFirm(string(m[1]))
	}
	if m := onClassRE.FindSubmatch(body); len(m) > 1 {
		out.ONClass = detectONClass(string(m[1]))
	}
	if m := defaultStatusRE.FindSubmatch(body); len(m) > 1 {
		out.DefaultStatus = detectDefaultStatus(string(m[1]))
	}
	if c := issuerCuitFromBody(body); c != "" {
		out.IssuerCuitRaw = c
	}
	if c := trusteeCuitFromBody(body); c != "" {
		out.TrusteeCuitRaw = c
	}
	if m := onSeriesIDRE.FindSubmatch(body); len(m) > 1 {
		out.ONSeriesID = string(m[1])
	}
	if m := bondholderCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.BondholderCount = v
		}
	}
	if m := outstandingPrincipalRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.OutstandingPrincipalARS = v
		}
	}
	if m := accruedInterestRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.AccruedInterestARS = v
		}
	}
	if m := covenantBreachCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.CovenantBreachCount = v
		}
	}
	if m := daysPastDueRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.DaysPastDue = v
		}
	}
	return out
}

// issuerCuitFromBody returns the first issuer CUIT match.
func issuerCuitFromBody(body []byte) string {
	if m := issuerCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// trusteeCuitFromBody returns the first trustee firm CUIT match.
func trusteeCuitFromBody(body []byte) string {
	if m := trusteeCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectTrusteeFirm normalizes a trustee-firm string.
func detectTrusteeFirm(s string) TrusteeFirm {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "tmf argentina") ||
		strings.Contains(t, "tmf-argentina"):
		return FirmTMFArgentina
	case strings.Contains(t, "tmf"):
		return FirmTMFTrust
	case strings.Contains(t, "bny"):
		return FirmBNYMellon
	case strings.Contains(t, "first trust") ||
		strings.Contains(t, "first-trust"):
		return FirmFirstTrust
	case strings.Contains(t, "equity trust") ||
		strings.Contains(t, "equity-trust"):
		return FirmEquityTrust
	case strings.Contains(t, "bice"):
		return FirmBICE
	case strings.Contains(t, "rosario"):
		return FirmRosarioAdministradora
	case strings.Contains(t, "cohen"):
		return FirmCohenTrustee
	case strings.Contains(t, "hsbc"):
		return FirmHSBCTrust
	case strings.Contains(t, "santander"):
		return FirmSantanderTrust
	case strings.Contains(t, "aval federal") ||
		strings.Contains(t, "aval-federal"):
		return FirmAvalFederalTrust
	}
	return FirmUnknown
}

// detectONClass normalizes an ON-class string.
func detectONClass(s string) ONClass {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "vrd"):
		return ONVRDMixed
	case strings.Contains(t, "convertible"):
		return ONConvertible
	case strings.Contains(t, "subordinated") || strings.Contains(t, "subordinada"):
		return ONSubordinated
	case strings.Contains(t, "secured") || strings.Contains(t, "garantizada"):
		return ONSecured
	case strings.Contains(t, "pyme"):
		return ONPyme
	case strings.Contains(t, "green"):
		return ONGreenBond
	case strings.Contains(t, "social"):
		return ONSocialBond
	case strings.Contains(t, "sustainability") || strings.Contains(t, "slb"):
		return ONSustainabilityLinked
	case strings.Contains(t, "simple") || t == "on":
		return ONSimple
	}
	return ONUnknown
}

// detectDefaultStatus normalizes a default-status string.
func detectDefaultStatus(s string) DefaultStatus {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "cross"):
		return StatusCrossDefault
	case strings.Contains(t, "covenant") || strings.Contains(t, "incumplimiento_covenant"):
		return StatusCovenantBreach
	case strings.Contains(t, "payment") || strings.Contains(t, "pago"):
		return StatusPaymentDefault
	case strings.Contains(t, "acceleration") || strings.Contains(t, "aceleracion"):
		return StatusAcceleration
	case strings.Contains(t, "restructured") || strings.Contains(t, "reestructurada"):
		return StatusRestructured
	case strings.Contains(t, "collateral") || strings.Contains(t, "ejecucion"):
		return StatusCollateralExecution
	case strings.Contains(t, "performing") || strings.Contains(t, "cumpliendo"):
		return StatusPerforming
	}
	return StatusUnknown
}
