package winargsubcust

import (
	"regexp"
	"strconv"
	"strings"
)

// SubCustFields captures scalar fields the audit pipeline needs.
type SubCustFields struct {
	SubCustBank          SubCustBank
	GlobalCustodian      GlobalCustodian
	DGTTreatyCountry     DGTTreatyCountry
	SubCustCuitRaw       string
	ForeignTINCountry    string
	ForeignTINRaw        string
	SWIFTBIC             string
	OmnibusAccountRaw    string
	ForeignBOCount       int64
	OmnibusAccountCount  int64
	OmnibusValueARS      int64
	FXClearanceAmountUSD int64
	WithholdingAmountARS int64
	HasPassword          bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|subcust[_\-]?password|swift[_\-]?password|api[_\-]?token|api[_\-]?key|api[_\-]?secret)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|subcust[_\-]?password|swift[_\-]?password|bearer[_\-]?token)\b"?\s*[:=]\s*["'][^"']{1,}["']`,
)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|subcust[_\-]?password|swift[_\-]?password)\s*>([^<]{1,})<\s*/`,
)

// subCustBankRE matches a sub-cust bank marker in body.
var subCustBankRE = regexp.MustCompile(
	`(?i)\b(bny[_\- ]?galicia|citibank[_\- ]?ar|hsbc[_\- ]?ar|standard[_\- ]?bank|icbc[_\- ]?ar|santander[_\- ]?ar|bbva[_\- ]?ar|itau[_\- ]?ar|credit[_\- ]?agricole[_\- ]?ar|jpmorgan[_\- ]?ar)\b`,
)

// globalCustodianRE matches a global-custodian marker in body.
var globalCustodianRE = regexp.MustCompile(
	`(?i)\b(bny[_\- ]?mellon|citi[_\- ]?gca|hsbc[_\- ]?ss|jpmorgan[_\- ]?ss|state[_\- ]?street|northern[_\- ]?trust|brown[_\- ]?brothers[_\- ]?harriman|bbh|ssga|caja[_\- ]?de[_\- ]?valores|cvsa)\b`,
)

// dgtTreatyRE matches a DGT-treaty-country field.
var dgtTreatyRE = regexp.MustCompile(
	`(?i)"?(?:dgt[_\- ]?treaty[_\- ]?country|treaty[_\- ]?country|dgt[_\- ]?country|country[_\- ]?dgt)"?\s*[:=>]\s*"?(usa|united[_\- ]?states|spain|espana|chile|brazil|brasil|germany|alemania|uk|united[_\- ]?kingdom|reino[_\- ]?unido|canada|italy|italia|france|francia|netherlands|holanda|paises[_\- ]?bajos|switzerland|suiza)"?`,
)

// subCustCuitKeyRE matches sub-cust bank CUIT field.
var subCustCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:subcust[_\- ]?cuit|bank[_\- ]?cuit|entidad[_\- ]?cuit|cuit[_\- ]?banco|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// foreignTINRE matches foreign TIN field with country code.
var foreignTINRE = regexp.MustCompile(
	`(?i)"?(?:foreign[_\- ]?tin|fii[_\- ]?tin|nominee[_\- ]?tin|tin[_\- ]?foreign|tin)"?\s*[:=>]\s*"?([A-Z]{2,3})[\-_:\s]+([A-Z0-9\-]{4,32})"?`,
)

// swiftBICRE matches SWIFT BIC (8 or 11 alphanumeric chars).
var swiftBICRE = regexp.MustCompile(
	`(?i)"?(?:swift[_\- ]?bic|bic|swift[_\- ]?code|swift)"?\s*[:=>]\s*"?([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)"?`,
)

// omnibusAccountRE matches omnibus account identifier.
var omnibusAccountRE = regexp.MustCompile(
	`(?i)"?(?:omnibus[_\- ]?account|omnibus[_\- ]?id|omnibus[_\- ]?acct|nominee[_\- ]?account)"?\s*[:=>]\s*"?([A-Z0-9][A-Z0-9\-\._]{3,64})"?`,
)

// foreignBOCountRE matches foreign beneficial-owner count.
var foreignBOCountRE = regexp.MustCompile(
	`(?i)"?(?:foreign[_\- ]?bo[_\- ]?count|foreign[_\- ]?beneficial[_\- ]?owner[_\- ]?count|fii[_\- ]?count|beneficiarios[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// omnibusAccountCountRE matches omnibus account count.
var omnibusAccountCountRE = regexp.MustCompile(
	`(?i)"?(?:omnibus[_\- ]?account[_\- ]?count|omnibus[_\- ]?count|cuentas[_\- ]?omnibus[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// omnibusValueRE matches omnibus aggregate value in ARS.
var omnibusValueRE = regexp.MustCompile(
	`(?i)"?(?:omnibus[_\- ]?value[_\- ]?ars|omnibus[_\- ]?aggregate[_\- ]?ars|omnibus[_\- ]?vn[_\- ]?ars|valor[_\- ]?omnibus[_\- ]?ars)"?\s*[:=>]\s*"?(\d{1,15})`,
)

// fxClearanceAmountRE matches FX clearance amount in USD.
var fxClearanceAmountRE = regexp.MustCompile(
	`(?i)"?(?:fx[_\- ]?clearance[_\- ]?amount[_\- ]?usd|fx[_\- ]?amount[_\- ]?usd|mulc[_\- ]?amount[_\- ]?usd|monto[_\- ]?mulc[_\- ]?usd)"?\s*[:=>]\s*"?(\d{1,15})`,
)

// withholdingAmountRE matches withholding tax amount in ARS.
var withholdingAmountRE = regexp.MustCompile(
	`(?i)"?(?:withholding[_\- ]?amount[_\- ]?ars|retencion[_\- ]?amount[_\- ]?ars|iigg[_\- ]?retencion[_\- ]?ars|tax[_\- ]?withheld[_\- ]?ars)"?\s*[:=>]\s*"?(\d{1,15})`,
)

// ParseSubCust parses any sub-cust artifact body (shared parser).
func ParseSubCust(body []byte) SubCustFields {
	var out SubCustFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := subCustBankRE.FindSubmatch(body); len(m) > 1 {
		out.SubCustBank = detectSubCustBank(string(m[1]))
	}
	if m := globalCustodianRE.FindSubmatch(body); len(m) > 1 {
		out.GlobalCustodian = detectGlobalCustodian(string(m[1]))
	}
	if m := dgtTreatyRE.FindSubmatch(body); len(m) > 1 {
		out.DGTTreatyCountry = detectDGTCountry(string(m[1]))
	}
	if c := subCustCuitFromBody(body); c != "" {
		out.SubCustCuitRaw = c
	}
	if m := foreignTINRE.FindSubmatch(body); len(m) > 2 {
		out.ForeignTINCountry = strings.ToUpper(string(m[1]))
		out.ForeignTINRaw = string(m[2])
	}
	if m := swiftBICRE.FindSubmatch(body); len(m) > 1 {
		out.SWIFTBIC = strings.ToUpper(string(m[1]))
	}
	if m := omnibusAccountRE.FindSubmatch(body); len(m) > 1 {
		out.OmnibusAccountRaw = string(m[1])
	}
	if m := foreignBOCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.ForeignBOCount = v
		}
	}
	if m := omnibusAccountCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.OmnibusAccountCount = v
		}
	}
	if m := omnibusValueRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.OmnibusValueARS = v
		}
	}
	if m := fxClearanceAmountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.FXClearanceAmountUSD = v
		}
	}
	if m := withholdingAmountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.WithholdingAmountARS = v
		}
	}
	return out
}

// subCustCuitFromBody returns the first sub-cust bank CUIT
// match.
func subCustCuitFromBody(body []byte) string {
	if m := subCustCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectSubCustBank normalizes a sub-cust bank string.
func detectSubCustBank(s string) SubCustBank {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "bny") && strings.Contains(t, "galicia"):
		return BankBNYGalicia
	case strings.Contains(t, "citibank"):
		return BankCitibankAR
	case strings.Contains(t, "hsbc"):
		return BankHSBCAR
	case strings.Contains(t, "standard") || strings.Contains(t, "icbc"):
		return BankStandardBank
	case strings.Contains(t, "santander"):
		return BankSantanderAR
	case strings.Contains(t, "bbva"):
		return BankBBVAAR
	case strings.Contains(t, "itau"):
		return BankItauAR
	case strings.Contains(t, "agricole"):
		return BankCreditAgricoleAR
	case strings.Contains(t, "jpmorgan"):
		return BankJPMorganAR
	}
	return BankUnknown
}

// detectGlobalCustodian normalizes a global-custodian string.
func detectGlobalCustodian(s string) GlobalCustodian {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "bny") && strings.Contains(t, "mellon"):
		return GCBNYMellon
	case strings.Contains(t, "citi") && strings.Contains(t, "gca"):
		return GCCitiGCA
	case strings.Contains(t, "hsbc"):
		return GCHSBCSS
	case strings.Contains(t, "jpmorgan"):
		return GCJPMorganSS
	case strings.Contains(t, "state street"):
		return GCStateStreet
	case strings.Contains(t, "northern"):
		return GCNorthernTrust
	case strings.Contains(t, "brown brothers") || strings.Contains(t, "bbh"):
		return GCBrownBrothersHarriman
	case strings.Contains(t, "ssga"):
		return GCSSGA
	case strings.Contains(t, "caja") || strings.Contains(t, "cvsa"):
		return GCCajaDeValores
	}
	return GCUnknown
}

// detectDGTCountry normalizes a DGT-treaty-country string.
func detectDGTCountry(s string) DGTTreatyCountry {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "usa") || strings.Contains(t, "united states"):
		return DGTUSA
	case strings.Contains(t, "spain") || strings.Contains(t, "espana"):
		return DGTSpain
	case strings.Contains(t, "chile"):
		return DGTChile
	case strings.Contains(t, "brazil") || strings.Contains(t, "brasil"):
		return DGTBrazil
	case strings.Contains(t, "germany") || strings.Contains(t, "alemania"):
		return DGTGermany
	case strings.Contains(t, "uk") || strings.Contains(t, "united kingdom") ||
		strings.Contains(t, "reino unido"):
		return DGTUK
	case strings.Contains(t, "canada"):
		return DGTCanada
	case strings.Contains(t, "italy") || strings.Contains(t, "italia"):
		return DGTItaly
	case strings.Contains(t, "france") || strings.Contains(t, "francia"):
		return DGTFrance
	case strings.Contains(t, "netherlands") || strings.Contains(t, "holanda") ||
		strings.Contains(t, "paises bajos"):
		return DGTNetherlands
	case strings.Contains(t, "switzerland") || strings.Contains(t, "suiza"):
		return DGTSwitzerland
	}
	return DGTUnknown
}

// TINSuffix4 returns last 4 chars of a foreign TIN (preserving
// case-insensitivity).
func TINSuffix4(tin string) string {
	t := strings.ToUpper(strings.TrimSpace(tin))
	t = strings.ReplaceAll(t, "-", "")
	if len(t) < 4 {
		return t
	}
	return t[len(t)-4:]
}
