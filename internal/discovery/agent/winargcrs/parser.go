package winargcrs

import (
	"regexp"
	"strconv"
	"strings"
)

// CRSFields captures scalar fields the audit pipeline needs from
// a CRS / FATCA artifact.
type CRSFields struct {
	ForeignTIN               string
	ForeignTINCountryCode    string
	ReportingFIGIIN          string
	AFIPReceiptID            string
	ClienteCuitRaw           string
	ReportingRegime          ReportingRegime
	CompetentAuthority       CompetentAuthority
	AccountHolderCount       int64
	BalanceTotalUSDThousands int64
	ReportableJurisdictions  int64
	HasPassword              bool
	HasMultiResidence        bool
	HasCRSXML                bool
	HasFATCAXML              bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|crs[_\-]?password|afip[_\-]?password|taxit[_\-]?password|filing[_\-]?password)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|crs[_\-]?password|afip[_\-]?password|taxit[_\-]?password|filing[_\-]?password)\b"?\s*[:=]\s*["'][^"']{1,}["']`)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|crs[_\-]?password|afip[_\-]?password)\s*>([^<]{1,})<\s*/`)

// foreignTINRE matches an OECD CRS foreign TIN element. CRS
// schema 2.0 uses `<crs:TIN issuedBy="XX">...</crs:TIN>` form.
var foreignTINRE = regexp.MustCompile(
	`(?is)<(?:crs:|fatca:|stf:)?TIN(?:\s+issuedBy\s*=\s*"([A-Z]{2})")?\s*>\s*([A-Za-z0-9\-]{5,40})\s*<`)

// foreignTINJSONRE matches a JSON form `"tin": "...", "tin_country":
// "..."`. The country may come either as `tin_country` or
// `issuedBy` separate field.
var foreignTINJSONRE = regexp.MustCompile(
	`(?i)"(?:foreign_tin|tin_number|tax_id|tin)"\s*:\s*"([A-Za-z0-9\-]{5,40})"[\s,\n]*(?:"(?:tin_country|tin_country_code|issued_by|country_code)"\s*:\s*"([A-Z]{2})")?`)

// giinRE matches a Global Intermediary Identification Number
// (GIIN). FATCA-registered FFIs have a 19-char dot-delimited
// GIIN: `XXXXXX.XXXXX.XX.XXX`.
var giinRE = regexp.MustCompile(
	`(?i)\b([A-Z0-9]{6}\.[A-Z0-9]{5}\.[A-Z]{2}\.[0-9]{3})\b`)

// afipReceiptRE matches an AFIP filing-receipt confirmation
// number. AFIP uses 13-15 digit confirmation numbers prefixed
// with `RG` or just numeric.
var afipReceiptRE = regexp.MustCompile(
	`(?i)"?(?:afip[_\-]?receipt|receipt[_\-]?id|confirmation[_\-]?id|nro[_\-]?presentacion|presentacion[_\-]?id|filing[_\-]?id)"?\s*[:=>]\s*"?([A-Z0-9\-]{6,32})"?`)

// accountHolderCountRE matches `<crs:AccountNumber>` repetition.
// CRS bodies list one `<AccountReport>` per account; counting
// `<AccountReport` opening tags gives the report volume.
var accountHolderCountRE = regexp.MustCompile(
	`(?i)<(?:crs:|fatca:|stf:)?AccountReport\b`)

// balanceUSDRE matches a USD balance amount field. CRS schema
// uses `<crs:AccountBalance currCode="USD">...</crs:AccountBalance>`.
var balanceUSDRE = regexp.MustCompile(
	`(?is)<(?:crs:|fatca:|stf:)?AccountBalance[^>]*currCode\s*=\s*"USD"[^>]*>\s*(\d{1,15}(?:\.\d+)?)\s*<`)

// balanceUSDJSONRE matches a JSON form `"balance_usd": <amount>`.
var balanceUSDJSONRE = regexp.MustCompile(
	`(?i)"(?:balance_usd|balance_dollars|account_balance_usd|balance)"\s*:\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`)

// reportableJurisdictionRE matches `<crs:ResCountryCode>XX</...>`.
var reportableJurisdictionRE = regexp.MustCompile(
	`(?i)<(?:crs:|fatca:|stf:)?ResCountryCode\s*>([A-Z]{2})<`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseCRSBody parses an OECD CRS XML body.
func ParseCRSBody(body []byte) CRSFields {
	out := parseCommon(body)
	out.ReportingRegime = RegimeCRS
	out.HasCRSXML = true
	out.AccountHolderCount = int64(len(accountHolderCountRE.FindAllIndex(body, -1)))
	if v, ok := sumUSDBalances(body); ok {
		out.BalanceTotalUSDThousands = v / 1000
	}
	out.ReportableJurisdictions = countReportableJurisdictions(body)
	if out.ReportableJurisdictions >= 2 {
		out.HasMultiResidence = checkTaxHavenMix(body)
	}
	return out
}

// ParseFATCABody parses an IRS FATCA XML body.
func ParseFATCABody(body []byte) CRSFields {
	out := parseCommon(body)
	out.ReportingRegime = RegimeFATCA
	out.HasFATCAXML = true
	out.AccountHolderCount = int64(len(accountHolderCountRE.FindAllIndex(body, -1)))
	if v, ok := sumUSDBalances(body); ok {
		out.BalanceTotalUSDThousands = v / 1000
	}
	return out
}

// ParseCompetentAuthority parses a CA-CA transmission XML body.
func ParseCompetentAuthority(body []byte) CRSFields {
	out := parseCommon(body)
	out.CompetentAuthority = detectCompetentAuthority(body)
	return out
}

// ParseAccountHolder parses an account-holder JSON body.
func ParseAccountHolder(body []byte) CRSFields {
	out := parseCommon(body)
	if v, ok := sumUSDBalances(body); ok {
		out.BalanceTotalUSDThousands = v / 1000
	}
	return out
}

// ParseSelfCertification parses a self-certification form body.
func ParseSelfCertification(body []byte) CRSFields {
	out := parseCommon(body)
	if out.ReportableJurisdictions >= 2 {
		out.HasMultiResidence = checkTaxHavenMix(body)
	}
	return out
}

// ParseW8BEN parses a W-8BEN attestation form body.
func ParseW8BEN(body []byte) CRSFields {
	return parseCommon(body)
}

// ParseW9 parses a W-9 attestation form body.
func ParseW9(body []byte) CRSFields {
	return parseCommon(body)
}

// ParseBalanceReport parses a balance CSV / XML body.
func ParseBalanceReport(body []byte) CRSFields {
	out := parseCommon(body)
	if v, ok := sumUSDBalances(body); ok {
		out.BalanceTotalUSDThousands = v / 1000
	}
	return out
}

// ParseAFIPReceipt parses an AFIP RG filing receipt body.
func ParseAFIPReceipt(body []byte) CRSFields {
	out := parseCommon(body)
	if m := afipReceiptRE.FindSubmatch(body); len(m) > 1 {
		out.AFIPReceiptID = string(m[1])
	}
	return out
}

// ParseConfig parses a generic CRS-tool config body.
func ParseConfig(body []byte) CRSFields {
	return parseCommon(body)
}

// parseCommon extracts the cross-cutting fields (password,
// foreign TIN, GIIN, cuit, reportable jurisdictions).
func parseCommon(body []byte) CRSFields {
	var out CRSFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := foreignTINRE.FindSubmatch(body); len(m) > 2 {
		out.ForeignTIN = string(m[2])
		if len(m[1]) > 0 {
			out.ForeignTINCountryCode = strings.ToUpper(string(m[1]))
		}
	}
	if out.ForeignTIN == "" {
		if m := foreignTINJSONRE.FindSubmatch(body); len(m) > 1 {
			out.ForeignTIN = string(m[1])
			if len(m) > 2 && len(m[2]) > 0 {
				out.ForeignTINCountryCode = strings.ToUpper(string(m[2]))
			}
		}
	}
	if m := giinRE.FindSubmatch(body); len(m) > 1 {
		out.ReportingFIGIIN = strings.ToUpper(string(m[1]))
	}
	out.ReportableJurisdictions = countReportableJurisdictions(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
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

// detectCompetentAuthority sniffs body for CA endpoint markers.
func detectCompetentAuthority(body []byte) CompetentAuthority {
	s := strings.ToLower(string(body))
	switch {
	case strings.Contains(s, "afip"):
		return CAAFIP
	case strings.Contains(s, "irs"):
		return CAIRS
	case strings.Contains(s, "hmrc"):
		return CAHMRC
	case strings.Contains(s, "ato"):
		return CAATO
	case strings.Contains(s, "cra-arc") || strings.Contains(s, "cra_arc") ||
		strings.Contains(s, "canada revenue"):
		return CACRA
	case strings.Contains(s, "sat-mexico") || strings.Contains(s, "sat_mexico") ||
		strings.Contains(s, "servicio de administracion tributaria"):
		return CASAT
	case strings.Contains(s, "sii-chile") || strings.Contains(s, "sii_chile") ||
		strings.Contains(s, "servicio impuestos internos"):
		return CASII
	case strings.Contains(s, "bzst") || strings.Contains(s, "bundeszentralamt"):
		return CABZSt
	case strings.Contains(s, "[ca]") || strings.Contains(s, "[competent_authority]"):
		return CACustom
	}
	return CAUnknown
}

// sumUSDBalances totals USD-denominated balances. Returns
// (sum, ok) where ok=true means at least one USD balance was
// found.
func sumUSDBalances(body []byte) (int64, bool) {
	var sum int64
	found := false
	for _, m := range balanceUSDRE.FindAllSubmatch(body, -1) {
		if len(m) <= 1 {
			continue
		}
		raw := strings.ReplaceAll(string(m[1]), ",", "")
		if dotIdx := strings.IndexByte(raw, '.'); dotIdx >= 0 {
			raw = raw[:dotIdx]
		}
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			sum += v
			found = true
		}
	}
	for _, m := range balanceUSDJSONRE.FindAllSubmatch(body, -1) {
		if len(m) <= 1 {
			continue
		}
		raw := strings.ReplaceAll(string(m[1]), ",", "")
		if dotIdx := strings.IndexByte(raw, '.'); dotIdx >= 0 {
			raw = raw[:dotIdx]
		}
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			sum += v
			found = true
		}
	}
	return sum, found
}

// countReportableJurisdictions counts distinct `<ResCountryCode>`
// values.
func countReportableJurisdictions(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range reportableJurisdictionRE.FindAllSubmatch(body, -1) {
		if len(m) <= 1 {
			continue
		}
		cc := strings.ToUpper(string(m[1]))
		if IsOECDReportableCountry(cc) {
			seen[cc] = struct{}{}
		}
	}
	return int64(len(seen))
}

// checkTaxHavenMix returns true if any of the listed residence
// countries is a tax haven (per the curated list).
func checkTaxHavenMix(body []byte) bool {
	for _, m := range reportableJurisdictionRE.FindAllSubmatch(body, -1) {
		if len(m) <= 1 {
			continue
		}
		cc := strings.ToUpper(string(m[1]))
		if IsTaxHavenCountry(cc) {
			return true
		}
	}
	return false
}
