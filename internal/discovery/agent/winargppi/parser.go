package winargppi

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// PPIFields captures scalar fields the audit pipeline needs
// from a PPI artifact.
type PPIFields struct {
	BearerToken             string
	GaliciaSSO              string
	Username                string
	ClienteCuitRaw          string
	BrokerMatricula         string
	DistinctSymbols         int64
	InternationalCount      int64
	CERUVACount             int64
	PortfolioAUMUSDCents    int64
	HasPassword             bool
	HasWealthMarker         bool
	HasCorporateMarker      bool
	HasInternacionalMarker  bool
	HasQuantImport          bool
	HasPerfilInversorMarker bool
}

// bearerRE matches an access-token / bearer / api-token.
var bearerRE = regexp.MustCompile(
	`(?i)("|')?(?:access[_-]?token|bearer|api[_-]?token|jwt|ppi[_-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{20,})`,
)

// galiciaSSORE matches a Banco Galicia SSO token / session.
var galiciaSSORE = regexp.MustCompile(
	`(?i)("|')?(?:galicia[_-]?sso|galicia[_-]?token|bg[_-]?sso|sso[_-]?galicia|bg[_-]?session|galicia[_-]?session)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{20,})`,
)

// usernameRE matches `username` / `user` / `email`.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:username|user|email|usuario)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// passwordRE matches a password row (line-anchored INI/JSON).
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|clave|pass|passwd)"?\s*[:=]\s*\S+`,
)

// passwordXMLRE matches `<password>…</password>`.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|clave)\s*>[^<\n]{1,}<\s*/\s*(?:password|clave)\s*>`,
)

// passwordInlineRE matches `password="..."` mid-line in Py source.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|clave|passwd)\s*=\s*["'][^"']{1,}["']`,
)

// ppiQuantImportRE detects PPI Quant SDK import.
var ppiQuantImportRE = regexp.MustCompile(
	`(?im)^\s*(?:from\s+ppi_?quant|import\s+ppi_?quant|from\s+ppi_api|import\s+ppi_api|from\s+pyppi|import\s+pyppi)`,
)

// wealthMarkerRE detects PPI Wealth markers.
var wealthMarkerRE = regexp.MustCompile(
	`(?i)(?:ppi[_\- ]?wealth|wealth[_\- ]?portfolio|managed[_\- ]?portfolio|portafolio[_\- ]?sugerido|portfolio[_\- ]?advisor)`,
)

// corporateMarkerRE detects Cuenta Empresa / corporate-treasury markers.
var corporateMarkerRE = regexp.MustCompile(
	`(?i)(?:cuenta[_\- ]?empresa|cuenta[_\- ]?corporativa|corporate[_\- ]?treasury|tesoreria[_\- ]?corporativa|persona[_\- ]?juridica|cuit[_\- ]?empresa)`,
)

// internacionalMarkerRE detects PPI Internacional / US-equity markers.
var internacionalMarkerRE = regexp.MustCompile(
	`(?i)(?:ppi[_\- ]?internacional|cuenta[_\- ]?internacional|us[_\- ]?equity|us[_\- ]?stocks|cedear[_\- ]?internacional|international[_\- ]?portfolio)`,
)

// perfilInversorMarkerRE detects a Perfil del Inversor survey body.
var perfilInversorMarkerRE = regexp.MustCompile(
	`(?i)(?:perfil[_\- ]?inversor|perfil[_\- ]?del[_\- ]?inversor|tolerancia[_\- ]?al[_\- ]?riesgo|risk[_\- ]?tolerance|horizonte[_\- ]?temporal|objetivo[_\- ]?inversion)`,
)

// symbolEntryRE matches a JSON/INI symbol entry.
var symbolEntryRE = regexp.MustCompile(
	`(?i)"?(?:symbol|simbolo|s[ií]mbolo|ticker|especie|instrumento)"?\s*[:=]\s*"?([A-Za-z0-9_\-\./]{2,32})`,
)

// notionalUSDRE matches USD-denominated amounts.
var notionalUSDRE = regexp.MustCompile(
	`(?i)(?:notional[_\- ]?usd|usd[_\- ]?amount|importe[_\- ]?usd|monto[_\- ]?usd|valor[_\- ]?usd|valor_mercado_usd|market_value_usd|aum_usd)"?\s*[:=]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// clienteCuitXMLRE matches `<cliente_cuit>…</cliente_cuit>`.
var clienteCuitXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:cliente[_\-]?cuit|cuit[_\-]?cliente|titular[_\-]?cuit|cuit)\s*>(\d{2}-?\d{8}-?\d)`,
)

// ParsePPICredentials parses a credentials / config body.
func ParsePPICredentials(body []byte) PPIFields {
	var out PPIFields
	if len(body) == 0 {
		return out
	}
	if passwordXMLRE.Match(body) || passwordRE.Match(body) ||
		passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := bearerRE.FindSubmatch(body); len(m) > 3 {
		out.BearerToken = string(m[3])
	}
	if m := galiciaSSORE.FindSubmatch(body); len(m) > 3 {
		out.GaliciaSSO = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	out.ClienteCuitRaw = cuitFromBody(body)
	out.BrokerMatricula = MatriculaFromText(string(body))
	return out
}

// ParsePPIPositions parses a positions cache.
func ParsePPIPositions(body []byte) PPIFields {
	var out PPIFields
	if len(body) == 0 {
		return out
	}
	syms := collectSymbols(body)
	out.DistinctSymbols = int64(len(syms))
	out.CERUVACount = countCERUVA(syms)
	out.InternationalCount = countUSEquityCEDEARs(syms)
	out.PortfolioAUMUSDCents = sumUSDAmounts(body)
	out.HasInternacionalMarker = internacionalMarkerRE.Match(body)
	out.HasWealthMarker = wealthMarkerRE.Match(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParsePPIOrders parses an orders cache.
func ParsePPIOrders(body []byte) PPIFields {
	out := ParsePPIPositions(body)
	return out
}

// ParsePPIWealthPortfolio parses a PPI Wealth portfolio.
func ParsePPIWealthPortfolio(body []byte) PPIFields {
	out := ParsePPIPositions(body)
	out.HasWealthMarker = true
	return out
}

// ParsePPICorporateTreasury parses a Cuenta Empresa file.
func ParsePPICorporateTreasury(body []byte) PPIFields {
	out := ParsePPIPositions(body)
	out.HasCorporateMarker = true
	if !out.HasCorporateMarker {
		out.HasCorporateMarker = corporateMarkerRE.Match(body)
	}
	return out
}

// ParsePPIPerfilInversor parses a Perfil del Inversor survey.
func ParsePPIPerfilInversor(body []byte) PPIFields {
	var out PPIFields
	if len(body) == 0 {
		return out
	}
	out.HasPerfilInversorMarker = perfilInversorMarkerRE.Match(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	out.BrokerMatricula = MatriculaFromText(string(body))
	return out
}

// ParsePPIQuantScript parses a PPI Quant strategy script.
func ParsePPIQuantScript(body []byte) PPIFields {
	var out PPIFields
	if len(body) == 0 {
		return out
	}
	if ppiQuantImportRE.Match(body) {
		out.HasQuantImport = true
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := bearerRE.FindSubmatch(body); len(m) > 3 {
		out.BearerToken = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParsePPIInternacional parses a PPI Internacional positions
// file (US equity).
func ParsePPIInternacional(body []byte) PPIFields {
	out := ParsePPIPositions(body)
	out.HasInternacionalMarker = true
	return out
}

// ParsePPIAccountExport parses a generic account export.
func ParsePPIAccountExport(body []byte) PPIFields {
	out := ParsePPIPositions(body)
	return out
}

// ParsePPITaxStatement parses a tax-statement / Bienes file.
func ParsePPITaxStatement(body []byte) PPIFields {
	var out PPIFields
	if len(body) == 0 {
		return out
	}
	out.PortfolioAUMUSDCents = sumUSDAmounts(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
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

// collectSymbols returns distinct uppercase symbols.
func collectSymbols(body []byte) []string {
	seen := map[string]struct{}{}
	for _, m := range symbolEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// countCERUVA returns the count of CER/UVA inflation-linked
// symbols.
func countCERUVA(syms []string) int64 {
	var n int64
	for _, s := range syms {
		if IsCERUVASymbol(s) {
			n++
		}
	}
	return n
}

// countUSEquityCEDEARs returns the count of US-equity CEDEAR
// symbols (PPI Internacional surface).
func countUSEquityCEDEARs(syms []string) int64 {
	var n int64
	for _, s := range syms {
		if IsUSEquityCEDEAR(s) {
			n++
		}
	}
	return n
}

// sumUSDAmounts sums all USD-amount rows in body.
func sumUSDAmounts(body []byte) int64 {
	var total int64
	for _, m := range notionalUSDRE.FindAllSubmatch(body, -1) {
		if c := decimalToCents(string(m[1])); c > 0 {
			total += c
		}
	}
	return total
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
