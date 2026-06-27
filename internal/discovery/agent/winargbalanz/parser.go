package winargbalanz

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// BalanzFields captures scalar fields the audit pipeline
// needs from a Balanz artifact.
type BalanzFields struct {
	BearerToken          string
	Username             string
	ClienteCuitRaw       string
	BrokerMatricula      string
	SessionFirstSeen     string
	SessionLastSeen      string
	DistinctSymbols      int64
	PortfolioCount       int64
	CaucionVolumeCents   int64
	CEDEARCount          int64
	LetrasCount          int64
	ONCount              int64
	FCISubscriptionCount int64
	HasPassword          bool
	IsAPI                bool
	IsDemo               bool
}

// bearerRE matches an `access_token` / `bearer` in credentials.
var bearerRE = regexp.MustCompile(
	`(?i)("|')?(?:access[_-]?token|bearer|api[_-]?token|jwt)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{20,})`)

// usernameRE matches `username` / `user` / `email`.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:username|user|email|usuario)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`)

// passwordRE matches a password row (line-anchored INI/JSON/XML).
var passwordRE = regexp.MustCompile(
	`(?im)^\s*(?:<\s*)?"?(?:password|clave|pass|passwd)"?\s*(?:[:=>]|>)\s*\S+`)

// passwordXMLRE matches `<password>…</password>` on a single
// line (Balanz Trader Pro settings.xml).
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|clave)\s*>[^<\n]{1,}<\s*/\s*(?:password|clave)\s*>`)

// passwordInlineRE matches `password="..."` mid-line in
// Python source (pyBalanz scripts).
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|clave|passwd)\s*=\s*["'][^"']{1,}["']`)

// apiClientRE detects pyBalanz import in a strategy script.
var apiClientRE = regexp.MustCompile(
	`(?im)^\s*(?:from\s+pybalanz|import\s+pybalanz|from\s+balanz_api|import\s+balanz_api|from\s+balanz\s+import)`)

// demoAccountRE detects a demo account marker.
var demoAccountRE = regexp.MustCompile(
	`(?i)\b(?:demo|simulator|sandbox|paper[_\- ]?trading|cuenta[_\- ]?demo|account[_\- ]?demo|test[_\- ]?env)\b`)

// timestampMinRE matches `YYYY-MM-DD HH:MM[:SS]`.
var timestampMinRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// clienteCuitXMLRE matches `<cliente_cuit>…</cliente_cuit>`.
var clienteCuitXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:cliente[_\-]?cuit|cuit[_\-]?cliente|titular[_\-]?cuit|cuit)\s*>(\d{2}-?\d{8}-?\d)`)

// symbolEntryRE matches a JSON/INI symbol entry.
var symbolEntryRE = regexp.MustCompile(
	`(?i)"?(?:symbol|simbolo|s[ií]mbolo|ticker|especie|instrumento)"?\s*[:=]\s*"?([A-Za-z0-9_\-\./]{2,32})`)

// positionEntryRE matches a position object marker.
var positionEntryRE = regexp.MustCompile(
	`(?i)"(?:positions?|posici[oó]nes?|holdings?|tenencias?|titulos?)"`)

// cedearEntryRE matches a CEDEAR entry header.
var cedearEntryRE = regexp.MustCompile(
	`(?i)"(?:cedear|cedeares|cedears)"`)

// letrasEntryRE matches a Letra entry header.
var letrasEntryRE = regexp.MustCompile(
	`(?i)"(?:letras?|lecap|boncer|bonte|tesoro)"`)

// onEntryRE matches an ON-corporate entry header.
var onEntryRE = regexp.MustCompile(
	`(?i)"(?:obligaciones[_\- ]?negociables|on[_\- ]?corporate|on[_\- ]?cache|corporate[_\- ]?bonds?|on_listing)"`)

// fciSubRE matches an FCI subscription entry.
var fciSubRE = regexp.MustCompile(
	`(?i)"(?:fci_id|fci_name|fondo_comun|subscripcion_fci|balanz_fci|balanz_capital)"`)

// caucionAmountRE matches a caución amount row.
var caucionAmountRE = regexp.MustCompile(
	`(?i)(?:caucion[_\- ]?amount|caucion[_\- ]?notional|caucion[_\- ]?monto|notional|importe|monto|valor)"?\s*[:=]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// ParseBalanzCredentials parses a credentials.json / api_key.json.
func ParseBalanzCredentials(body []byte) BalanzFields {
	var out BalanzFields
	if len(body) == 0 {
		return out
	}
	if m := bearerRE.FindSubmatch(body); len(m) > 3 {
		out.BearerToken = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if passwordXMLRE.Match(body) || passwordRE.Match(body) ||
		passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	out.ClienteCuitRaw = cuitFromBody(body)
	out.BrokerMatricula = MatriculaFromText(string(body))
	if demoAccountRE.Match(body) {
		out.IsDemo = true
	}
	return out
}

// ParseBalanzConfig parses a Balanz Trader Pro settings.xml /
// settings.ini / pyBalanz config.yaml.
func ParseBalanzConfig(body []byte) BalanzFields {
	out := ParseBalanzCredentials(body)
	return out
}

// ParseBalanzPositions parses a positions.json snapshot.
func ParseBalanzPositions(body []byte) BalanzFields {
	var out BalanzFields
	if len(body) == 0 {
		return out
	}
	out.PortfolioCount = int64(len(positionEntryRE.FindAllIndex(body, -1)))
	out.DistinctSymbols = countDistinctSymbols(body)
	out.LetrasCount = countLetrasSymbols(body)
	out.CEDEARCount = countCEDEARObjects(body)
	out.ONCount = countONObjects(body)
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseBalanzOrders parses an orders.json cache.
func ParseBalanzOrders(body []byte) BalanzFields {
	var out BalanzFields
	if len(body) == 0 {
		return out
	}
	stamps := timestampMinRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	out.DistinctSymbols = countDistinctSymbols(body)
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseBalanzCaucion parses a caucion_cache.json.
func ParseBalanzCaucion(body []byte) BalanzFields {
	var out BalanzFields
	if len(body) == 0 {
		return out
	}
	for _, m := range caucionAmountRE.FindAllSubmatch(body, -1) {
		if c := decimalToCents(string(m[1])); c > 0 {
			out.CaucionVolumeCents += c
		}
	}
	if out.CaucionVolumeCents == 0 && HasCaucionTicker(body) {
		// Presence-only signal even if no notional parsed.
		out.CaucionVolumeCents = 1
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseBalanzCEDEAR parses a cedear_cache.json.
func ParseBalanzCEDEAR(body []byte) BalanzFields {
	var out BalanzFields
	if len(body) == 0 {
		return out
	}
	out.CEDEARCount = int64(len(symbolEntryRE.FindAllIndex(body, -1)))
	if out.CEDEARCount == 0 && cedearEntryRE.Match(body) {
		out.CEDEARCount = 1
	}
	return out
}

// ParseBalanzLetras parses a letras / LECAP / BONCER cache.
func ParseBalanzLetras(body []byte) BalanzFields {
	var out BalanzFields
	if len(body) == 0 {
		return out
	}
	out.LetrasCount = countLetrasSymbols(body)
	if out.LetrasCount == 0 && letrasEntryRE.Match(body) {
		out.LetrasCount = 1
	}
	return out
}

// ParseBalanzON parses an Obligaciones Negociables cache.
func ParseBalanzON(body []byte) BalanzFields {
	var out BalanzFields
	if len(body) == 0 {
		return out
	}
	out.ONCount = countONObjects(body)
	if out.ONCount == 0 && onEntryRE.Match(body) {
		out.ONCount = 1
	}
	return out
}

// ParseBalanzFCI parses a Balanz Capital FCI subscriptions
// cache.
func ParseBalanzFCI(body []byte) BalanzFields {
	var out BalanzFields
	if len(body) == 0 {
		return out
	}
	out.FCISubscriptionCount = int64(len(fciSubRE.FindAllIndex(body, -1)))
	return out
}

// ParseBalanzStrategy parses a .py / .ipynb body and detects
// pyBalanz imports + hardcoded credentials.
func ParseBalanzStrategy(body []byte) BalanzFields {
	var out BalanzFields
	if len(body) == 0 {
		return out
	}
	if apiClientRE.Match(body) {
		out.IsAPI = true
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := bearerRE.FindSubmatch(body); len(m) > 3 {
		out.BearerToken = string(m[3])
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

// countDistinctSymbols returns the number of unique tickers.
func countDistinctSymbols(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range symbolEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	return int64(len(seen))
}

// countLetrasSymbols returns the number of unique letras
// tickers detected.
func countLetrasSymbols(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range symbolEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if IsLetraTicker(s) {
			seen[s] = struct{}{}
		}
	}
	return int64(len(seen))
}

// countCEDEARObjects returns the number of CEDEAR rows
// (counted from symbol entries near a "cedear" marker, or
// fallback to symbol total when explicit context exists).
func countCEDEARObjects(body []byte) int64 {
	if !cedearEntryRE.Match(body) {
		return 0
	}
	return int64(len(symbolEntryRE.FindAllIndex(body, -1)))
}

// countONObjects returns the number of ON rows.
func countONObjects(body []byte) int64 {
	if !onEntryRE.Match(body) {
		return 0
	}
	return int64(len(symbolEntryRE.FindAllIndex(body, -1)))
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
