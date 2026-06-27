package winargcohen

import (
	"regexp"
	"strconv"
	"strings"
)

// CohenFields captures scalar fields the audit pipeline needs
// from a Cohen artifact.
type CohenFields struct {
	OAuthToken           string
	Username             string
	CuentaComitente      string
	FIXSenderCompID      string
	ClienteCuitRaw       string
	BackofficeChannel    BackofficeChannel
	DistinctSymbols      int64
	AREquitySymbolsCount int64
	CEDEARSymbolsCount   int64
	CuotaparteCount      int64
	LiquidacionCount     int64
	HasPassword          bool
	HasOAuth             bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|cohen[_\-]?password|cliente[_\-]?password|backoffice[_\-]?password|fix[_\-]?password)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|cohen[_\-]?password|cohen[_\-]?secret|cliente[_\-]?password|backoffice[_\-]?password|fix[_\-]?password)\b"?\s*[:=]\s*["'][^"']{1,}["']`)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|cohen[_\-]?password|backoffice[_\-]?password)\s*>([^<]{1,})<\s*/`)

// oauthRefreshTokenRE matches an OAuth2 refresh token field.
// Cohen Mobile uses standard OAuth2 with `refresh_token` /
// `access_token` JSON keys.
var oauthRefreshTokenRE = regexp.MustCompile(
	`(?i)"?(?:refresh_token|access_token|oauth_token|cohen[_\-]?token|bearer[_\-]?token)"?\s*[:=>]\s*"([A-Za-z0-9_\-\.\+/=]{20,})"?`)

// usernameRE matches Cohen / cliente login. INI / JSON / XML
// separator forms (`[:=>]`) all supported.
var usernameRE = regexp.MustCompile(
	`(?i)"?(?:cohen[_\-]?username|cohen[_\-]?user|cliente[_\-]?user|backoffice[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=>]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`)

// cuentaComitenteRE matches the Cuenta Comitente number — 4 to
// 8 digit broker-side account identifier. Cohen specifically
// uses 4-6 digit numbers.
var cuentaComitenteRE = regexp.MustCompile(
	`(?i)"?(?:cuenta[_\- ]?comitente|comitente[_\- ]?nro|cta[_\- ]?comitente|nro[_\- ]?cuenta)"?\s*[:=>]\s*"?(\d{4,8})"?`)

// fixSenderCompIDRE matches a FIX SenderCompID — sign of a
// FIX session config to MAE / BYMA.
var fixSenderCompIDRE = regexp.MustCompile(
	`(?i)(?:SenderCompID|49=|sender[_\-]?comp[_\-]?id)\s*[:=>]\s*"?([A-Za-z0-9_\-\.]{2,32})`)

// cuotaparteCountRE matches a per-receipt cuotaparte count.
// Cohen AM receipts include `cuotapartes_emitidas` or
// `cantidad_cuotapartes` numeric field.
var cuotaparteCountRE = regexp.MustCompile(
	`(?i)"?(?:cuotapartes[_\- ]?emitidas|cantidad[_\- ]?cuotapartes|cuotapartes[_\- ]?suscriptas|cuotapartes[_\- ]?rescatadas|cuotaparte[_\- ]?count|nro[_\- ]?cuotapartes)"?\s*[:=>]\s*"?(\d{1,12}(?:[.,]\d+)?)`)

// liquidacionRowRE matches a per-liquidación CSV row. Cohen
// daily liquidación PDFs sometimes export to CSV with header
// `Fecha,Cuenta,Especie,Cantidad,Precio,Importe`. Data rows
// start with a date.
var liquidacionRowRE = regexp.MustCompile(
	`(?im)^\d{2}[/-]\d{2}[/-]\d{4},\d+,[A-Z][A-Z0-9.\-]{1,8},`)

// optionsSymbolRE matches an OCC-style option chain symbol.
var optionsSymbolRE = regexp.MustCompile(
	`(?i)\b([A-Z]{1,5}_\d{6}[CP]\d{8})\b`)

// symbolEntryRE matches a per-symbol entry in profile /
// statement / liquidación. Cohen profile JSON has `"especie":
// "GGAL"` keys (and may number them `especie2`, `especie3` for
// multi-position records); CSV liquidaciones have
// `<date>,<acct>,<TICKER>` data-row form (no per-row keyword
// markers).
var symbolEntryRE = regexp.MustCompile(
	`(?im)(?:"?(?:especie\d*|symbol(?:_?\w+)?|sym|ticker|instrument)"?\s*[:=]\s*"?|<(?:especie\d*|symbol|instrument)[^>]*>|^\d{2}[/-]\d{2}[/-]\d{4},\d+,)([A-Z][A-Z0-9_\-\./]{0,7})`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseCohenProfile parses a Cohen NetTrader profile body.
func ParseCohenProfile(body []byte) CohenFields {
	var out CohenFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := oauthRefreshTokenRE.FindSubmatch(body); len(m) > 1 {
		out.OAuthToken = string(m[1])
		out.HasOAuth = true
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if m := cuentaComitenteRE.FindSubmatch(body); len(m) > 1 {
		out.CuentaComitente = string(m[1])
	}
	if m := fixSenderCompIDRE.FindSubmatch(body); len(m) > 1 {
		out.FIXSenderCompID = string(m[1])
	}
	out.BackofficeChannel = detectBackoffice(body)
	out.AREquitySymbolsCount, out.CEDEARSymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseCohenSessionToken parses a session token body.
func ParseCohenSessionToken(body []byte) CohenFields {
	return ParseCohenProfile(body)
}

// ParseCohenMobileOAuth parses a Cohen Mobile OAuth body.
func ParseCohenMobileOAuth(body []byte) CohenFields {
	out := ParseCohenProfile(body)
	out.HasOAuth = out.HasOAuth || oauthRefreshTokenRE.Match(body)
	return out
}

// ParseCohenFCISubscription parses a Cohen AM suscripcion body.
func ParseCohenFCISubscription(body []byte) CohenFields {
	out := ParseCohenProfile(body)
	if m := cuotaparteCountRE.FindSubmatch(body); len(m) > 1 {
		raw := strings.ReplaceAll(strings.ReplaceAll(
			string(m[1]), ",", ""), ".", "")
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			out.CuotaparteCount = v
		}
	}
	return out
}

// ParseCohenFCIRedemption parses a Cohen AM rescate body.
func ParseCohenFCIRedemption(body []byte) CohenFields {
	return ParseCohenFCISubscription(body)
}

// ParseCohenCuotaparte parses a cuotaparte record body.
func ParseCohenCuotaparte(body []byte) CohenFields {
	return ParseCohenFCISubscription(body)
}

// ParseCohenLiquidacion parses a liquidación CSV/PDF body.
func ParseCohenLiquidacion(body []byte) CohenFields {
	out := ParseCohenProfile(body)
	out.LiquidacionCount = int64(len(liquidacionRowRE.FindAllIndex(body, -1)))
	return out
}

// ParseCohenResearch parses an equity research PDF body
// (PDF body parsed as text; we only count keywords).
func ParseCohenResearch(body []byte) CohenFields {
	out := ParseCohenProfile(body)
	return out
}

// ParseCohenSAGGM parses a SAGGM back-office config body.
func ParseCohenSAGGM(body []byte) CohenFields {
	out := ParseCohenProfile(body)
	if out.BackofficeChannel == "" || out.BackofficeChannel == BackofficeUnknown {
		out.BackofficeChannel = BackofficeSAGGMGalileo
	}
	return out
}

// ParseCohenFIXSession parses a FIX session cfg body.
func ParseCohenFIXSession(body []byte) CohenFields {
	out := ParseCohenProfile(body)
	if m := fixSenderCompIDRE.FindSubmatch(body); len(m) > 1 {
		out.FIXSenderCompID = string(m[1])
	}
	return out
}

// ParseCohenTradeConfirmation parses a boleto / trade confirm body.
func ParseCohenTradeConfirmation(body []byte) CohenFields {
	return ParseCohenLiquidacion(body)
}

// ParseCohenStatement parses an estado de cuenta body.
func ParseCohenStatement(body []byte) CohenFields {
	return ParseCohenLiquidacion(body)
}

// cuitFromBody returns the first cliente CUIT match.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectBackoffice sniffs body for back-office channel markers.
func detectBackoffice(body []byte) BackofficeChannel {
	s := strings.ToLower(string(body))
	switch {
	case strings.Contains(s, "saggm_galileo") ||
		strings.Contains(s, "saggm-galileo") ||
		strings.Contains(s, "saggm galileo") ||
		strings.Contains(s, "galileo"):
		return BackofficeSAGGMGalileo
	case strings.Contains(s, "saggm_mariva") ||
		strings.Contains(s, "saggm-mariva") ||
		strings.Contains(s, "saggm mariva") ||
		strings.Contains(s, "mariva"):
		return BackofficeSAGGMMariva
	case strings.Contains(s, "cohen_direct") ||
		strings.Contains(s, "cohen-direct") ||
		strings.Contains(s, "cohen direct"):
		return BackofficeCohenDirect
	case strings.Contains(s, "sintesis"):
		return BackofficeSintesis
	case strings.Contains(s, "[backoffice]"):
		return BackofficeCustom
	}
	return BackofficeUnknown
}

// classifySymbols returns counts of AR equity, CEDEAR, and
// total distinct symbols.
func classifySymbols(body []byte) (ar, cedear, total int64) {
	seen := map[string]struct{}{}
	arSet := map[string]struct{}{}
	cedearSet := map[string]struct{}{}
	for _, m := range optionsSymbolRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
	}
	for _, m := range symbolEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
		if IsAREquityStem(s) {
			arSet[s] = struct{}{}
		}
		if IsCEDEARStem(s) {
			cedearSet[s] = struct{}{}
		}
	}
	return int64(len(arSet)), int64(len(cedearSet)), int64(len(seen))
}
