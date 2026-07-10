package winargcocoscapital

import (
	"bufio"
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// CocosFields captures scalar fields the audit pipeline needs
// from a Cocos artifact.
type CocosFields struct {
	BearerToken          string
	RefreshToken         string
	Username             string
	ClienteCuitRaw       string
	SessionFirstSeen     string
	SessionLastSeen      string
	OrderCount           int64
	PollsPerMinMax       int64
	PortfolioCount       int64
	MaxPositionCents     int64
	USDTVolumeCents      int64
	FCISubscriptionCount int64
	HasPassword          bool
	Has2FA               bool
	HasMEPCCLArbitrage   bool
	HasStrategyImport    bool
}

// bearerRE matches an `access_token` in Cocos credentials.
var bearerRE = regexp.MustCompile(
	`(?i)("|')?access[_-]?token("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{20,})`,
)

// refreshRE matches `refresh_token`.
var refreshRE = regexp.MustCompile(
	`(?i)("|')?refresh[_-]?token("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{20,})`,
)

// usernameRE matches `username` / `user` / `email`.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:username|user|email|usuario)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// passwordRE matches a password row (line-anchored INI/JSON).
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|clave|pass|passwd)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line in
// Python source.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|clave|passwd)\s*=\s*["'][^"']{1,}["']`,
)

// twofaRE matches a TOTP / 2FA secret.
var twofaRE = regexp.MustCompile(
	`(?i)("|')?(?:totp|twofa|2fa|tfa)(?:[_-]?(?:secret|key|seed))?("|')?\s*[:=]\s*("|')?([A-Z2-7]{16,})`,
)

// strategyImportRE detects cocos-api / pycocos imports.
var strategyImportRE = regexp.MustCompile(
	`(?im)^\s*(?:from\s+cocos_api|import\s+cocos_api|from\s+pycocos|import\s+pycocos|from\s+cocos|import\s+cocos)`,
)

// timestampMinRE matches `YYYY-MM-DD HH:MM[:SS]`.
var timestampMinRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`,
)

// pollRE matches a poll / GET / fetch marker.
var pollRE = regexp.MustCompile(
	`(?i)(?:\bpoll\b|\bfetch\b|GET\s+/|HTTP\s+200|response_status|polled)`,
)

// orderEntryRE matches an order entry.
var orderEntryRE = regexp.MustCompile(
	`(?i)"(?:order_id|orden_id|orderid|order_number|numero_orden|simbolo|symbol|ticker)"`,
)

// positionRE matches a portfolio position entry.
var positionRE = regexp.MustCompile(
	`(?i)"(?:positions?|posici[oó]nes?|holdings?|tenencias?|titulos?)"`,
)

// fciSubRE matches an FCI subscription entry.
var fciSubRE = regexp.MustCompile(
	`(?i)"(?:fci_id|fci_subscription|fci_name|fondo_comun|subscripcion_fci)"`,
)

// usdtAmountRE matches `usdt_amount=NN.NN` / `ars_amount=NN`
// in a USDT trade log entry.
var usdtAmountRE = regexp.MustCompile(
	`(?i)(?:usdt[_\- ]?amount|ars[_\- ]?amount|notional|importe|monto)"?\s*[:=]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// notionalRE matches a notional row.
var notionalRE = regexp.MustCompile(
	`(?i)(?:valor_mercado|importe|monto|valor|notional|amount|total)"?\s*[:=]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`,
)

// mepStemRE matches the ARS-denominated bond stem.
var mepStemRE = regexp.MustCompile(
	`(?i)\b(?:AL30|AL35|AL41|GD30|GD35|GD38|GD41|GD46)\b`,
)

// mepDCRE matches the USD-MEP / USD-CCL bond counterpart.
var mepDCRE = regexp.MustCompile(
	`(?i)\b(?:AL30[DC]|AL35[DC]|AL41[DC]|GD30[DC]|GD35[DC]|GD38[DC]|GD41[DC]|GD46[DC])\b`,
)

// HasMEPCCLPattern reports whether body has both ARS bond
// stem AND MEP/CCL counterpart.
func HasMEPCCLPattern(body []byte) bool {
	return mepStemRE.Match(body) && mepDCRE.Match(body)
}

// ParseCocosCredentials parses a credentials.json / config body.
func ParseCocosCredentials(body []byte) CocosFields {
	var out CocosFields
	if len(body) == 0 {
		return out
	}
	if m := bearerRE.FindSubmatch(body); len(m) > 3 {
		out.BearerToken = string(m[3])
	}
	if m := refreshRE.FindSubmatch(body); len(m) > 3 {
		out.RefreshToken = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); m != nil {
		out.Username = string(m[1])
	}
	if passwordRE.Match(body) {
		out.HasPassword = true
	}
	if twofaRE.Match(body) {
		out.Has2FA = true
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	if out.ClienteCuitRaw == "" {
		if m := cuitRE.FindSubmatch(body); m != nil {
			out.ClienteCuitRaw = string(m[1]) + string(m[2]) + string(m[3])
		}
	}
	return out
}

// ParseCocosOrdersCache parses an orders-cache body.
func ParseCocosOrdersCache(body []byte) CocosFields {
	var out CocosFields
	if len(body) == 0 {
		return out
	}
	out.OrderCount = int64(len(orderEntryRE.FindAllIndex(body, -1)))
	out.PollsPerMinMax = peakPollsPerMinute(body)
	stamps := timestampMinRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	if HasMEPCCLPattern(body) {
		out.HasMEPCCLArbitrage = true
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseCocosPortfolio parses a portfolio snapshot.
func ParseCocosPortfolio(body []byte) CocosFields {
	var out CocosFields
	if len(body) == 0 {
		return out
	}
	out.PortfolioCount = int64(len(positionRE.FindAllIndex(body, -1)))
	for _, m := range notionalRE.FindAllSubmatch(body, -1) {
		cents := decimalToCents(string(m[1]))
		if cents > out.MaxPositionCents {
			out.MaxPositionCents = cents
		}
	}
	if HasMEPCCLPattern(body) {
		out.HasMEPCCLArbitrage = true
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseCocosUSDTLog parses a USDT pay / trade log.
func ParseCocosUSDTLog(body []byte) CocosFields {
	var out CocosFields
	if len(body) == 0 {
		return out
	}
	for _, m := range usdtAmountRE.FindAllSubmatch(body, -1) {
		if cents := decimalToCents(string(m[1])); cents > 0 {
			out.USDTVolumeCents += cents
		}
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseCocosFCISubscriptions parses an FCI subscriptions cache.
func ParseCocosFCISubscriptions(body []byte) CocosFields {
	var out CocosFields
	if len(body) == 0 {
		return out
	}
	out.FCISubscriptionCount = int64(len(fciSubRE.FindAllIndex(body, -1)))
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseCocosStrategy parses a .py / .ipynb body and detects
// cocos-api / pycocos imports + hardcoded credentials.
func ParseCocosStrategy(body []byte) CocosFields {
	var out CocosFields
	if len(body) == 0 {
		return out
	}
	if strategyImportRE.Match(body) {
		out.HasStrategyImport = true
	}
	if m := usernameRE.FindSubmatch(body); m != nil {
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

// peakPollsPerMinute returns highest per-minute bucketed
// poll count.
func peakPollsPerMinute(body []byte) int64 {
	bucket := map[string]int64{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if !pollRE.Match(line) {
			continue
		}
		ts := timestampMinRE.Find(line)
		if ts == nil {
			continue
		}
		bucket[string(ts)]++
	}
	var peak int64
	for _, v := range bucket {
		if v > peak {
			peak = v
		}
	}
	return peak
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
