package winargpyhomebroker

import (
	"bufio"
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// PHBFields captures scalar fields the audit pipeline needs
// from a pyhomebroker artifact.
type PHBFields struct {
	Username                 string
	SessionCookieFingerprint string
	ClienteCuitRaw           string
	SessionFirstSeen         string
	SessionLastSeen          string
	Period                   string
	CookieCount              int64
	OrderCount               int64
	PollsPerMinMax           int64
	InstrumentCount          int64
	PortfolioCount           int64
	MaxPositionCents         int64
	HasCookies               bool
	HasUsername              bool
	HasPassword              bool
	Has2FA                   bool
	HasStrategyImport        bool
}

// usernameRE detects a `username`/`user`/`broker_user` row.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:username|user|broker[_-]?user|usuario|cuenta_usuario)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,64})"?`)

// passwordRE detects a `password`/`clave`/`broker_password` row.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|clave|broker[_-]?password|pass|passwd)"?\s*[:=]\s*\S+`)

// twofaRE detects a TOTP / 2FA secret row. Accepts optional
// `_secret` / `_key` / `_seed` suffix on the key token.
var twofaRE = regexp.MustCompile(
	`(?i)("|')?(?:totp|twofa|2fa|tfa)(?:[_-]?(?:secret|key|seed))?("|')?\s*[:=]\s*("|')?([A-Z2-7]{16,})`)

// cookieKeyRE matches a cookie key in a session jar (JSON
// list of cookie objects).
var cookieKeyRE = regexp.MustCompile(
	`(?i)("|')?(name|cookie[_-]?name|key)("|')?\s*[:=]\s*("|')?([A-Za-z0-9_\-.]{1,80})`)

// cookieValueRE matches a cookie value entry. Go regexp caps
// repeats at 1000; cookies longer than that are uncommon and
// the captured fragment still fingerprints the jar.
var cookieValueRE = regexp.MustCompile(
	`(?i)("|')?(value|cookie[_-]?value)("|')?\s*[:=]\s*("|')?([A-Za-z0-9+/=._\-]{8,1000})`)

// strategyImportRE detects an `import pyhomebroker` line.
var strategyImportRE = regexp.MustCompile(
	`(?im)^\s*(?:from\s+pyhomebroker|import\s+pyhomebroker|from\s+homebroker|import\s+homebroker)`)

// timestampMinRE matches `YYYY-MM-DD HH:MM[:SS]` at line start.
var timestampMinRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`)

// pollRE matches a poll / fetch / GET marker.
var pollRE = regexp.MustCompile(
	`(?i)(?:\bpoll\b|\bfetch\b|GET\s+/|HTTP\s+200|response_status|polled)`)

// orderEntryRE matches an order entry in cache JSON / log.
var orderEntryRE = regexp.MustCompile(
	`(?i)("|')?(order_id|order[_-]?number|orden_id|symbol|ticker)("|')?\s*[:=]\s*"`)

// positionRE matches a portfolio position entry. Accepts
// optional plural `s` suffix so `"positions":[]` matches.
var positionRE = regexp.MustCompile(
	`(?i)("|')?(positions?|posici[oó]nes?|holdings?|tenencias?)("|')?\s*[:=]\s*`)

// notionalRE matches a notional row with bounded numeric
// capture. Accepts optional surrounding quotes for JSON-quoted
// string values (`"valor_mercado":"5000000.00"`).
var notionalRE = regexp.MustCompile(
	`(?i)(?:valor_mercado|importe|monto|valor|notional|amount|total)"?\s*[:=]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// instrumentRE matches a symbol/ticker key in cache JSON.
var instrumentRE = regexp.MustCompile(
	`(?i)("|')?(symbol|ticker|especie|instrumento)("|')?\s*[:=]\s*"`)

// clienteCuitKeyRE matches a labeled cliente CUIT.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParsePHBConfig parses a pyhomebroker config.ini / .toml /
// .yaml body. Captures broker username/password/2fa presence.
func ParsePHBConfig(body []byte) PHBFields {
	var out PHBFields
	if len(body) == 0 {
		return out
	}
	if m := usernameRE.FindSubmatch(body); m != nil {
		out.HasUsername = true
		if len(m) > 1 {
			out.Username = string(m[1])
		}
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

// ParsePHBCredentials is a synonym for ParsePHBConfig — the
// credentials.json artifact shares the same structure.
func ParsePHBCredentials(body []byte) PHBFields {
	return ParsePHBConfig(body)
}

// ParsePHBSession parses a session cookie jar body. Counts
// cookie keys + computes a hash fingerprint over the values.
func ParsePHBSession(body []byte) PHBFields {
	var out PHBFields
	if len(body) == 0 {
		return out
	}
	out.CookieCount = int64(len(cookieKeyRE.FindAllIndex(body, -1)))
	if out.CookieCount > 0 {
		out.HasCookies = true
		// Fingerprint = hash of concatenated cookie values
		// (truncated). Captured for drift detection — the raw
		// values are NEVER persisted.
		vals := cookieValueRE.FindAllSubmatch(body, -1)
		if len(vals) > 0 {
			var sb strings.Builder
			for _, m := range vals {
				if len(m) > 5 {
					v := string(m[5])
					if len(v) > 32 {
						v = v[:32]
					}
					sb.WriteString(v)
					sb.WriteByte('|')
				}
			}
			out.SessionCookieFingerprint = sb.String()
		}
	}
	return out
}

// ParsePHBOrdersCache parses an orders-cache JSON body.
//
// Counts order entries, computes peak polls-per-minute by
// bucketing timestamps in the cache.
func ParsePHBOrdersCache(body []byte) PHBFields {
	var out PHBFields
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
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParsePHBPortfolio parses a portfolio-snapshot body.
func ParsePHBPortfolio(body []byte) PHBFields {
	var out PHBFields
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
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParsePHBMarketData parses a market-data cache. Captures
// instrument count.
func ParsePHBMarketData(body []byte) PHBFields {
	var out PHBFields
	if len(body) == 0 {
		return out
	}
	out.InstrumentCount = int64(len(instrumentRE.FindAllIndex(body, -1)))
	return out
}

// ParsePHBTradeLog parses a trade-log body. Same structure
// as orders cache.
func ParsePHBTradeLog(body []byte) PHBFields {
	return ParsePHBOrdersCache(body)
}

// ParsePHBStrategy detects pyhomebroker imports in .py / .ipynb.
func ParsePHBStrategy(body []byte) PHBFields {
	var out PHBFields
	if len(body) == 0 {
		return out
	}
	if strategyImportRE.Match(body) {
		out.HasStrategyImport = true
	}
	return out
}

// peakPollsPerMinute counts poll markers per per-minute bucket
// and returns the maximum.
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
