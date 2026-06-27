package winargprimary

import (
	"bufio"
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

// PrimaryFields captures scalar fields the audit pipeline
// needs from a Primary / pyRofex artifact.
type PrimaryFields struct {
	BearerToken       string
	RefreshToken      string
	ClienteCuitRaw    string
	AccountID         string
	SessionFirstSeen  string
	SessionLastSeen   string
	OrderCount        int64
	OrderPerMinMax    int64
	InstrumentCount   int64
	WSSubCount        int64
	MaxNotionalCents  int64
	HasPassword       bool
	HasStrategyImport bool
}

// bearerRE detects an `access_token`/`Bearer ...` row in a
// JSON / config body.
var bearerRE = regexp.MustCompile(
	`(?i)("|')?(access[_-]?token|bearer|auth[_-]?token)("|')?\s*[:=]\s*("|')?Bearer\s+([A-Za-z0-9_\-\.\+/=]{20,})|(?i)("|')?(access[_-]?token|bearer|auth[_-]?token)("|')?\s*[:=]\s*("|')?([A-Za-z0-9_\-\.\+/=]{20,})`)

// refreshRE detects a refresh_token row.
var refreshRE = regexp.MustCompile(
	`(?i)("|')?refresh[_-]?token("|')?\s*[:=]\s*("|')?([A-Za-z0-9_\-\.\+/=]{20,})`)

// passwordRE detects a Password / clave row in pyrofex INI.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*(?:password|clave|secret|api[_-]?secret)\s*[:=]\s*\S+`)

// strategyImportRE detects an `import pyRofex` / `from pyRofex
// import ...` line in a Python script.
var strategyImportRE = regexp.MustCompile(
	`(?im)^\s*(?:from\s+pyRofex|import\s+pyRofex|from\s+pyrofex|import\s+pyrofex)`)

// timestampMinuteRE matches per-minute timestamps in an
// orders log (`YYYY-MM-DD HH:MM`).
var timestampMinuteRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2})`)

// orderRE matches an order entry marker in the audit log
// (case-insensitive `order` keyword or HTTP POST /orders).
var orderRE = regexp.MustCompile(
	`(?i)(?:\border\b|POST\s+/orders|new[_-]?order|order[_-]?status|side\s*[:=]\s*(?:buy|sell))`)

// instrumentRE matches a `symbol`/`ticker`/`instrument_id`
// key in JSON / config bodies.
var instrumentRE = regexp.MustCompile(
	`(?i)("|')?(symbol|ticker|instrument_id|instrumentId)("|')?\s*[:=]\s*"`)

// wsSubRE matches a websocket subscription entry.
var wsSubRE = regexp.MustCompile(
	`(?i)("|')?(subscription|subscribe|topic)("|')?\s*[:=]\s*"`)

// cuentaKeyRE matches `cuenta_comitente: NNNNN`.
var cuentaKeyRE = regexp.MustCompile(
	`(?i)("|')?(cuenta_comitente|cuenta|account_id|account)("|')?\s*[:=]\s*"?(\d{4,12})"?`)

// notionalKeyRE matches `notional`/`amount` in an order log.
var notionalKeyRE = regexp.MustCompile(
	`(?i)("|')?(notional|amount|quantity|price)("|')?\s*[:=]\s*"?([0-9][0-9\.,]*)`)

// ParsePrimaryConfig parses a credentials.json / pyrofex.ini /
// config.yaml body. Captures bearer + refresh + password.
func ParsePrimaryConfig(body []byte) PrimaryFields {
	var out PrimaryFields
	if len(body) == 0 {
		return out
	}
	if m := bearerRE.FindSubmatch(body); m != nil {
		// Take the longest non-empty capture group (regex has
		// two alternatives with capture at m[5] or m[10]).
		var token string
		if len(m) > 5 && len(m[5]) > 0 {
			token = string(m[5])
		}
		if token == "" && len(m) > 10 && len(m[10]) > 0 {
			token = string(m[10])
		}
		if token != "" {
			out.BearerToken = token
		}
	}
	if m := refreshRE.FindSubmatch(body); m != nil {
		if len(m) > 4 {
			out.RefreshToken = string(m[4])
		}
	}
	if passwordRE.Match(body) {
		out.HasPassword = true
	}
	if m := cuentaKeyRE.FindSubmatch(body); m != nil {
		if len(m) > 4 {
			out.AccountID = string(m[4])
		}
	}
	if m := cuitRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1]) + string(m[2]) + string(m[3])
	}
	return out
}

// ParsePrimaryTokenCache parses a raw refresh_token /
// access_token file body. The body is the token itself.
func ParsePrimaryTokenCache(body []byte) PrimaryFields {
	var out PrimaryFields
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) >= 20 {
		out.RefreshToken = trimmed
	}
	return out
}

// ParsePrimaryOrderAudit parses an order audit log body.
//
// Counts orders, computes peak orders-per-minute, captures
// first/last timestamps and max-notional.
func ParsePrimaryOrderAudit(body []byte) PrimaryFields {
	var out PrimaryFields
	if len(body) == 0 {
		return out
	}
	// Order count = orderRE matches across body.
	out.OrderCount = int64(len(orderRE.FindAllIndex(body, -1)))
	// First/last timestamp.
	stamps := timestampMinuteRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	// Notional peak — scan all matches.
	for _, m := range notionalKeyRE.FindAllSubmatch(body, -1) {
		if len(m) < 5 {
			continue
		}
		cents := decimalToCents(string(m[4]))
		if cents > out.MaxNotionalCents {
			out.MaxNotionalCents = cents
		}
	}
	// Orders per minute peak — bucket by `YYYY-MM-DD HH:MM`.
	out.OrderPerMinMax = peakOrdersPerMinute(body)
	if m := cuentaKeyRE.FindSubmatch(body); m != nil {
		if len(m) > 4 {
			out.AccountID = string(m[4])
		}
	}
	if m := cuitRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1]) + string(m[2]) + string(m[3])
	}
	return out
}

// ParsePrimaryWSState parses a websocket subscription-state
// body. Counts subscription entries.
func ParsePrimaryWSState(body []byte) PrimaryFields {
	var out PrimaryFields
	if len(body) == 0 {
		return out
	}
	out.WSSubCount = int64(len(wsSubRE.FindAllIndex(body, -1)))
	return out
}

// ParsePrimaryInstrumentCache parses an instrument metadata
// cache. Counts symbol/ticker keys.
func ParsePrimaryInstrumentCache(body []byte) PrimaryFields {
	var out PrimaryFields
	if len(body) == 0 {
		return out
	}
	out.InstrumentCount = int64(len(instrumentRE.FindAllIndex(body, -1)))
	return out
}

// ParsePrimaryStrategy parses a .py / .ipynb body and
// detects pyRofex usage.
func ParsePrimaryStrategy(body []byte) PrimaryFields {
	var out PrimaryFields
	if len(body) == 0 {
		return out
	}
	if strategyImportRE.Match(body) {
		out.HasStrategyImport = true
	}
	return out
}

// peakOrdersPerMinute returns the highest number of order-RE
// matches falling inside any single per-minute bucket. Used
// to flag HFT activity.
func peakOrdersPerMinute(body []byte) int64 {
	bucket := map[string]int64{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if !orderRE.Match(line) {
			continue
		}
		ts := timestampMinuteRE.Find(line)
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
	if f <= 0 {
		return 0
	}
	return int64(f * 100)
}
