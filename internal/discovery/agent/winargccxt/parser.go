package winargccxt

import (
	"bufio"
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// CCXTFields captures scalar fields the audit pipeline needs
// from a CCXT artifact.
type CCXTFields struct {
	ExchangeID           string
	ExchangeKey          string
	StrategyName         string
	ClienteCuitRaw       string
	DistinctExchanges    int64
	TradeCount           int64
	PeakAPICallsPerSec   int64
	TotalUSDTVolumeCents int64
	HasPassword          bool
	HasArgentine         bool
	HasGlobal            bool
	HasDerivatives       bool
	HasDEX               bool
	HasArbitrageBot      bool
	HasUSDTARSArbitrage  bool
	HasFundingRate       bool
}

// passwordRE matches a password row (line-anchored INI/JSON).
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line in Python.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|apiKey|secret)\s*=\s*["'][^"']{1,}["']`)

// exchangeIDRE matches a CCXT `exchange = ccxt.<id>(...)` form
// or `"exchange": "<id>"` config form.
var exchangeIDRE = regexp.MustCompile(
	`(?i)(?:ccxt\.|"exchange"\s*[:=]\s*"|exchange_id\s*[:=]\s*"|"id"\s*[:=]\s*")([a-z0-9_\-]{2,32})`)

// exchangeKeyRE matches a generic API key / secret. CCXT's
// canonical form is `apiKey` and `secret`.
var exchangeKeyRE = regexp.MustCompile(
	`(?i)"?(?:apiKey|api[_\-]?key|api[_\-]?secret|secret|private[_\-]?key|access[_\-]?token|consumer[_\-]?secret)"?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`)

// ccxtImportRE detects ccxt import in a Python source file.
// Word-boundary at end so `import ccxt` matches the same as
// `import ccxt as X` and `import ccxt.async_support`.
var ccxtImportRE = regexp.MustCompile(
	`(?im)^\s*(?:from\s+ccxt|import\s+ccxt\b)`)

// arbitrageRE detects arbitrage / triangular / spread markers.
var arbitrageRE = regexp.MustCompile(
	`(?i)(?:arbitrage|arbitraje|triangular|cross[_\- ]?exchange|spread[_\- ]?bot|price[_\- ]?spread|funding[_\- ]?spread)`)

// fundingRateRE detects perp funding-rate strategy markers.
var fundingRateRE = regexp.MustCompile(
	`(?i)(?:funding[_\- ]?rate|fundingrate|fr[_\- ]?arb|perp[_\- ]?spot|basis[_\- ]?trade)`)

// strategyNameRE matches a Python class / function name that
// looks like a strategy.
var strategyNameRE = regexp.MustCompile(
	`(?im)(?:^\s*class\s+|^\s*def\s+)([A-Z][A-Za-z0-9_]{2,64}|[a-z][a-z0-9_]{2,64})\s*[\(:]`)

// usdtARSRE detects USDT/ARS or USDT-ARS markers.
var usdtARSRE = regexp.MustCompile(
	`(?i)(?:USDT/ARS|USDTARS|USDT-ARS|usdt_ars|usdt-ars)`)

// timestampRE matches `YYYY-MM-DD HH:MM:SS`.
var timestampRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`)

// apiCallRE detects per-line API-call markers in trade logs.
var apiCallRE = regexp.MustCompile(
	`(?i)(?:GET\s+/|POST\s+/|fetch[_\-]?ticker|fetch[_\-]?order|fetch[_\-]?balance|create[_\-]?order|cancel[_\-]?order|fetch[_\-]?trades|api[_\-]?call)`)

// usdtAmountRE matches `usdt_amount=NN.NN` rows.
var usdtAmountRE = regexp.MustCompile(
	`(?i)(?:usdt[_\- ]?amount|usdt[_\- ]?volume|amount[_\- ]?usdt|volume[_\- ]?usdt|notional[_\- ]?usdt)"?\s*[:=]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseCCXTConfig parses a config / credentials body.
func ParseCCXTConfig(body []byte) CCXTFields {
	var out CCXTFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := exchangeIDRE.FindSubmatch(body); len(m) > 1 {
		out.ExchangeID = string(m[1])
	}
	if m := exchangeKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ExchangeKey = string(m[1])
	}
	out.DistinctExchanges = countDistinctExchanges(body)
	out.HasArgentine, out.HasGlobal, out.HasDerivatives, out.HasDEX = classifyExchangesInBody(body)
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteCuitRaw = string(m[1])
	}
	out.HasUSDTARSArbitrage = HasUSDTARSPattern(body)
	return out
}

// ParseCCXTExchangeKeys parses a per-exchange keys.json file.
func ParseCCXTExchangeKeys(body []byte) CCXTFields {
	return ParseCCXTConfig(body)
}

// ParseCCXTStrategyPy parses a Python strategy / arbitrage body.
func ParseCCXTStrategyPy(body []byte) CCXTFields {
	var out CCXTFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := exchangeKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ExchangeKey = string(m[1])
	}
	if m := exchangeIDRE.FindSubmatch(body); len(m) > 1 {
		out.ExchangeID = string(m[1])
	}
	out.DistinctExchanges = countDistinctExchanges(body)
	out.HasArgentine, out.HasGlobal, out.HasDerivatives, out.HasDEX = classifyExchangesInBody(body)
	if arbitrageRE.Match(body) {
		out.HasArbitrageBot = true
	}
	if fundingRateRE.Match(body) {
		out.HasFundingRate = true
	}
	if HasUSDTARSPattern(body) {
		out.HasUSDTARSArbitrage = true
	}
	if m := strategyNameRE.FindSubmatch(body); len(m) > 1 {
		out.StrategyName = string(m[1])
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseCCXTArbitrageBot parses an arbitrage bot script body.
// Same fields as strategy + always flags arbitrage.
func ParseCCXTArbitrageBot(body []byte) CCXTFields {
	out := ParseCCXTStrategyPy(body)
	out.HasArbitrageBot = true
	return out
}

// ParseCCXTTradeLog parses a trade-log file.
func ParseCCXTTradeLog(body []byte) CCXTFields {
	var out CCXTFields
	if len(body) == 0 {
		return out
	}
	out.TradeCount = int64(len(apiCallRE.FindAllIndex(body, -1)))
	out.PeakAPICallsPerSec = peakAPICallsPerSecond(body)
	out.DistinctExchanges = countDistinctExchanges(body)
	out.HasArgentine, out.HasGlobal, out.HasDerivatives, out.HasDEX = classifyExchangesInBody(body)
	for _, m := range usdtAmountRE.FindAllSubmatch(body, -1) {
		out.TotalUSDTVolumeCents += decimalToCents(string(m[1]))
	}
	if HasUSDTARSPattern(body) {
		out.HasUSDTARSArbitrage = true
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseCCXTBalanceSnapshot parses a per-exchange balance JSON.
func ParseCCXTBalanceSnapshot(body []byte) CCXTFields {
	var out CCXTFields
	if len(body) == 0 {
		return out
	}
	out.DistinctExchanges = countDistinctExchanges(body)
	out.HasArgentine, out.HasGlobal, out.HasDerivatives, out.HasDEX = classifyExchangesInBody(body)
	for _, m := range usdtAmountRE.FindAllSubmatch(body, -1) {
		out.TotalUSDTVolumeCents += decimalToCents(string(m[1]))
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// HasUSDTARSPattern reports a USDT/ARS pair marker.
func HasUSDTARSPattern(body []byte) bool {
	return usdtARSRE.Match(body)
}

// HasCCXTImport reports whether body imports ccxt.
func HasCCXTImport(body []byte) bool {
	return ccxtImportRE.Match(body)
}

// countDistinctExchanges returns the number of distinct CCXT
// exchange IDs referenced anywhere in body.
func countDistinctExchanges(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range exchangeIDRE.FindAllSubmatch(body, -1) {
		id := strings.ToLower(strings.TrimSpace(string(m[1])))
		if id == "" {
			continue
		}
		seen[id] = struct{}{}
	}
	return int64(len(seen))
}

// classifyExchangesInBody scans every exchange ID match and
// reports which membership classes fired.
func classifyExchangesInBody(body []byte) (ar, global, deriv, dex bool) {
	for _, m := range exchangeIDRE.FindAllSubmatch(body, -1) {
		id := strings.ToLower(strings.TrimSpace(string(m[1])))
		switch {
		case IsArgentineExchange(id):
			ar = true
		case IsDerivativesExchange(id):
			deriv = true
		case IsGlobalMajorExchange(id):
			global = true
		case IsDEXExchange(id):
			dex = true
		}
	}
	return ar, global, deriv, dex
}

// peakAPICallsPerSecond bucketed by HH:MM:SS timestamp prefix.
// Returns highest per-second bucket count.
func peakAPICallsPerSecond(body []byte) int64 {
	bucket := map[string]int64{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if !apiCallRE.Match(line) {
			continue
		}
		ts := timestampRE.Find(line)
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
