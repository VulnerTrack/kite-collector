package winarglean

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// LeanFields captures scalar fields the audit pipeline needs
// from a LEAN artifact.
type LeanFields struct {
	BrokerageKey    string
	QCUserToken     string
	BrokerageName   string
	AlgorithmName   string
	ClienteCuitRaw  string
	Class           AlgorithmClass
	Resolution      DataResolution
	BacktestCount   int64
	DistinctSymbols int64
	SharpeRatioBps  int64
	AnnualReturnBps int64
	HasPassword     bool
	HasLiveMode     bool
	HasArgentine    bool
	HasCrypto       bool
	HasUSEquity     bool
	HasFutures      bool
}

// brokerageNameRE matches a `brokerage`/`live-mode-brokerage` key
// in a LEAN config (JSON or YAML form).
var brokerageNameRE = regexp.MustCompile(
	`(?i)"?(?:brokerage|live[_\-]?mode[_\-]?brokerage|live[_\-]?broker|broker(?:age)?[_\-]?type|live[_\-]?adapter)"?\s*[:=]\s*"?([A-Za-z0-9_\-\.]{3,64})"?`)

// liveModeRE detects `live-mode: true` / `"live-mode": true`.
var liveModeRE = regexp.MustCompile(
	`(?i)"?live[_\-]?mode"?\s*[:=]\s*"?(true|1|yes|on)"?`)

// brokerageKeyRE matches a generic API key / secret in any of
// the LEAN brokerage adapter forms.
var brokerageKeyRE = regexp.MustCompile(
	`(?i)"?(?:api[_\-]?key|api[_\-]?secret|access[_\-]?token|client[_\-]?secret|consumer[_\-]?key|private[_\-]?key|broker[_\-]?token|primary[_\-]?key|primary[_\-]?secret|ib[_\-]?user|ib[_\-]?password|alpaca[_\-]?key|alpaca[_\-]?secret|coinbase[_\-]?key|coinbase[_\-]?secret|binance[_\-]?key|binance[_\-]?secret)"?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`)

// qcUserTokenRE matches a QuantConnect user token / cloud creds.
var qcUserTokenRE = regexp.MustCompile(
	`(?i)"?(?:user[_\-]?token|qc[_\-]?token|api[_\-]?access[_\-]?token|cloud[_\-]?token|quantconnect[_\-]?token)"?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`)

// passwordRE matches a password row (line-anchored INI/JSON/XML).
var passwordRE = regexp.MustCompile(
	`(?im)^\s*(?:<\s*)?"?(?:password|passwd|clave)"?\s*(?:[:=>]|>)\s*\S+`)

// passwordXMLRE matches `<password>…</password>` on a single line.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|clave)\s*>[^<\n]{1,}<\s*/\s*(?:password|passwd|clave)\s*>`)

// passwordInlineRE matches `password="..."` mid-line in Python
// or C# source.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|broker_token)\s*=\s*["'][^"']{1,}["']`)

// algorithmNameRE matches a LEAN algorithm class name (C#).
var algorithmNameRE = regexp.MustCompile(
	`(?im)(?:public\s+)?class\s+([A-Z][A-Za-z0-9_]{2,64})\s*:\s*QCAlgorithm`)

// algorithmPyNameRE matches a Python LEAN algorithm class name.
var algorithmPyNameRE = regexp.MustCompile(
	`(?im)class\s+([A-Z][A-Za-z0-9_]{2,64})\s*\(\s*QCAlgorithm\s*\)`)

// algorithmConfigNameRE matches algorithm-name in config JSON.
var algorithmConfigNameRE = regexp.MustCompile(
	`(?i)"?(?:algorithm[_\-]?type[_\-]?name|algorithm[_\-]?name|algorithm[_\-]?class)"?\s*[:=]\s*"?([A-Za-z0-9_\.\-]{3,64})"?`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// clienteCuitXMLRE matches `<cliente_cuit>…</cliente_cuit>`.
var clienteCuitXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:cliente[_\-]?cuit|cuit[_\-]?cliente|titular[_\-]?cuit|cuit)\s*>(\d{2}-?\d{8}-?\d)`)

// symbolEntryRE matches a JSON/INI symbol entry. LEAN often
// uses `AddEquity("GGAL")` form, so also detect quoted args.
var symbolEntryRE = regexp.MustCompile(
	`(?i)(?:Add(?:Equity|Option|Future|Forex|Crypto)\s*\(\s*"|"?(?:symbol|simbolo|ticker|instrument)"?\s*[:=]\s*"?)([A-Za-z0-9_\-\./]{2,32})`)

// sharpeRE matches a Sharpe-ratio metric in a backtest result.
var sharpeRE = regexp.MustCompile(
	`(?i)"?(?:sharpe[_\-]?ratio|sharpe)"?\s*[:=]\s*"?(-?[0-9]+(?:\.[0-9]+)?)"?`)

// annualReturnRE matches an annual-return metric.
var annualReturnRE = regexp.MustCompile(
	`(?i)"?(?:annual[_\-]?return|annualised[_\-]?return|annualized[_\-]?return|compounded[_\-]?annual[_\-]?return|cagr)"?\s*[:=]\s*"?(-?[0-9]+(?:\.[0-9]+)?)"?%?`)

// ParseLeanConfig parses a lean.json / config.json body.
func ParseLeanConfig(body []byte) LeanFields {
	var out LeanFields
	if len(body) == 0 {
		return out
	}
	if passwordXMLRE.Match(body) || passwordRE.Match(body) {
		out.HasPassword = true
	}
	if m := brokerageNameRE.FindSubmatch(body); len(m) > 1 {
		out.BrokerageName = string(m[1])
	}
	if m := brokerageKeyRE.FindSubmatch(body); len(m) > 1 {
		out.BrokerageKey = string(m[1])
	}
	if m := qcUserTokenRE.FindSubmatch(body); len(m) > 1 {
		out.QCUserToken = string(m[1])
	}
	if liveModeRE.Match(body) {
		out.HasLiveMode = true
	}
	if m := algorithmConfigNameRE.FindSubmatch(body); len(m) > 1 {
		out.AlgorithmName = string(m[1])
	}
	out.ClienteCuitRaw = cuitFromBody(body)
	if out.BrokerageName != "" {
		out.HasArgentine = IsArgentineBrokerage(out.BrokerageName)
		out.HasCrypto = IsCryptoBrokerage(out.BrokerageName)
		out.HasUSEquity = IsUSEquityBrokerage(out.BrokerageName)
	}
	return out
}

// ParseLeanCredentials parses a credentials / api-token body.
func ParseLeanCredentials(body []byte) LeanFields {
	return ParseLeanConfig(body)
}

// ParseLeanAlgorithmCS parses a C# QCAlgorithm body.
func ParseLeanAlgorithmCS(body []byte) LeanFields {
	var out LeanFields
	if len(body) == 0 {
		return out
	}
	if m := algorithmNameRE.FindSubmatch(body); len(m) > 1 {
		out.AlgorithmName = string(m[1])
	}
	out.Class = AlgorithmClassFromBody(body)
	out.Resolution = DataResolutionFromBody(body)
	out.DistinctSymbols = countDistinctSymbols(body)
	if passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := brokerageKeyRE.FindSubmatch(body); len(m) > 1 {
		out.BrokerageKey = string(m[1])
	}
	out.ClienteCuitRaw = cuitFromBody(body)
	return out
}

// ParseLeanAlgorithmPy parses a Python QCAlgorithm body.
func ParseLeanAlgorithmPy(body []byte) LeanFields {
	var out LeanFields
	if len(body) == 0 {
		return out
	}
	if m := algorithmPyNameRE.FindSubmatch(body); len(m) > 1 {
		out.AlgorithmName = string(m[1])
	}
	out.Class = AlgorithmClassFromBody(body)
	out.Resolution = DataResolutionFromBody(body)
	out.DistinctSymbols = countDistinctSymbols(body)
	if passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := brokerageKeyRE.FindSubmatch(body); len(m) > 1 {
		out.BrokerageKey = string(m[1])
	}
	out.ClienteCuitRaw = cuitFromBody(body)
	return out
}

// ParseLeanBacktestResult parses a backtest result JSON.
func ParseLeanBacktestResult(body []byte) LeanFields {
	var out LeanFields
	if len(body) == 0 {
		return out
	}
	out.BacktestCount = 1
	if m := sharpeRE.FindSubmatch(body); len(m) > 1 {
		out.SharpeRatioBps = parseRatioToBps(string(m[1]))
	}
	if m := annualReturnRE.FindSubmatch(body); len(m) > 1 {
		out.AnnualReturnBps = parseRatioToBps(string(m[1]))
	}
	if m := algorithmConfigNameRE.FindSubmatch(body); len(m) > 1 {
		out.AlgorithmName = string(m[1])
	}
	out.DistinctSymbols = countDistinctSymbols(body)
	return out
}

// ParseLeanLiveConfig parses a live deployment config.
func ParseLeanLiveConfig(body []byte) LeanFields {
	out := ParseLeanConfig(body)
	out.HasLiveMode = true
	return out
}

// ParseLeanCLIConfig parses a LEAN CLI credentials file.
func ParseLeanCLIConfig(body []byte) LeanFields {
	var out LeanFields
	if len(body) == 0 {
		return out
	}
	if m := qcUserTokenRE.FindSubmatch(body); len(m) > 1 {
		out.QCUserToken = string(m[1])
	}
	if passwordRE.Match(body) || passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	return out
}

// ParseLeanNodepacket parses a LEAN cluster nodepacket.
func ParseLeanNodepacket(body []byte) LeanFields {
	out := ParseLeanConfig(body)
	if m := qcUserTokenRE.FindSubmatch(body); len(m) > 1 {
		out.QCUserToken = string(m[1])
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

// countDistinctSymbols returns the count of unique tickers.
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

// parseRatioToBps converts a percentage / ratio string to bps.
// Sharpe ratios (-2.0 to +5.0) are stored as bps directly
// (sharpe * 10000). Annual return percentages (10.5%) get
// scaled by 100 (=> 10.5% → 1050 bps). Plain ratios (1.20 =
// 120%) get scaled by 10000.
func parseRatioToBps(s string) int64 {
	s = strings.TrimSpace(strings.TrimSuffix(s, "%"))
	if s == "" {
		return 0
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	// If absolute value > 5, treat as percent already (e.g. 10.5
	// for 10.5%); else treat as ratio (0.15 for 15%).
	if math.Abs(f) > 5 {
		return int64(math.Round(f * 100))
	}
	return int64(math.Round(f * 10000))
}
