package winargpybacktest

import (
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// PyBTFields captures scalar fields the audit pipeline needs
// from a pybacktest artifact.
type PyBTFields struct {
	ArgentineTickers    map[string]struct{}
	APIKey              string
	StrategyName        string
	Period              string
	SharpeX100          int
	AnnualReturnPct     int
	MaxDrawdownPct      int
	TradeCount          int64
	HasLookaheadBias    bool
	HasIpynbWithSecrets bool
}

// sharpeRE matches `sharpe: NN.NN` / `Sharpe Ratio: NN`.
var sharpeRE = regexp.MustCompile(
	`(?i)(?:sharpe(?:[_\- ]?ratio)?|sharpe[_\- ]?ratio)"?\s*[:=>]\s*"?(-?[0-9]+(?:[.,][0-9]+)?)`,
)

// annualReturnRE matches `annual_return: NN%` / `Annualized Return: NN.NN`.
var annualReturnRE = regexp.MustCompile(
	`(?i)(?:annual(?:ized)?[_\- ]?return|cagr|return[_\- ]?annual)"?\s*[:=>]\s*"?(-?[0-9]+(?:[.,][0-9]+)?)\s*%?`,
)

// maxDrawdownRE matches `max_drawdown: NN%`.
var maxDrawdownRE = regexp.MustCompile(
	`(?i)(?:max[_\- ]?drawdown|maxdrawdown|max[_\- ]?dd|drawdown[_\- ]?max)"?\s*[:=>]\s*"?(-?[0-9]+(?:[.,][0-9]+)?)\s*%?`,
)

// tradeCountRE matches `total_trades: NN` / `n_trades: NN`.
var tradeCountRE = regexp.MustCompile(
	`(?i)(?:total[_\- ]?trades|n[_\- ]?trades|trade[_\- ]?count|num[_\- ]?trades|trades[_\- ]?total)"?\s*[:=>]\s*"?([0-9]+)`,
)

// strategyNameRE matches `strategy_name: <name>` / `name: <name>`.
var strategyNameRE = regexp.MustCompile(
	`(?i)(?:strategy[_\- ]?name|strategy[_\- ]?id|name)"?\s*[:=>]\s*"?([A-Za-z0-9_\-]{2,80})"?`,
)

// tickerRE matches a ticker token (3-6 upper-alphanumeric).
var tickerRE = regexp.MustCompile(
	`(?:^|[\s\|;,>"'<])([A-Z][A-Z0-9]{1,5})(?:[\s\|;,<"'/]|$)`,
)

// lookaheadRE detects lookahead-bias markers.
var lookaheadRE = regexp.MustCompile(
	`(?i)(?:shift\(\s*-1\s*\)|shift\(\s*-2\s*\)|future_data|peek_ahead|next_day_open|forward[_\- ]?fill|look[_\- ]?ahead)`,
)

// apiKeyRE detects an API-key declaration in Python source.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(api[_-]?key|bearer|access[_-]?token|secret|password)("|')?\s*[:=]\s*("|')([A-Za-z0-9_\-\.\+/=]{16,})`,
)

// secretInIpynbRE detects an embedded secret in a notebook
// cell (JSON-formatted .ipynb).
var secretInIpynbRE = regexp.MustCompile(
	`(?i)\\"(?:api[_-]?key|bearer|access[_-]?token|secret|password)\\"\s*:\s*\\"([A-Za-z0-9_\-\.\+/=]{16,})`,
)

// ParsePyBacktestArtifact parses a pybacktest result body and
// extracts scalar fields.
//
// We use flat regex scans rather than format-specific parsers
// — backtest output spans JSON / CSV / TXT / HTML and the same
// keys appear across forms. Binary .pkl / .parquet bodies are
// hashed-only by the collector (no Python pickle decoder).
func ParsePyBacktestArtifact(body []byte) PyBTFields {
	out := PyBTFields{ArgentineTickers: map[string]struct{}{}}
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	if m := sharpeRE.FindSubmatch(body); len(m) > 1 {
		f := parseFloat(string(m[1]))
		out.SharpeX100 = int(math.Round(f * 100))
	}
	if m := annualReturnRE.FindSubmatch(body); len(m) > 1 {
		f := parseFloat(string(m[1]))
		// Ratio form: 0.45 = 45 %, 1.20 = 120 %. The convention
		// in quant backtest outputs is ratio; we treat values
		// up to 5.0 (500 %) as ratios since literal-percent
		// annual returns above 500 are also extremely rare in
		// honest backtests.
		if f > 0 && f <= 5 {
			f *= 100
		}
		out.AnnualReturnPct = int(math.Round(f))
	}
	if m := maxDrawdownRE.FindSubmatch(body); len(m) > 1 {
		f := math.Abs(parseFloat(string(m[1])))
		// Ratio form (0.45 = 45%).
		if f > 0 && f <= 1 {
			f *= 100
		}
		if f > 100 {
			f = 100
		}
		out.MaxDrawdownPct = int(math.Round(f))
	}
	if m := tradeCountRE.FindSubmatch(body); len(m) > 1 {
		n, _ := strconv.ParseInt(string(m[1]), 10, 64)
		out.TradeCount = n
	}
	if m := strategyNameRE.FindSubmatch(body); len(m) > 1 {
		out.StrategyName = strings.TrimSpace(string(m[1]))
	}
	// Scan tickers — preserve Argentine ones only.
	for _, m := range tickerRE.FindAllSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		t := strings.ToUpper(string(m[1]))
		if IsArgentineTicker(t) {
			out.ArgentineTickers[t] = struct{}{}
		}
	}
	if lookaheadRE.Match(body) {
		out.HasLookaheadBias = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 5 {
		out.APIKey = string(m[5])
	}
	if secretInIpynbRE.Match(body) {
		out.HasIpynbWithSecrets = true
	}
	return out
}

// parseFloat parses a decimal with comma- or dot-separator.
func parseFloat(s string) float64 {
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
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return f
}
