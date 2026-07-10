package winargtradestation

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// TSFields captures scalar fields the audit pipeline needs
// from a TradeStation artifact.
type TSFields struct {
	APIKey               string
	Username             string
	TSAccountID          string
	ClienteCuitRaw       string
	DistinctSymbols      int64
	USEquitySymbolsCount int64
	CMESymbolsCount      int64
	MATbaSymbolsCount    int64
	RadarScreenSymbols   int64
	PeakMsgPerSec        int64
	FillCount            int64
	WFORunCount          int64
	HasPassword          bool
	HasAPICredentials    bool
	HasStrategyAutotrade bool
}

// passwordRE matches a password row.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|ts[_\-]?password|tradestation[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|ts[_\-]?password|tradestation[_\-]?password|ts[_\-]?secret)\s*=\s*["'][^"']{1,}["']`,
)

// apiKeyRE matches a TradeStation REST API token / OAuth bearer.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(?:ts[_\-]?api[_\-]?key|ts[_\-]?token|tradestation[_\-]?token|tradestation[_\-]?api[_\-]?key|access[_\-]?token|api[_\-]?key|api[_\-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`,
)

// usernameRE matches TradeStation login name.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:ts[_\-]?username|ts[_\-]?user|tradestation[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// accountIDRE matches a TS account ID — typically numeric
// (TradeStation accounts are 8-9 digit numerics).
var accountIDRE = regexp.MustCompile(
	`(?i)"?(?:ts[_\-]?account|account[_\-]?id|accountid|trading[_\-]?account|account[_\-]?number|account[_\-]?name)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{3,32})`,
)

// autotradeRE detects strategy auto-trade armed state. Common
// surfaces:
//
//   - workspace XML: `AutomatedTrading="true"`,
//     `AutoTrading="enabled"`.
//   - strategy properties: `AutoTrade=1`,
//     `EnableAutoTrade=true`.
//   - TS Easy Language: `SetExitOnClose()`,
//     `Strategy.AutoTrade(true)`.
var autotradeRE = regexp.MustCompile(
	`(?i)(?:automatedtrading\s*=\s*"?(?:true|1|on|yes)|autotrading\s*=\s*"?(?:enabled|true|1|on)|auto[_\- ]?trade\s*=\s*(?:1|true|on|yes)|enableautotrade\s*=\s*(?:1|true)|strategy\.autotrade\s*\(\s*true)`,
)

// orderEventRE matches a per-fill entry in OrderLog.txt or
// trade-log row.
var orderEventRE = regexp.MustCompile(
	`(?i)(?:OrderFilled|FillEvent|FillID|fill[_\- ]?id|order[_\- ]?status\s*[:=]\s*"?(?:filled|partfill)|executed[_\- ]?qty)`,
)

// wfoRunRE matches a Walk Forward Optimizer run marker.
var wfoRunRE = regexp.MustCompile(
	`(?i)(?:WalkForwardRun|WFO[_\- ]?Run|WFO[_\- ]?Iteration|optimization[_\- ]?run|run[_\- ]?id\s*[:=])`,
)

// radarRowRE matches a per-symbol RadarScreen row entry.
var radarRowRE = regexp.MustCompile(
	`(?i)(?:<symbol[^>]*>|"?symbol"?\s*[:=]\s*"?|<row[^>]*sym=")([A-Z][A-Z0-9.\-/]{1,16})`,
)

// timestampRE matches `YYYY-MM-DD HH:MM:SS`.
var timestampRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`,
)

// messageMarkerRE matches per-message markers used to estimate
// message rate in TS Network logs.
var messageMarkerRE = regexp.MustCompile(
	`(?i)(?:MarketDataUpdate|QuoteUpdate|TradeUpdate|HeartBeat|LogonResponse|OrderUpdate|ExecutionReport)`,
)

// symbolEntryRE matches TradeStation symbol entries: workspace
// XML `<Symbol>AAPL</Symbol>`, INI `Symbol=ES`, JSON
// `"symbol":"NQ"`, EasyLanguage `Symbol("AAPL")`.
var symbolEntryRE = regexp.MustCompile(
	`(?i)(?:"?(?:symbol(?:_\w+)?|sym|ticker|instrument|root)"?\s*[:=]\s*"?|<symbol[^>]*>|Symbol\(\s*"|InsertSymbol\(\s*")([A-Za-z0-9_\-\./]{1,32})`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseTSConfig parses tsserver.cfg / TradingAccount<id>.cfg.
func ParseTSConfig(body []byte) TSFields {
	var out TSFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
		out.HasAPICredentials = true
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.TSAccountID = string(m[1])
	}
	out.USEquitySymbolsCount, out.CMESymbolsCount, out.MATbaSymbolsCount,
		out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseTSCredentials parses a credentials body.
func ParseTSCredentials(body []byte) TSFields {
	return ParseTSConfig(body)
}

// ParseTSELSSource parses an .els encrypted EasyLanguage body.
// Body is encrypted so we only sniff the plaintext header /
// metadata for symbol hints + CUIT.
func ParseTSELSSource(body []byte) TSFields {
	var out TSFields
	if len(body) == 0 {
		return out
	}
	out.USEquitySymbolsCount, out.CMESymbolsCount, out.MATbaSymbolsCount,
		out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseTSELDPackage parses an .eld download package body —
// these often contain manifests with strategy metadata.
func ParseTSELDPackage(body []byte) TSFields {
	return ParseTSELSSource(body)
}

// ParseTSStrategy parses a .tss strategy / .tsi indicator /
// .tsg chart-group body.
func ParseTSStrategy(body []byte) TSFields {
	var out TSFields
	if len(body) == 0 {
		return out
	}
	if autotradeRE.Match(body) {
		out.HasStrategyAutotrade = true
	}
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.TSAccountID = string(m[1])
	}
	out.USEquitySymbolsCount, out.CMESymbolsCount, out.MATbaSymbolsCount,
		out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseTSWorkspace parses a .wkspace workspace body.
func ParseTSWorkspace(body []byte) TSFields {
	return ParseTSStrategy(body)
}

// ParseTSWFOResult parses a .wfo Walk-Forward Optimizer body.
func ParseTSWFOResult(body []byte) TSFields {
	out := ParseTSStrategy(body)
	out.WFORunCount = int64(len(wfoRunRE.FindAllIndex(body, -1)))
	return out
}

// ParseTSRadarScreen parses an .rds RadarScreen scanner body.
func ParseTSRadarScreen(body []byte) TSFields {
	out := ParseTSStrategy(body)
	seen := map[string]struct{}{}
	for _, m := range radarRowRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
	}
	out.RadarScreenSymbols = int64(len(seen))
	return out
}

// ParseTSOrderLog parses OrderLog.txt — per-fill trail.
func ParseTSOrderLog(body []byte) TSFields {
	var out TSFields
	if len(body) == 0 {
		return out
	}
	out.FillCount = int64(len(orderEventRE.FindAllIndex(body, -1)))
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.TSAccountID = string(m[1])
	}
	out.PeakMsgPerSec = peakMessagesPerSecond(body)
	out.USEquitySymbolsCount, out.CMESymbolsCount, out.MATbaSymbolsCount,
		out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseTSTradeManager parses a TradeManager.csv export.
func ParseTSTradeManager(body []byte) TSFields {
	out := ParseTSOrderLog(body)
	return out
}

// ParseTSNetworkLog parses a TradeStation Network session log.
func ParseTSNetworkLog(body []byte) TSFields {
	var out TSFields
	if len(body) == 0 {
		return out
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
		out.HasAPICredentials = true
	}
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.TSAccountID = string(m[1])
	}
	out.PeakMsgPerSec = peakMessagesPerSecond(body)
	out.USEquitySymbolsCount, out.CMESymbolsCount, out.MATbaSymbolsCount,
		out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseTSAPIScript parses a Python / .NET REST script.
func ParseTSAPIScript(body []byte) TSFields {
	var out TSFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
		out.HasAPICredentials = true
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	out.USEquitySymbolsCount, out.CMESymbolsCount, out.MATbaSymbolsCount,
		out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// cuitFromBody returns a cliente CUIT match.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// classifySymbols returns counts of US equity / CME / MATba /
// total distinct symbols. Splits on `/` for contract-month
// separation only — MATba stems may contain `-`.
func classifySymbols(body []byte) (usEq, cme, matba, total int64) {
	seen := map[string]struct{}{}
	usEqSet := map[string]struct{}{}
	cmeSet := map[string]struct{}{}
	matbaSet := map[string]struct{}{}
	for _, m := range symbolEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
		stem := s
		if i := strings.Index(s, "/"); i > 0 {
			stem = s[:i]
		}
		switch {
		case IsMATbaRofexSymbol(stem):
			matbaSet[stem] = struct{}{}
		case IsCMEFuturesSymbol(stem):
			cmeSet[stem] = struct{}{}
		case IsUSEquityStem(stem):
			usEqSet[stem] = struct{}{}
		}
	}
	return int64(len(usEqSet)), int64(len(cmeSet)),
		int64(len(matbaSet)), int64(len(seen))
}

// peakMessagesPerSecond bucketed by HH:MM:SS prefix.
func peakMessagesPerSecond(body []byte) int64 {
	bucket := map[string]int64{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if !messageMarkerRE.Match(line) {
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
