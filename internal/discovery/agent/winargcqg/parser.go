package winargcqg

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// CQGFields captures scalar fields the audit pipeline needs
// from a CQG artifact.
type CQGFields struct {
	APIKey            string
	Username          string
	CQGAccountID      string
	FIXSenderCompID   string
	FIXTargetCompID   string
	ClienteCuitRaw    string
	DistinctSymbols   int64
	MATbaSymbolsCount int64
	CMESymbolsCount   int64
	BlockTradeCount   int64
	PeakMsgPerSec     int64
	HasPassword       bool
	HasFIXContinuum   bool
	HasFIXDropCopy    bool
	HasAlgoSEMarker   bool
	HasQTraderMarker  bool
}

// passwordRE matches a password row.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|cqg[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|cqg_secret)\s*=\s*["'][^"']{1,}["']`,
)

// apiKeyRE matches a CQG API key / token.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(?:cqg[_\-]?api[_\-]?key|cqg[_\-]?token|api[_\-]?key|api[_\-]?token|continuum[_\-]?key)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`,
)

// usernameRE matches CQG username.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:cqg[_\-]?username|cqg[_\-]?user|username|user|email|login[_\-]?id)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// accountIDRE matches a CQG account ID.
var accountIDRE = regexp.MustCompile(
	`(?i)"?(?:cqg[_\-]?account|account[_\-]?id|accountId|trader[_\-]?id)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{3,32})`,
)

// fixContinuumRE detects CQG Continuum FIX session markers.
var fixContinuumRE = regexp.MustCompile(
	`(?i)(?:8=FIX\.4\.4|8=FIXT\.1\.1|continuum[_\- ]?fix|cqg[_\- ]?continuum|continuum[_\- ]?session)`,
)

// fixDropCopyRE detects FIX drop-copy session markers.
var fixDropCopyRE = regexp.MustCompile(
	`(?i)(?:drop[_\- ]?copy|DropCopySession|TargetSubID=DROP|10010=DROP|TradeCaptureReport)`,
)

// fixSenderRE matches FIX SenderCompID.
var fixSenderRE = regexp.MustCompile(
	`(?i)(?:49=|SenderCompID["'\s:=]+)([A-Z0-9_\-\.]{2,32})`,
)

// fixTargetRE matches FIX TargetCompID.
var fixTargetRE = regexp.MustCompile(
	`(?i)(?:56=|TargetCompID["'\s:=]+)([A-Z0-9_\-\.]{2,32})`,
)

// algoSEMarkerRE detects CQG Algo SE strategy markers.
var algoSEMarkerRE = regexp.MustCompile(
	`(?i)(?:AlgoSE|algo[_\- ]?strategy|algo[_\- ]?se|cqg[_\- ]?algo|strategy[_\- ]?engine)`,
)

// qtraderMarkerRE detects CQG QTrader (block-trading) markers.
var qtraderMarkerRE = regexp.MustCompile(
	`(?i)(?:qtrader|q[_\- ]?trader|block[_\- ]?trade|block[_\- ]?workspace|pre[_\- ]?arranged|negotiated[_\- ]?cross)`,
)

// blockTradeEventRE matches a per-row block-trade entry.
var blockTradeEventRE = regexp.MustCompile(
	`(?i)(?:block_id|trade_id|operacion_id|bloque_id|pre_arranged_id)`,
)

// timestampRE matches `YYYY-MM-DD HH:MM:SS`.
var timestampRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`,
)

// messageMarkerRE matches per-message FIX/log markers used to
// estimate message rate.
var messageMarkerRE = regexp.MustCompile(
	`(?i)(?:35=W|35=X|35=D|35=8|MarketDataIncrementalRefresh|md_update|order_event|execution_report)`,
)

// symbolEntryRE matches a JSON/INI symbol entry or FIX
// tag `55=DLR`. `symbol_N` / `symbol_<word>` variants accepted
// to match Algo SE strategies that label legs as `symbol_1`,
// `symbol_2` etc.
var symbolEntryRE = regexp.MustCompile(
	`(?i)(?:\b55=|"?(?:symbol(?:_\w+)?|simbolo|ticker|instrument|contract|conid)"?\s*[:=]\s*"?)([A-Za-z0-9_\-\./]{2,32})`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseCQGConfig parses a CQG terminal config body.
func ParseCQGConfig(body []byte) CQGFields {
	var out CQGFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.CQGAccountID = string(m[1])
	}
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseCQGCredentials parses an api-token / credentials body.
func ParseCQGCredentials(body []byte) CQGFields {
	return ParseCQGConfig(body)
}

// ParseCQGICConfig parses an Integrated Client config body.
func ParseCQGICConfig(body []byte) CQGFields {
	return ParseCQGConfig(body)
}

// ParseCQGQTraderConfig parses a QTrader block-trade body.
func ParseCQGQTraderConfig(body []byte) CQGFields {
	out := ParseCQGConfig(body)
	out.HasQTraderMarker = qtraderMarkerRE.Match(body)
	out.BlockTradeCount = int64(len(blockTradeEventRE.FindAllIndex(body, -1)))
	return out
}

// ParseCQGContinuumConfig parses a Continuum FIX config body.
func ParseCQGContinuumConfig(body []byte) CQGFields {
	out := ParseCQGConfig(body)
	if fixContinuumRE.Match(body) {
		out.HasFIXContinuum = true
	}
	if m := fixSenderRE.FindSubmatch(body); len(m) > 1 {
		out.FIXSenderCompID = string(m[1])
	}
	if m := fixTargetRE.FindSubmatch(body); len(m) > 1 {
		out.FIXTargetCompID = string(m[1])
	}
	return out
}

// ParseCQGAlgoSEStrategy parses an Algo SE strategy body.
func ParseCQGAlgoSEStrategy(body []byte) CQGFields {
	var out CQGFields
	if len(body) == 0 {
		return out
	}
	out.HasAlgoSEMarker = algoSEMarkerRE.Match(body)
	if passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseCQGAPIScript parses a CQG API Python / C++ script.
func ParseCQGAPIScript(body []byte) CQGFields {
	var out CQGFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseCQGSessionLog parses a terminal session log.
func ParseCQGSessionLog(body []byte) CQGFields {
	var out CQGFields
	if len(body) == 0 {
		return out
	}
	out.PeakMsgPerSec = peakMessagesPerSecond(body)
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.CQGAccountID = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseCQGPositions parses a positions cache.
func ParseCQGPositions(body []byte) CQGFields {
	var out CQGFields
	if len(body) == 0 {
		return out
	}
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.CQGAccountID = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseCQGOrders parses an orders cache.
func ParseCQGOrders(body []byte) CQGFields {
	return ParseCQGPositions(body)
}

// ParseCQGFIXLog parses a FIX session / drop-copy log.
func ParseCQGFIXLog(body []byte) CQGFields {
	var out CQGFields
	if len(body) == 0 {
		return out
	}
	if fixContinuumRE.Match(body) {
		out.HasFIXContinuum = true
	}
	if fixDropCopyRE.Match(body) {
		out.HasFIXDropCopy = true
	}
	if m := fixSenderRE.FindSubmatch(body); len(m) > 1 {
		out.FIXSenderCompID = string(m[1])
	}
	if m := fixTargetRE.FindSubmatch(body); len(m) > 1 {
		out.FIXTargetCompID = string(m[1])
	}
	out.PeakMsgPerSec = peakMessagesPerSecond(body)
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.CQGAccountID = string(m[1])
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

// classifySymbols returns counts of distinct MATba-Rofex,
// CME, and total symbols. Splits only on `/` (contract-month
// separator) and not `-` because some MATba symbols
// themselves contain `-` (e.g. `MTR-USD`, `ROS-DLR`).
func classifySymbols(body []byte) (matba, cme, total int64) {
	seen := map[string]struct{}{}
	mat := map[string]struct{}{}
	cm := map[string]struct{}{}
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
		if IsMATbaRofexSymbol(stem) {
			mat[stem] = struct{}{}
			continue
		}
		if IsCMEFuturesSymbol(stem) {
			cm[stem] = struct{}{}
		}
	}
	return int64(len(mat)), int64(len(cm)), int64(len(seen))
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
