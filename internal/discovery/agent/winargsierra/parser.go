package winargsierra

import (
	"bufio"
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

// SierraFields captures scalar fields the audit pipeline needs
// from a Sierra Chart artifact.
type SierraFields struct {
	ClienteCuitRaw    string
	Username          string
	SierraAccountID   string
	DTCServerHost     string
	APIKey            string
	DistinctSymbols   int64
	DTCServerPort     int
	MATbaSymbolsCount int64
	CMESymbolsCount   int64
	FillCount         int64
	PeakMsgPerSec     int64
	HasPassword       bool
	HasDTCSession     bool
	HasDTCServerURL   bool
	HasAutotrade      bool
}

// passwordRE matches a password row.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|sierra[_\-]?password|dtc[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|sierra[_\-]?password|dtc[_\-]?password|sierra[_\-]?secret)\s*=\s*["'][^"']{1,}["']`,
)

// apiKeyRE matches a Sierra Chart API key / token.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(?:sierra[_\-]?api[_\-]?key|sierra[_\-]?token|api[_\-]?key|api[_\-]?token|dtc[_\-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`,
)

// usernameRE matches Sierra Chart username.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:sierra[_\-]?username|sierra[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// accountIDRE matches a Sierra Chart account ID.
var accountIDRE = regexp.MustCompile(
	`(?i)"?(?:sierra[_\-]?account|account[_\-]?id|accountid|trader[_\-]?id|account[_\-]?name)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{3,32})`,
)

// dtcServerRE detects a DTC server URL — `dtc_server=host:port`
// or `Server=host:port`. The DTC protocol is the binary
// low-latency wire used by Sierra Chart.
var dtcServerRE = regexp.MustCompile(
	`(?i)(?:dtc[_\-]?server|dtc[_\-]?host|server[_\-]?address|server)\s*[:=]\s*"?([A-Za-z0-9_.\-]{3,253})\s*[:]?\s*(\d{2,5})?`,
)

// dtcSessionRE detects a DTC session-log marker. Sierra Chart
// DTC logs prefix lines with "DTC " or contain
// `EncodingResponse`, `LogonRequest`, `Heartbeat`, or
// `MarketDataUpdate` keywords from the DTC spec.
var dtcSessionRE = regexp.MustCompile(
	`(?i)(?:DTC[_\- ]?(?:server|client|session|protocol)|EncodingResponse|LogonRequest|HeartBeat|MarketDataUpdate(?:Trade|BidAsk|LastTradeSnapshot)|TradeAccountResponse)`,
)

// autotradeRE detects spreadsheet auto-trade activation
// markers (`AutoTradeEnabled`, `auto_trade=true`, etc.).
var autotradeRE = regexp.MustCompile(
	`(?i)(?:autotradeenabled|auto[_\- ]?trade\s*[:=]\s*(?:true|1|on|yes)|autotrade=true|spreadsheettrading.*enabled)`,
)

// fillEventRE matches a per-fill order entry in
// tradingactivity.txt (Sierra writes one line per fill).
var fillEventRE = regexp.MustCompile(
	`(?i)(?:OrderFilled|FillEvent|^\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}.*\bFill\b|fill[_\-]?id\s*[:=])`,
)

// timestampRE matches `YYYY-MM-DD HH:MM:SS`.
var timestampRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`,
)

// messageMarkerRE matches per-message DTC markers used to
// estimate message rate.
var messageMarkerRE = regexp.MustCompile(
	`(?i)(?:MarketDataUpdate|MarketDepthUpdate|HeartBeat|LogonResponse|TradeAccountResponse|ExecutionReport|OrderUpdate)`,
)

// symbolEntryRE matches a Sierra workspace/chartbook/log
// symbol entry. Supports `Symbol=DLR`, `"symbol":"ES"`,
// or quoted XML `<symbol>NQ</symbol>` (the `>` and `<`
// chars open the value match).
var symbolEntryRE = regexp.MustCompile(
	`(?i)(?:"?(?:symbol(?:_\w+)?|simbolo|ticker|instrument|contract|root)"?\s*[:=]\s*"?|<symbol[^>]*>)([A-Za-z0-9_\-\./]{2,32})`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseSierraConfig parses sierra.config or similar.
func ParseSierraConfig(body []byte) SierraFields {
	var out SierraFields
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
		out.SierraAccountID = string(m[1])
	}
	if m := dtcServerRE.FindSubmatch(body); len(m) > 1 {
		out.HasDTCServerURL = true
		out.DTCServerHost = string(m[1])
		if len(m) > 2 && len(m[2]) > 0 {
			if p, err := strconv.Atoi(string(m[2])); err == nil &&
				p > 0 && p < 65536 {
				out.DTCServerPort = p
			}
		}
	}
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseSierraCredentials parses a credentials body.
func ParseSierraCredentials(body []byte) SierraFields {
	return ParseSierraConfig(body)
}

// ParseSierraWorkspace parses .cwsp workspace body.
func ParseSierraWorkspace(body []byte) SierraFields {
	var out SierraFields
	if len(body) == 0 {
		return out
	}
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.SierraAccountID = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseSierraChartbook parses .cht chartbook body.
func ParseSierraChartbook(body []byte) SierraFields {
	return ParseSierraWorkspace(body)
}

// ParseSierraACSILSource parses .scss / .cpp ACSIL source.
func ParseSierraACSILSource(body []byte) SierraFields {
	var out SierraFields
	if len(body) == 0 {
		return out
	}
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

// ParseSierraSpreadsheet parses a .spreadsheet trading-system
// body — flags auto-trade activation.
func ParseSierraSpreadsheet(body []byte) SierraFields {
	out := ParseSierraWorkspace(body)
	if autotradeRE.Match(body) {
		out.HasAutotrade = true
	}
	return out
}

// ParseSierraTradingActivity parses tradingactivity.txt.
func ParseSierraTradingActivity(body []byte) SierraFields {
	var out SierraFields
	if len(body) == 0 {
		return out
	}
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.SierraAccountID = string(m[1])
	}
	out.FillCount = int64(len(fillEventRE.FindAllIndex(body, -1)))
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseSierraDTCLog parses a DTC session log.
func ParseSierraDTCLog(body []byte) SierraFields {
	var out SierraFields
	if len(body) == 0 {
		return out
	}
	if dtcSessionRE.Match(body) {
		out.HasDTCSession = true
	}
	if m := dtcServerRE.FindSubmatch(body); len(m) > 1 {
		out.HasDTCServerURL = true
		out.DTCServerHost = string(m[1])
		if len(m) > 2 && len(m[2]) > 0 {
			if p, err := strconv.Atoi(string(m[2])); err == nil &&
				p > 0 && p < 65536 {
				out.DTCServerPort = p
			}
		}
	}
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.SierraAccountID = string(m[1])
	}
	out.PeakMsgPerSec = peakMessagesPerSecond(body)
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
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
