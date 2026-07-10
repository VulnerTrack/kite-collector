package winargtt

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// TTFields captures scalar fields the audit pipeline needs
// from a TT (Trading Technologies) artifact.
type TTFields struct {
	APIKey            string
	Username          string
	TTAccountID       string
	FIXSenderCompID   string
	FIXTargetCompID   string
	ClienteCuitRaw    string
	DistinctSymbols   int64
	MATbaSymbolsCount int64
	CMESymbolsCount   int64
	PeakMsgPerSec     int64
	HasPassword       bool
	HasTTFIXSession   bool
	HasFIXDropCopy    bool
	HasADLMarker      bool
	HasAlgoSEMarker   bool
	HasAuroraMarker   bool
	HasScoreMarker    bool
	HasTTASMarker     bool
}

// passwordRE matches a password row.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|tt[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_secret|app_secret|tt_secret|tt_app_secret)\s*=\s*["'][^"']{1,}["']`,
)

// apiKeyRE matches a TT API key / app key / token.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(?:tt[_\-]?api[_\-]?key|tt[_\-]?app[_\-]?key|tt[_\-]?token|app[_\-]?key|api[_\-]?key|api[_\-]?token|access[_\-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`,
)

// usernameRE matches TT username.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:tt[_\-]?username|tt[_\-]?user|username|user|email|login[_\-]?id)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// accountIDRE matches a TT account ID.
var accountIDRE = regexp.MustCompile(
	`(?i)"?(?:tt[_\-]?account|account[_\-]?id|accountId|trader[_\-]?id|account[_\-]?name)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{3,32})`,
)

// ttFIXSessionRE detects TT FIX 4.4 institutional gateway
// session markers.
var ttFIXSessionRE = regexp.MustCompile(
	`(?i)(?:8=FIX\.4\.4|8=FIXT\.1\.1|tt[_\- ]?fix|tt[_\- ]?gateway|fix[_\- ]?adapter|tt[_\- ]?adapter)`,
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

// adlMarkerRE detects TT ADL (Algo Development Language)
// visual-algo strategy markers.
var adlMarkerRE = regexp.MustCompile(
	`(?i)(?:\.adl\b|<adl[_\- ]?strategy|adl[_\- ]?block|adl[_\- ]?canvas|adl[_\- ]?algo|tt[_\- ]?adl|algo[_\- ]?development[_\- ]?language)`,
)

// algoSEMarkerRE detects TT Algo SE strategy markers.
var algoSEMarkerRE = regexp.MustCompile(
	`(?i)(?:algo[_\- ]?se|algose|tt[_\- ]?algo[_\- ]?se|strategy[_\- ]?engine|server[_\- ]?strategy)`,
)

// auroraMarkerRE detects TT Aurora HFT-grade execution
// platform markers.
var auroraMarkerRE = regexp.MustCompile(
	`(?i)(?:tt[_\- ]?aurora|aurora[_\- ]?engine|aurora[_\- ]?execution|hft[_\- ]?aurora)`,
)

// scoreMarkerRE detects TT Score algo-monitoring/audit
// report markers.
var scoreMarkerRE = regexp.MustCompile(
	`(?i)(?:tt[_\- ]?score|\.score\b|score[_\- ]?report|algo[_\- ]?monitor|algo[_\- ]?audit)`,
)

// ttasMarkerRE detects TTAS (TT Access Service) — TT broker
// connectivity tier (the bridge to MATba-Rofex via local
// broker).
var ttasMarkerRE = regexp.MustCompile(
	`(?i)(?:\bttas\b|tt[_\- ]?access[_\- ]?service|matba[_\- ]?rofex[_\- ]?routing|tt[_\- ]?broker[_\- ]?connect)`,
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
// to match Algo SE/ADL strategies that label legs as
// `symbol_1`, `symbol_2` etc.
var symbolEntryRE = regexp.MustCompile(
	`(?i)(?:\b55=|"?(?:symbol(?:_\w+)?|simbolo|ticker|instrument|contract|conid)"?\s*[:=]\s*"?)([A-Za-z0-9_\-\./]{2,32})`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseTTConfig parses a TT terminal config body.
func ParseTTConfig(body []byte) TTFields {
	var out TTFields
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
		out.TTAccountID = string(m[1])
	}
	if ttasMarkerRE.Match(body) {
		out.HasTTASMarker = true
	}
	if adlMarkerRE.Match(body) {
		out.HasADLMarker = true
	}
	if algoSEMarkerRE.Match(body) {
		out.HasAlgoSEMarker = true
	}
	if auroraMarkerRE.Match(body) {
		out.HasAuroraMarker = true
	}
	if scoreMarkerRE.Match(body) {
		out.HasScoreMarker = true
	}
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseTTCredentials parses an api-token / credentials body.
func ParseTTCredentials(body []byte) TTFields {
	return ParseTTConfig(body)
}

// ParseTTDesktopConfig parses a TT Desktop workspace config.
func ParseTTDesktopConfig(body []byte) TTFields {
	return ParseTTConfig(body)
}

// ParseTTFIXAdapterConfig parses a TT FIX-adapter config body.
func ParseTTFIXAdapterConfig(body []byte) TTFields {
	out := ParseTTConfig(body)
	if ttFIXSessionRE.Match(body) {
		out.HasTTFIXSession = true
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
	return out
}

// ParseTTADLStrategy parses a TT ADL visual-algo body.
func ParseTTADLStrategy(body []byte) TTFields {
	var out TTFields
	if len(body) == 0 {
		return out
	}
	out.HasADLMarker = true
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

// ParseTTAlgoSEStrategy parses a TT Algo SE server-strategy body.
func ParseTTAlgoSEStrategy(body []byte) TTFields {
	var out TTFields
	if len(body) == 0 {
		return out
	}
	out.HasAlgoSEMarker = true
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

// ParseTTAuroraConfig parses a TT Aurora HFT engine config.
func ParseTTAuroraConfig(body []byte) TTFields {
	out := ParseTTConfig(body)
	out.HasAuroraMarker = true
	return out
}

// ParseTTScoreReport parses a TT Score algo-monitor/audit body.
func ParseTTScoreReport(body []byte) TTFields {
	var out TTFields
	if len(body) == 0 {
		return out
	}
	out.HasScoreMarker = true
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.TTAccountID = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseTTAPIScript parses a TT REST/SDK Python / Java script.
func ParseTTAPIScript(body []byte) TTFields {
	var out TTFields
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

// ParseTTSessionLog parses a terminal/adapter session log.
func ParseTTSessionLog(body []byte) TTFields {
	var out TTFields
	if len(body) == 0 {
		return out
	}
	if ttFIXSessionRE.Match(body) {
		out.HasTTFIXSession = true
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
	if ttasMarkerRE.Match(body) {
		out.HasTTASMarker = true
	}
	out.PeakMsgPerSec = peakMessagesPerSecond(body)
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.TTAccountID = string(m[1])
	}
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
// separator) and not `-` because some MATba symbols themselves
// contain `-` (e.g. `MTR-USD`, `ROS-DLR`).
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
