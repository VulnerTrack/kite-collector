package winargbymadata

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// BymadataFields captures scalar fields the audit pipeline
// needs from a Bymadata artifact.
type BymadataFields struct {
	APIKey              string
	Username            string
	FIXSenderCompID     string
	FIXTargetCompID     string
	SessionFirstSeen    string
	SessionLastSeen     string
	Tier                SubscriptionTier
	MessageCount        int64
	DistinctCuits       int64
	PeakMsgPerSec       int64
	HistoricalRows      int64
	DistinctSymbols     int64
	HasPassword         bool
	HasFIXFASTSession   bool
	HasWebsocketSession bool
	HasDepthOfBook      bool
	HasInternational    bool
}

// apiKeyRE matches a bymadata API key / vendor key / token.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(?:bymadata[_-]?(?:api[_-]?key|key|token|vendor[_-]?key|client[_-]?id)|vendor[_-]?key|api[_-]?key|access[_-]?token|client[_-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{20,})`)

// usernameRE matches `username` / `user` / `email`.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:username|user|email|usuario|vendor[_\-]?id|client[_\-]?name)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`)

// passwordRE matches a password row (line-anchored INI/JSON/XML).
var passwordRE = regexp.MustCompile(
	`(?im)^\s*(?:<\s*)?"?(?:password|clave|pass|passwd|vendor[_\-]?pass)"?\s*(?:[:=>]|>)\s*\S+`)

// passwordXMLRE matches `<password>…</password>` on a single line.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|clave)\s*>[^<\n]{1,}<\s*/\s*(?:password|clave)\s*>`)

// passwordInlineRE matches `password="..."` mid-line in
// Python source.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|clave|passwd|api_key|vendor_key)\s*=\s*["'][^"']{1,}["']`)

// fixFASTRE detects FIX-FAST 5.0 session markers.
var fixFASTRE = regexp.MustCompile(
	`(?i)(?:8=FIXT\.1\.1|8=FIX\.5\.0|fixfast|fix[_\- ]?fast|fast[_\- ]?template|9=\d+\x01|35=W|35=X|35=d|MDFullGrp)`)

// fixSenderRE matches FIX SenderCompID.
var fixSenderRE = regexp.MustCompile(
	`(?i)(?:49=|SenderCompID["'\s:=]+)([A-Z0-9_\-\.]{2,32})`)

// fixTargetRE matches FIX TargetCompID.
var fixTargetRE = regexp.MustCompile(
	`(?i)(?:56=|TargetCompID["'\s:=]+)([A-Z0-9_\-\.]{2,32})`)

// websocketRE detects WS handshake / streaming markers.
var websocketRE = regexp.MustCompile(
	`(?i)(?:wss?://[a-z0-9_\-\.]+|Sec-WebSocket-Key|Upgrade:\s*websocket|websocket[_\- ]?handshake|hub[_\- ]?connect|hub[_\- ]?subscribe|stream[_\- ]?subscribe)`)

// timestampRE matches `YYYY-MM-DD HH:MM[:SS]`.
var timestampRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`)

// messageMarkerRE matches per-message log markers used to
// estimate message rate (FIX-FAST or WS payload lines).
var messageMarkerRE = regexp.MustCompile(
	`(?i)(?:35=W|35=X|35=d|MarketDataIncrementalRefresh|MarketDataSnapshotFullRefresh|md_update|mdupdate|book_update|trade_tick|level1_update|level2_update)`)

// symbolJSONRE matches a JSON / INI symbol entry.
var symbolJSONRE = regexp.MustCompile(
	`(?i)"?(?:symbol|simbolo|s[ií]mbolo|ticker|especie|instrumento|55=)"?\s*[:=]\s*"?([A-Za-z0-9_\-\./]{2,32})`)

// symbolXMLRE matches `<symbol>…</symbol>`.
var symbolXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:symbol|simbolo|ticker|instrument)\s*>([A-Za-z0-9_\-\./]{2,32})<\s*/\s*(?:symbol|simbolo|ticker|instrument)\s*>`)

// sdkImportRE detects bymadata SDK imports.
var sdkImportRE = regexp.MustCompile(
	`(?im)^\s*(?:from\s+bymadata|import\s+bymadata|from\s+ar\.com\.byma\.bymadata|import\s+ar\.com\.byma\.bymadata)`)

// ParseBymadataCredentials parses an api_key.json / config.
func ParseBymadataCredentials(body []byte) BymadataFields {
	var out BymadataFields
	if len(body) == 0 {
		return out
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if passwordXMLRE.Match(body) || passwordRE.Match(body) ||
		passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	out.DistinctCuits = DistinctCuitsInBody(body)
	out.Tier = SubscriptionTierFromBody(body)
	if HasDepthOfBookMarker(body) {
		out.HasDepthOfBook = true
	}
	if HasInternationalMarker(body) {
		out.HasInternational = true
	}
	return out
}

// ParseBymadataConfig parses a Bymadata terminal config /
// settings file.
func ParseBymadataConfig(body []byte) BymadataFields {
	return ParseBymadataCredentials(body)
}

// ParseBymadataFIXFASTLog parses a FIX-FAST 5.0 session log.
func ParseBymadataFIXFASTLog(body []byte) BymadataFields {
	var out BymadataFields
	if len(body) == 0 {
		return out
	}
	if fixFASTRE.Match(body) {
		out.HasFIXFASTSession = true
	}
	if m := fixSenderRE.FindSubmatch(body); len(m) > 1 {
		out.FIXSenderCompID = string(m[1])
	}
	if m := fixTargetRE.FindSubmatch(body); len(m) > 1 {
		out.FIXTargetCompID = string(m[1])
	}
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	out.MessageCount = int64(len(messageMarkerRE.FindAllIndex(body, -1)))
	out.PeakMsgPerSec = peakMessagesPerSecond(body)
	out.DistinctSymbols = countDistinctSymbols(body)
	out.DistinctCuits = DistinctCuitsInBody(body)
	out.Tier = SubscriptionTierFromBody(body)
	if HasDepthOfBookMarker(body) {
		out.HasDepthOfBook = true
	}
	if HasInternationalMarker(body) {
		out.HasInternational = true
	}
	return out
}

// ParseBymadataWSLog parses a WebSocket streaming session log.
func ParseBymadataWSLog(body []byte) BymadataFields {
	var out BymadataFields
	if len(body) == 0 {
		return out
	}
	if websocketRE.Match(body) {
		out.HasWebsocketSession = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	out.MessageCount = int64(len(messageMarkerRE.FindAllIndex(body, -1)))
	out.PeakMsgPerSec = peakMessagesPerSecond(body)
	out.DistinctSymbols = countDistinctSymbols(body)
	out.DistinctCuits = DistinctCuitsInBody(body)
	out.Tier = SubscriptionTierFromBody(body)
	if HasDepthOfBookMarker(body) {
		out.HasDepthOfBook = true
	}
	if HasInternationalMarker(body) {
		out.HasInternational = true
	}
	return out
}

// ParseBymadataRESTCache parses a REST snapshot cache file.
func ParseBymadataRESTCache(body []byte) BymadataFields {
	var out BymadataFields
	if len(body) == 0 {
		return out
	}
	out.DistinctSymbols = countDistinctSymbols(body)
	out.DistinctCuits = DistinctCuitsInBody(body)
	out.Tier = SubscriptionTierFromBody(body)
	if HasDepthOfBookMarker(body) {
		out.HasDepthOfBook = true
	}
	if HasInternationalMarker(body) {
		out.HasInternational = true
	}
	return out
}

// ParseBymadataHistoricalCSV parses a historical CSV / Parquet
// header + row count.
func ParseBymadataHistoricalCSV(body []byte) BymadataFields {
	var out BymadataFields
	if len(body) == 0 {
		return out
	}
	out.HistoricalRows = countCSVRows(body)
	out.DistinctSymbols = countDistinctSymbolsCSV(body)
	out.Tier = SubscriptionTierFromBody(body)
	if HasDepthOfBookMarker(body) {
		out.HasDepthOfBook = true
	}
	if HasInternationalMarker(body) {
		out.HasInternational = true
	}
	return out
}

// ParseBymadataSDKScript parses a .py / .ipynb body and
// detects bymadata SDK imports + hardcoded credentials.
func ParseBymadataSDKScript(body []byte) BymadataFields {
	var out BymadataFields
	if len(body) == 0 {
		return out
	}
	if sdkImportRE.Match(body) {
		// presence-only; reflected in account-class classify.
		_ = sdkImportRE
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	return out
}

// HasSDKImport reports whether a body imports the bymadata
// vendor SDK.
func HasSDKImport(body []byte) bool {
	return sdkImportRE.Match(body)
}

// countDistinctSymbols returns the count of unique tickers.
func countDistinctSymbols(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range symbolJSONRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	for _, m := range symbolXMLRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	return int64(len(seen))
}

// peakMessagesPerSecond bucketed by HH:MM:SS timestamp prefix.
// Returns highest per-second bucket.
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

// countCSVRows returns the number of data rows in a CSV / TSV
// (excludes the header row).
func countCSVRows(body []byte) int64 {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	var n int64
	for scanner.Scan() {
		n++
	}
	if n > 0 {
		n--
	}
	return n
}

// countDistinctSymbolsCSV scans a CSV for a `symbol` /
// `ticker` column and returns distinct values.
func countDistinctSymbolsCSV(body []byte) int64 {
	if len(body) == 0 {
		return 0
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	if !scanner.Scan() {
		return 0
	}
	headerLine := scanner.Text()
	delim := inferDelimiter(headerLine)
	headers := strings.Split(headerLine, delim)
	symIdx := -1
	for i, h := range headers {
		hl := strings.ToLower(strings.TrimSpace(h))
		if hl == "symbol" || hl == "ticker" || hl == "simbolo" ||
			hl == "instrument" || hl == "instrumento" || hl == "especie" {
			symIdx = i
			break
		}
	}
	if symIdx < 0 {
		return countDistinctSymbols(body)
	}
	seen := map[string]struct{}{}
	for scanner.Scan() {
		row := strings.Split(scanner.Text(), delim)
		if symIdx >= len(row) {
			continue
		}
		s := strings.ToUpper(strings.TrimSpace(row[symIdx]))
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	return int64(len(seen))
}

// inferDelimiter picks the most-likely CSV delimiter.
func inferDelimiter(headerLine string) string {
	counts := map[string]int{
		",":  strings.Count(headerLine, ","),
		";":  strings.Count(headerLine, ";"),
		"\t": strings.Count(headerLine, "\t"),
		"|":  strings.Count(headerLine, "|"),
	}
	best := ","
	bestN := 0
	for d, n := range counts {
		if n > bestN {
			best = d
			bestN = n
		}
	}
	return best
}
