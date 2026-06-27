package winargbookmap

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// BookmapFields captures scalar fields the audit pipeline
// needs from a Bookmap artifact.
type BookmapFields struct {
	APIKey              string
	Username            string
	BookmapAccountID    string
	ClienteCuitRaw      string
	BrokerPlugin        BrokerPlugin
	DistinctSymbols     int64
	MATbaSymbolsCount   int64
	CMESymbolsCount     int64
	CryptoSymbolsCount  int64
	PeakMsgPerSec       int64
	IndicatorCount      int64
	MarketplaceCount    int64
	HasPassword         bool
	HasSpeedOfTapeArmed bool
	HasMBOSubscription  bool
}

// passwordRE matches a password row.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|bookmap[_\-]?password|broker[_\-]?password)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|bookmap[_\-]?password|bookmap[_\-]?secret|broker[_\-]?password)\s*=\s*["'][^"']{1,}["']`)

// apiKeyRE matches a Bookmap / plug-in API key / token.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(?:bookmap[_\-]?api[_\-]?key|bookmap[_\-]?token|rithmic[_\-]?token|cqg[_\-]?token|binance[_\-]?api[_\-]?key|broker[_\-]?token|api[_\-]?key|api[_\-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`)

// usernameRE matches Bookmap / broker login.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:bookmap[_\-]?username|broker[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`)

// accountIDRE matches a Bookmap account ID.
var accountIDRE = regexp.MustCompile(
	`(?i)"?(?:bookmap[_\-]?account|account[_\-]?id|accountid|broker[_\-]?account|trader[_\-]?id)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{3,32})`)

// speedOfTapeRE detects Speed of Tape auto-trade armed state.
var speedOfTapeRE = regexp.MustCompile(
	`(?i)(?:speed[_\- ]?of[_\- ]?tape[_\- ]?(?:armed|enabled|auto)\s*=\s*(?:1|true|on|yes)|sot[_\- ]?(?:armed|enabled)\s*=\s*(?:1|true|on)|cluster[_\- ]?auto[_\- ]?trade|iceberg[_\- ]?auto[_\- ]?trade|spoof[_\- ]?detection[_\- ]?armed)`)

// mboMarkerRE detects MBO (Market By Order) subscription
// markers. MBO is a premium L3 feed; CME charges $5K+/month.
var mboMarkerRE = regexp.MustCompile(
	`(?i)(?:mbo[_\- ]?(?:subscription|feed|data|enabled)|market[_\- ]?by[_\- ]?order|l3[_\- ]?(?:depth|feed|data|orderbook)|order[_\- ]?level[_\- ]?data)`)

// pluginConfigRE matches a broker-plugin config section header.
var pluginConfigRE = regexp.MustCompile(
	`(?i)\[(?:IB|IBController|TWS|Rithmic|CQG|Continuum|TT|TradingTechnologies|DAS|DASInet|Kraken|Binance|Bitfinex)\]`)

// pluginCredentialRE matches plug-in cleartext credential row.
var pluginCredentialRE = regexp.MustCompile(
	`(?i)(?:tws[_\- ]?port|ib[_\- ]?port|rithmic[_\- ]?(?:user|server)|cqg[_\- ]?user|das[_\- ]?(?:user|server)|binance[_\- ]?api[_\-]?key|hmac[_\- ]?secret|api[_\- ]?username|client[_\- ]?id)\s*[:=]\s*\S+`)

// indicatorClassRE matches Java indicator class declarations
// in Bookmap Indicator SDK code.
var indicatorClassRE = regexp.MustCompile(
	`(?im)(?:public\s+class\s+\w+\s+implements\s+(?:CustomIndicator|MultiInstrumentIndicator|BookmapIndicator)\b|@Layer\b|@MarketplacePlugin\b)`)

// timestampRE matches `YYYY-MM-DD HH:MM:SS`.
var timestampRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`)

// messageMarkerRE matches per-message rate markers.
var messageMarkerRE = regexp.MustCompile(
	`(?i)(?:MarketDataUpdate|DOMUpdate|HeartBeat|LogonResponse|TradeUpdate|OrderUpdate|book[_\- ]?update|tick[_\- ]?received|depth[_\- ]?update)`)

// symbolEntryRE matches Bookmap symbol entries.
var symbolEntryRE = regexp.MustCompile(
	`(?i)(?:"?(?:symbol(?:_\w+)?|sym|ticker|instrument|root)"?\s*[:=]\s*"?|<symbol[^>]*>|subscribe\(\s*"|addSymbol\(\s*")([A-Za-z0-9_\-\./]{1,32})`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseBookmapConfig parses a generic Bookmap cfg body.
func ParseBookmapConfig(body []byte) BookmapFields {
	var out BookmapFields
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
		out.BookmapAccountID = string(m[1])
	}
	out.BrokerPlugin = detectBrokerPlugin(body)
	if speedOfTapeRE.Match(body) {
		out.HasSpeedOfTapeArmed = true
	}
	if mboMarkerRE.Match(body) {
		out.HasMBOSubscription = true
	}
	out.MATbaSymbolsCount, out.CMESymbolsCount,
		out.CryptoSymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseBookmapCredentials parses a credentials body.
func ParseBookmapCredentials(body []byte) BookmapFields {
	return ParseBookmapConfig(body)
}

// ParseBookmapWorkspace parses a .bookmap workspace body.
func ParseBookmapWorkspace(body []byte) BookmapFields {
	return ParseBookmapConfig(body)
}

// ParseBookmapConnectionConfig parses a per-broker plug-in cfg.
func ParseBookmapConnectionConfig(body []byte) BookmapFields {
	out := ParseBookmapConfig(body)
	if pluginConfigRE.Match(body) && pluginCredentialRE.Match(body) {
		out.HasPassword = out.HasPassword || true
	}
	return out
}

// ParseBookmapIndicatorSDK parses a .java / .indicator body.
func ParseBookmapIndicatorSDK(body []byte) BookmapFields {
	var out BookmapFields
	if len(body) == 0 {
		return out
	}
	out.IndicatorCount = int64(len(indicatorClassRE.FindAllIndex(body, -1)))
	if passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	out.MATbaSymbolsCount, out.CMESymbolsCount,
		out.CryptoSymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseBookmapMarketplacePlugin parses a third-party .jar
// Marketplace plug-in body (best-effort filename + plaintext
// metadata).
func ParseBookmapMarketplacePlugin(body []byte) BookmapFields {
	var out BookmapFields
	out.MarketplaceCount = 1
	if len(body) == 0 {
		return out
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	return out
}

// ParseBookmapSessionLog parses a session-log body.
func ParseBookmapSessionLog(body []byte) BookmapFields {
	var out BookmapFields
	if len(body) == 0 {
		return out
	}
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.BookmapAccountID = string(m[1])
	}
	out.PeakMsgPerSec = peakMessagesPerSecond(body)
	out.MATbaSymbolsCount, out.CMESymbolsCount,
		out.CryptoSymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseBookmapMBOCache parses MBO subscription data — flagged
// as L3 redistribution concern.
func ParseBookmapMBOCache(body []byte) BookmapFields {
	out := ParseBookmapSessionLog(body)
	out.HasMBOSubscription = true
	return out
}

// cuitFromBody returns a cliente CUIT match.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectBrokerPlugin sniffs body for plug-in vendor markers.
func detectBrokerPlugin(body []byte) BrokerPlugin {
	s := strings.ToLower(string(body))
	switch {
	case strings.Contains(s, "[rithmic]") || strings.Contains(s, "rithmic_user"):
		return PluginRithmic
	case strings.Contains(s, "[cqg]") || strings.Contains(s, "[continuum]"):
		return PluginCQG
	case strings.Contains(s, "[tt]") || strings.Contains(s, "tradingtechnologies"):
		return PluginTT
	case strings.Contains(s, "[das]") || strings.Contains(s, "dasinet"):
		return PluginDAS
	case strings.Contains(s, "[kraken]") || strings.Contains(s, "kraken_api_key"):
		return PluginKraken
	case strings.Contains(s, "[binance]") || strings.Contains(s, "binance_api_key"):
		return PluginBinance
	case strings.Contains(s, "[bitfinex]") || strings.Contains(s, "bitfinex_api_key"):
		return PluginBitfinex
	case strings.Contains(s, "[ib]") || strings.Contains(s, "ibcontroller") ||
		strings.Contains(s, "tws_port") || strings.Contains(s, "[tws]"):
		return PluginIB
	case strings.Contains(s, "[plugin]"):
		return PluginCustom
	}
	return PluginUnknown
}

// classifySymbols returns counts of MATba / CME / crypto and
// total distinct symbols.
func classifySymbols(body []byte) (matba, cme, crypto, total int64) {
	seen := map[string]struct{}{}
	mat := map[string]struct{}{}
	cm := map[string]struct{}{}
	crSet := map[string]struct{}{}
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
			mat[stem] = struct{}{}
		case IsCryptoSymbol(s) || IsCryptoSymbol(stem):
			crSet[s] = struct{}{}
		case IsCMEFuturesSymbol(stem):
			cm[stem] = struct{}{}
		}
	}
	return int64(len(mat)), int64(len(cm)),
		int64(len(crSet)), int64(len(seen))
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
