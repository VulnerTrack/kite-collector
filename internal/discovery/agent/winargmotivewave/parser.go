package winargmotivewave

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// MWFields captures scalar fields the audit pipeline needs
// from a MotiveWave artifact.
type MWFields struct {
	APIKey               string
	Username             string
	MotiveWaveAccountID  string
	ClienteCuitRaw       string
	BrokerPlugin         BrokerPlugin
	DistinctSymbols      int64
	MATbaSymbolsCount    int64
	CMESymbolsCount      int64
	USEquitySymbolsCount int64
	PeakMsgPerSec        int64
	StrategyCount        int64
	ElliottWaveRuleCount int64
	HasPassword          bool
	HasDOMArmed          bool
	HasPaperTradingMode  bool
}

// passwordRE matches a password row.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|motivewave[_\-]?password|broker[_\-]?password)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|motivewave[_\-]?password|motivewave[_\-]?secret|broker[_\-]?password)\s*=\s*["'][^"']{1,}["']`)

// apiKeyRE matches a MotiveWave / plug-in API key / token.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(?:motivewave[_\-]?api[_\-]?key|motivewave[_\-]?token|broker[_\-]?token|rithmic[_\-]?token|cqg[_\-]?token|iqfeed[_\-]?token|api[_\-]?key|api[_\-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`)

// usernameRE matches MotiveWave / broker login.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:motivewave[_\-]?username|broker[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`)

// accountIDRE matches a MotiveWave account ID.
var accountIDRE = regexp.MustCompile(
	`(?i)"?(?:motivewave[_\-]?account|account[_\-]?id|accountid|broker[_\-]?account|trader[_\-]?id)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{3,32})`)

// domArmedRE detects DOM Trading panel armed state.
var domArmedRE = regexp.MustCompile(
	`(?i)(?:dom[_\- ]?armed\s*=\s*(?:1|true|on|yes)|dom[_\- ]?trading[_\- ]?enabled\s*=\s*(?:1|true)|auto[_\- ]?execute"?\s*[:=]\s*"?(?:true|1|on|yes)|one[_\- ]?click[_\- ]?trading\s*=\s*(?:1|true|on|yes))`)

// paperTradingRE detects paper / replay-mode markers.
var paperTradingRE = regexp.MustCompile(
	`(?i)(?:paper[_\- ]?trading\s*[:=]\s*(?:true|1|on|enabled)|trading[_\- ]?replay|sim[_\- ]?account|simulation[_\- ]?mode|demo[_\- ]?account)`)

// strategyRE matches Java strategy class declarations in
// MotiveWave Strategy SDK code.
var strategyRE = regexp.MustCompile(
	`(?im)(?:public\s+class\s+\w+\s+extends\s+Strategy\b|public\s+class\s+\w+\s+implements\s+Strategy\b|@StrategyHeader\b|@MotiveWave\.Strategy\b)`)

// elliottWaveRE detects Elliott Wave auto-detection rule
// markers in MotiveWave configs / scripts.
var elliottWaveRE = regexp.MustCompile(
	`(?i)(?:elliott[_\- ]?wave|EW[_\- ]?count|wave[_\- ]?(?:degree|pattern)|impulse[_\- ]?wave|corrective[_\- ]?wave|fibonacci[_\- ]?(?:retrace|extension))`)

// pluginConfigRE matches a broker-plugin config section header.
var pluginConfigRE = regexp.MustCompile(
	`(?i)\[(?:IB|IBController|TWS|Rithmic|CQG|Continuum|IQFeed|TradeStation|TradeKing)\]`)

// pluginCredentialRE matches plug-in cleartext credential row.
var pluginCredentialRE = regexp.MustCompile(
	`(?i)(?:tws[_\- ]?port|ib[_\- ]?port|rithmic[_\- ]?(?:user|server)|cqg[_\- ]?user|iqfeed[_\- ]?(?:user|product)|tradestation[_\- ]?(?:user|token)|api[_\- ]?username|client[_\- ]?id)\s*[:=]\s*\S+`)

// timestampRE matches `YYYY-MM-DD HH:MM:SS`.
var timestampRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`)

// messageMarkerRE matches per-message rate markers.
var messageMarkerRE = regexp.MustCompile(
	`(?i)(?:MarketDataUpdate|QuoteUpdate|TradeUpdate|HeartBeat|LogonResponse|OrderUpdate|tick\s+received|bar\s+update)`)

// symbolEntryRE matches MotiveWave symbol entries.
var symbolEntryRE = regexp.MustCompile(
	`(?i)(?:"?(?:symbol(?:_\w+)?|sym|ticker|instrument|root)"?\s*[:=]\s*"?|<symbol[^>]*>|Symbol\(\s*"|addSymbol\(\s*"|getSymbol\(\s*")([A-Za-z0-9_\-\./]{1,32})`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseMWConfig parses a generic MotiveWave cfg body.
func ParseMWConfig(body []byte) MWFields {
	var out MWFields
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
		out.MotiveWaveAccountID = string(m[1])
	}
	out.BrokerPlugin = detectBrokerPlugin(body)
	if paperTradingRE.Match(body) {
		out.HasPaperTradingMode = true
	}
	out.ElliottWaveRuleCount = int64(len(elliottWaveRE.FindAllIndex(body, -1)))
	out.MATbaSymbolsCount, out.CMESymbolsCount,
		out.USEquitySymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseMWCredentials parses a credentials body.
func ParseMWCredentials(body []byte) MWFields {
	return ParseMWConfig(body)
}

// ParseMWWorkspace parses a .mwk workspace body.
func ParseMWWorkspace(body []byte) MWFields {
	return ParseMWConfig(body)
}

// ParseMWTemplate parses a .mwt template body.
func ParseMWTemplate(body []byte) MWFields {
	return ParseMWConfig(body)
}

// ParseMWJavaStrategy parses a .java strategy body.
func ParseMWJavaStrategy(body []byte) MWFields {
	var out MWFields
	if len(body) == 0 {
		return out
	}
	out.StrategyCount = int64(len(strategyRE.FindAllIndex(body, -1)))
	if passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	out.ElliottWaveRuleCount = int64(len(elliottWaveRE.FindAllIndex(body, -1)))
	out.BrokerPlugin = detectBrokerPlugin(body)
	out.MATbaSymbolsCount, out.CMESymbolsCount,
		out.USEquitySymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseMWConnectionConfig parses a per-broker plug-in cfg.
func ParseMWConnectionConfig(body []byte) MWFields {
	out := ParseMWConfig(body)
	if pluginConfigRE.Match(body) && pluginCredentialRE.Match(body) {
		out.HasPassword = out.HasPassword || true
	}
	return out
}

// ParseMWDOMConfig parses a DOM Trading panel cfg.
func ParseMWDOMConfig(body []byte) MWFields {
	out := ParseMWConfig(body)
	if domArmedRE.Match(body) {
		out.HasDOMArmed = true
	}
	return out
}

// ParseMWSessionLog parses a session log body.
func ParseMWSessionLog(body []byte) MWFields {
	var out MWFields
	if len(body) == 0 {
		return out
	}
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.MotiveWaveAccountID = string(m[1])
	}
	out.PeakMsgPerSec = peakMessagesPerSecond(body)
	out.MATbaSymbolsCount, out.CMESymbolsCount,
		out.USEquitySymbolsCount, out.DistinctSymbols = classifySymbols(body)
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

// detectBrokerPlugin sniffs body for plug-in vendor markers.
func detectBrokerPlugin(body []byte) BrokerPlugin {
	s := strings.ToLower(string(body))
	switch {
	case strings.Contains(s, "[rithmic]") || strings.Contains(s, "rithmic_user"):
		return PluginRithmic
	case strings.Contains(s, "[cqg]") || strings.Contains(s, "[continuum]"):
		return PluginCQG
	case strings.Contains(s, "[iqfeed]") || strings.Contains(s, "iqfeed_user"):
		return PluginIQFeed
	case strings.Contains(s, "[tradestation]") ||
		strings.Contains(s, "tradestation_token"):
		return PluginTradeStation
	case strings.Contains(s, "[tradeking]"):
		return PluginTradeKing
	case strings.Contains(s, "[ib]") || strings.Contains(s, "ibcontroller") ||
		strings.Contains(s, "tws_port") || strings.Contains(s, "[tws]"):
		return PluginIB
	case strings.Contains(s, "[plugin]"):
		return PluginCustom
	}
	return PluginUnknown
}

// classifySymbols returns counts of MATba / CME / US / total
// distinct symbols.
func classifySymbols(body []byte) (matba, cme, us, total int64) {
	seen := map[string]struct{}{}
	mat := map[string]struct{}{}
	cm := map[string]struct{}{}
	usSet := map[string]struct{}{}
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
		case IsCMEFuturesSymbol(stem):
			cm[stem] = struct{}{}
		case IsUSEquityStem(stem):
			usSet[stem] = struct{}{}
		}
	}
	return int64(len(mat)), int64(len(cm)),
		int64(len(usSet)), int64(len(seen))
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
