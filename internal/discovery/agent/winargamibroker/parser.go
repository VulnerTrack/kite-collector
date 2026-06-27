package winargamibroker

import (
	"regexp"
	"strings"
)

// AmiFields captures scalar fields the audit pipeline needs
// from an AmiBroker artifact.
type AmiFields struct {
	APIKey               string
	Username             string
	ClienteCuitRaw       string
	PluginDLLName        string
	BrokerPlugin         BrokerPlugin
	DistinctTickers      int64
	BYMATickersCount     int64
	CEDEARTickersCount   int64
	ARBondTickersCount   int64
	MERVTickersCount     int64
	OrderStatementCount  int64
	FillCount            int64
	HasPassword          bool
	HasBrokerPluginCreds bool
	HasAutotradeArmed    bool
	HasMERVStrategy      bool
}

// passwordRE matches a password row in Broker.txt / config.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|ami[_\-]?password|broker[_\-]?password)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|ami[_\-]?password|broker[_\-]?password|broker[_\-]?secret|tws[_\-]?password)\s*=\s*["'][^"']{1,}["']`)

// apiKeyRE matches an AmiBroker / plug-in API key / token.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(?:ami[_\-]?api[_\-]?key|ami[_\-]?token|broker[_\-]?token|iol[_\-]?token|cocos[_\-]?token|ib[_\-]?token|api[_\-]?key|api[_\-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`)

// usernameRE matches AmiBroker / broker username.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:ami[_\-]?username|broker[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`)

// autotradeArmedRE detects AutoTrade Window armed state. Two
// distinct surfaces:
//
//  1. UI-state config: `AutoTradeEnabled=1`, `auto_trade=true`.
//  2. AFL pragma: `EnableScript("AutoTrade")`, `EnableTextOutput`.
//  3. AmiBroker AFP API: `aamibrokerAutoTrade.Enable(true)`.
var autotradeArmedRE = regexp.MustCompile(
	`(?i)(?:autotradeenabled\s*=\s*(?:1|true|on|yes)|auto[_\- ]?trade\s*[:=]\s*(?:true|1|on|yes)|automatic[_\- ]?execution|auto[_\- ]?trading\s*=\s*(?:1|true|on|yes)|aamibrokerautotrade\.enable\s*\(\s*true)`)

// aflOrderRE detects AFL Buy/Sell/Cover/Short statements that
// indicate an algo-strategy formula (vs purely indicators).
var aflOrderRE = regexp.MustCompile(
	`(?im)\b(?:Buy|Sell|Short|Cover|BuyPrice|SellPrice|ShortPrice|CoverPrice|PlaceTrade|TradeRequest|PositionSize)\s*=`)

// orderEventRE matches an order/fill event in a trade-log
// row (one fill per line).
var orderEventRE = regexp.MustCompile(
	`(?i)(?:OrderFilled|FillEvent|order[_\- ]?id|fill[_\- ]?id|executed[_\- ]?qty|^\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}.*\bFILL\b)`)

// pluginDLLRE matches a known broker-plug-in DLL filename.
var pluginDLLRE = regexp.MustCompile(
	`(?i)(amibroker_ib\.dll|ami_ib\.dll|ib_plugin\.dll|tws_plugin\.dll|amibroker_iol\.dll|iol_plugin\.dll|amibroker_cocos\.dll|cocos_plugin\.dll|amibroker_byma\.dll|byma_plugin\.dll|amibroker_rofex\.dll|rofex_plugin\.dll)`)

// pluginConfigRE matches a plug-in config section header used
// in Broker.txt / plug-in INI files.
var pluginConfigRE = regexp.MustCompile(
	`(?i)\[(?:IB|IBController|TWS|IOL|InvertirOnline|Cocos|CocosCapital|BYMA|Bymadata|Rofex|MATbaRofex)\]`)

// pluginCredentialRE matches a plug-in cleartext credential
// row (port + username pattern is typical for IB TWS).
var pluginCredentialRE = regexp.MustCompile(
	`(?i)(?:tws[_\- ]?port|ib[_\- ]?port|gateway[_\- ]?port|gateway[_\- ]?host|api[_\- ]?username|client[_\- ]?id)\s*[:=]\s*\S+`)

// tickerEntryRE matches AFL/APX/workspace ticker entries:
//   - AFL: `Buy = (Symbol() == "GGAL")`
//   - APX: `<Symbol>GGAL</Symbol>`, `Symbol=GGAL`
//   - AutoTrade: `Symbol("GGAL")`, `AddSymbol("YPFD")`
//
// Trimmed to ≤8 chars to limit false positives on ALL-CAPS
// English words. AR tickers ≤6 chars (e.g. `MERVAL` = 6).
var tickerEntryRE = regexp.MustCompile(
	`(?i)(?:"?(?:symbol(?:_\w+)?|ticker|instrument|stock|equity|name)"?\s*[:=]\s*"?|<symbol[^>]*>|Symbol\(\s*"|AddSymbol\(\s*")([A-Z][A-Z0-9.\-]{1,7})`)

// aflSymbolCmpRE matches the AFL idiom `Symbol() == "TICKER"`
// or `Name() == "TICKER"` (and reverse-order comparison).
// Distinct pattern because the ticker is on the RHS of `==`
// rather than after an `=` assignment.
var aflSymbolCmpRE = regexp.MustCompile(
	`(?i)(?:Symbol|Name)\s*\(\s*\)\s*={2,3}\s*"([A-Z][A-Z0-9.\-]{1,7})"`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseAmiConfig parses Broker.txt / plug-in cfg body.
func ParseAmiConfig(body []byte) AmiFields {
	var out AmiFields
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
	if pluginConfigRE.Match(body) && pluginCredentialRE.Match(body) {
		out.HasBrokerPluginCreds = true
	}
	out.BrokerPlugin = detectBrokerPlugin(body)
	out.BYMATickersCount, out.CEDEARTickersCount, out.ARBondTickersCount,
		out.MERVTickersCount, out.DistinctTickers = classifyTickers(body)
	if out.MERVTickersCount > 0 {
		out.HasMERVStrategy = true
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseAmiCredentials parses a credentials body.
func ParseAmiCredentials(body []byte) AmiFields {
	return ParseAmiConfig(body)
}

// ParseAmiAFLFormula parses an .afl formula body.
func ParseAmiAFLFormula(body []byte) AmiFields {
	var out AmiFields
	if len(body) == 0 {
		return out
	}
	out.OrderStatementCount = int64(len(aflOrderRE.FindAllIndex(body, -1)))
	if passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	out.BrokerPlugin = detectBrokerPlugin(body)
	out.BYMATickersCount, out.CEDEARTickersCount, out.ARBondTickersCount,
		out.MERVTickersCount, out.DistinctTickers = classifyTickers(body)
	if out.MERVTickersCount > 0 {
		out.HasMERVStrategy = true
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseAmiAPXProject parses an .apx project body.
func ParseAmiAPXProject(body []byte) AmiFields {
	return ParseAmiAFLFormula(body)
}

// ParseAmiWorkspace parses an .awx workspace body.
func ParseAmiWorkspace(body []byte) AmiFields {
	var out AmiFields
	if len(body) == 0 {
		return out
	}
	out.BrokerPlugin = detectBrokerPlugin(body)
	out.BYMATickersCount, out.CEDEARTickersCount, out.ARBondTickersCount,
		out.MERVTickersCount, out.DistinctTickers = classifyTickers(body)
	if out.MERVTickersCount > 0 {
		out.HasMERVStrategy = true
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseAmiLayout parses a .cdl layout body.
func ParseAmiLayout(body []byte) AmiFields {
	return ParseAmiWorkspace(body)
}

// ParseAmiAutotradeConfig parses an AutoTrade Window cfg body.
func ParseAmiAutotradeConfig(body []byte) AmiFields {
	out := ParseAmiWorkspace(body)
	if autotradeArmedRE.Match(body) {
		out.HasAutotradeArmed = true
	}
	if pluginConfigRE.Match(body) && pluginCredentialRE.Match(body) {
		out.HasBrokerPluginCreds = true
	}
	return out
}

// ParseAmiBacktestReport parses a backtest-report CSV body.
func ParseAmiBacktestReport(body []byte) AmiFields {
	return ParseAmiWorkspace(body)
}

// ParseAmiTradeLog parses a trade-log body.
func ParseAmiTradeLog(body []byte) AmiFields {
	var out AmiFields
	if len(body) == 0 {
		return out
	}
	out.FillCount = int64(len(orderEventRE.FindAllIndex(body, -1)))
	out.BrokerPlugin = detectBrokerPlugin(body)
	out.BYMATickersCount, out.CEDEARTickersCount, out.ARBondTickersCount,
		out.MERVTickersCount, out.DistinctTickers = classifyTickers(body)
	if out.MERVTickersCount > 0 {
		out.HasMERVStrategy = true
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseAmiBrokerPlugin parses a broker-plugin DLL body — we
// can't parse PE, so we just sniff for printable plug-in
// vendor strings and the DLL filename token.
func ParseAmiBrokerPlugin(body []byte, name string) AmiFields {
	var out AmiFields
	if m := pluginDLLRE.FindString(strings.ToLower(name)); m != "" {
		out.PluginDLLName = m
	} else {
		out.PluginDLLName = strings.ToLower(name)
	}
	out.BrokerPlugin = detectBrokerPluginFromName(out.PluginDLLName)
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
// Order matters: section headers ([IB] etc.) win over generic
// markers (tws_port) because section headers are explicit
// configuration intent. AR-specific plug-ins come first to
// avoid collision with generic IB markers (IOL/Cocos/BYMA/
// ROFEX often coexist with IB-style port config).
func detectBrokerPlugin(body []byte) BrokerPlugin {
	s := strings.ToLower(string(body))
	switch {
	case strings.Contains(s, "invertironline") || strings.Contains(s, "iol_") ||
		strings.Contains(s, "[iol]"):
		return PluginIOL
	case strings.Contains(s, "cocoscapital") || strings.Contains(s, "cocos_") ||
		strings.Contains(s, "[cocos]"):
		return PluginCocos
	case strings.Contains(s, "matbarofex") || strings.Contains(s, "rofex_") ||
		strings.Contains(s, "[rofex]"):
		return PluginROFEX
	case strings.Contains(s, "bymadata") || strings.Contains(s, "byma_") ||
		strings.Contains(s, "[byma]"):
		return PluginBYMA
	case strings.Contains(s, "[ib]") || strings.Contains(s, "ibcontroller") ||
		strings.Contains(s, "interactivebrokers") || strings.Contains(s, "ib_port"):
		return PluginIB
	case strings.Contains(s, "[tws]") || strings.Contains(s, "tws_port") ||
		strings.Contains(s, "tws.dll") || strings.Contains(s, "tws_username") ||
		strings.Contains(s, "tws_password"):
		return PluginTWS
	case strings.Contains(s, "[plugin]"):
		return PluginCustom
	}
	return PluginUnknown
}

// detectBrokerPluginFromName maps a DLL filename to plug-in
// identity.
func detectBrokerPluginFromName(name string) BrokerPlugin {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "iol"):
		return PluginIOL
	case strings.Contains(n, "cocos"):
		return PluginCocos
	case strings.Contains(n, "rofex"):
		return PluginROFEX
	case strings.Contains(n, "byma"):
		return PluginBYMA
	case strings.Contains(n, "tws"):
		return PluginTWS
	case strings.Contains(n, "ib"):
		return PluginIB
	case strings.Contains(n, "plugin") || strings.Contains(n, "broker"):
		return PluginCustom
	}
	return PluginUnknown
}

// classifyTickers walks the body matching tickers and returns
// (byma, cedear, ar-bond, merv, total) counts. Each ticker
// is counted once regardless of how many times it appears.
// Two regex passes cover assignment-style and AFL-comparison-
// style ticker usage.
func classifyTickers(body []byte) (byma, cedear, bond, merv, total int64) {
	seen := map[string]struct{}{}
	bymaSet := map[string]struct{}{}
	cedearSet := map[string]struct{}{}
	bondSet := map[string]struct{}{}
	mervSet := map[string]struct{}{}
	consider := func(s string) {
		if s == "" {
			return
		}
		seen[s] = struct{}{}
		switch {
		case IsMERVIndexSymbol(s):
			mervSet[s] = struct{}{}
		case IsARBondTicker(s):
			bondSet[s] = struct{}{}
		case IsBYMAEquityTicker(s):
			bymaSet[s] = struct{}{}
		case IsCEDEARTicker(s):
			cedearSet[s] = struct{}{}
		}
	}
	for _, m := range tickerEntryRE.FindAllSubmatch(body, -1) {
		consider(strings.ToUpper(strings.TrimSpace(string(m[1]))))
	}
	for _, m := range aflSymbolCmpRE.FindAllSubmatch(body, -1) {
		consider(strings.ToUpper(strings.TrimSpace(string(m[1]))))
	}
	return int64(len(bymaSet)), int64(len(cedearSet)),
		int64(len(bondSet)), int64(len(mervSet)), int64(len(seen))
}
