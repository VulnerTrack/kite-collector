package winargmulticharts

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// MCFields captures scalar fields the audit pipeline needs from
// a MultiCharts artifact.
type MCFields struct {
	APIKey               string
	Username             string
	MCAccountID          string
	ClienteCuitRaw       string
	BrokerPlugin         BrokerPlugin
	DistinctSymbols      int64
	MATbaSymbolsCount    int64
	CMESymbolsCount      int64
	PeakMsgPerSec        int64
	FillCount            int64
	PortfolioSymbolCount int64
	HasPassword          bool
	HasBrokerPluginCreds bool
	HasSendOrderStrategy bool
	HasPortfolioTrader   bool
	HasDOMArmed          bool
}

// passwordRE matches a password row in MultiCharts.cfg /
// BrokerProfiles\<broker>.cfg.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|mc[_\-]?password|broker[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|mc[_\-]?password|broker[_\-]?password|rithmic[_\-]?password|tws[_\-]?password)\s*=\s*["'][^"']{1,}["']`,
)

// apiKeyRE matches a MultiCharts / plug-in API key / token.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(?:mc[_\-]?api[_\-]?key|mc[_\-]?token|rithmic[_\-]?token|cqg[_\-]?token|iqfeed[_\-]?token|broker[_\-]?token|api[_\-]?key|api[_\-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`,
)

// usernameRE matches MultiCharts / plug-in username.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:mc[_\-]?username|broker[_\-]?user|username|user|login[_\-]?id|email|rithmic[_\-]?user)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// accountIDRE matches an MC account ID / broker account.
var accountIDRE = regexp.MustCompile(
	`(?i)"?(?:mc[_\-]?account|account[_\-]?id|accountid|broker[_\-]?account|trader[_\-]?id|account[_\-]?name)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{3,32})`,
)

// sendOrderRE detects Send-Order Strategy armed state. Two
// surfaces:
//
//  1. UI cfg: `SendOrderEnabled=1`, `AutoTradingState=ON`.
//  2. .wsp workspace flag: `SendOrders="true"`,
//     `AutomatedTrading="enabled"`.
//  3. Portfolio Trader auto-execution: `autoExecution=true`.
var sendOrderRE = regexp.MustCompile(
	`(?i)(?:send[_\- ]?order[_\- ]?enabled\s*=\s*(?:1|true|on|yes)|sendorders\s*=\s*"?true|autotrading[_\- ]?state\s*=\s*(?:on|enabled|true|1)|automatedtrading\s*=\s*"?(?:enabled|true|1)|autoexecution\s*=\s*"?(?:true|1)|auto[_\- ]?trading\s*=\s*(?:1|true|on|yes))`,
)

// portfolioTraderRE detects Portfolio Trader markers — config
// for multi-symbol portfolio strategy execution.
var portfolioTraderRE = regexp.MustCompile(
	`(?i)(?:portfolio[_\- ]?trader|portfoliotrader|portfolio[_\- ]?session|<portfolio[ >]|portfolio[_\- ]?strategy)`,
)

// domArmedRE detects DOM (Depth-of-Market) Trading panel armed
// state — scalper / HFT pattern.
var domArmedRE = regexp.MustCompile(
	`(?i)(?:dom[_\- ]?trading[_\- ]?enabled\s*=\s*(?:1|true|on|yes)|dom[_\- ]?armed\s*=\s*(?:1|true|on|yes)|domtrading\s*=\s*"?true|order[_\- ]?bar[_\- ]?armed\s*=\s*(?:1|true|on|yes))`,
)

// pluginConfigRE matches a broker-plug-in config section header.
var pluginConfigRE = regexp.MustCompile(
	`(?i)\[(?:IB|IBController|TWS|Rithmic|CQG|Continuum|IQFeed|InteractiveData|TT|MATbaRofex|Matba_Rofex|Matba-Rofex)\]`,
)

// pluginCredentialRE matches a plug-in cleartext credential row.
var pluginCredentialRE = regexp.MustCompile(
	`(?i)(?:tws[_\- ]?port|ib[_\- ]?port|gateway[_\- ]?port|gateway[_\- ]?host|rithmic[_\- ]?(?:user|server|gateway)|cqg[_\- ]?(?:user|server)|iqfeed[_\- ]?(?:user|product)|api[_\- ]?username|client[_\- ]?id)\s*[:=]\s*\S+`,
)

// orderEventRE matches an order/fill event in a trade-log row.
var orderEventRE = regexp.MustCompile(
	`(?i)(?:OrderFilled|FillEvent|FillID|order[_\- ]?id|fill[_\- ]?id|executed[_\- ]?qty|^\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}.*\bFILL\b)`,
)

// timestampRE matches `YYYY-MM-DD HH:MM:SS`.
var timestampRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`,
)

// messageMarkerRE matches per-message markers used to estimate
// message rate (DOM updates dominate in MultiCharts logs).
var messageMarkerRE = regexp.MustCompile(
	`(?i)(?:MarketDataUpdate|MarketDepthUpdate|DOMUpdate|HeartBeat|LogonResponse|TradeAccountResponse|ExecutionReport|OrderUpdate|QuoteUpdate)`,
)

// symbolEntryRE matches MultiCharts symbol entries: workspace
// XML `<Symbol>DLR</Symbol>`, .wsp `Symbol=ES`, JSON
// `"symbol":"6E"`, Portfolio Trader `<sym>...</sym>`,
// PowerLanguage `inputs: Symbol("DLR")`.
var symbolEntryRE = regexp.MustCompile(
	`(?i)(?:"?(?:symbol(?:_\w+)?|sym|simbolo|ticker|instrument|contract|root)"?\s*[:=]\s*"?|<symbol[^>]*>|<sym[^>]*>|Symbol\(\s*"|InsertSymbol\(\s*")([A-Za-z0-9_\-\./]{2,32})`,
)

// portfolioSymRE matches Portfolio Trader symbol entries in
// .pls files — counts how many symbols the portfolio runs.
var portfolioSymRE = regexp.MustCompile(
	`(?i)<(?:symbol|sym|instrument)[^>]*>([A-Za-z0-9_\-\./]{2,32})</(?:symbol|sym|instrument)>`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseMCConfig parses MultiCharts.cfg / BrokerProfiles cfg.
func ParseMCConfig(body []byte) MCFields {
	var out MCFields
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
		out.MCAccountID = string(m[1])
	}
	if pluginConfigRE.Match(body) && pluginCredentialRE.Match(body) {
		out.HasBrokerPluginCreds = true
	}
	out.BrokerPlugin = detectBrokerPlugin(body)
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseMCCredentials parses a credentials body.
func ParseMCCredentials(body []byte) MCFields {
	return ParseMCConfig(body)
}

// ParseMCWorkspace parses .wsp workspace body.
func ParseMCWorkspace(body []byte) MCFields {
	var out MCFields
	if len(body) == 0 {
		return out
	}
	if sendOrderRE.Match(body) {
		out.HasSendOrderStrategy = true
	}
	if portfolioTraderRE.Match(body) {
		out.HasPortfolioTrader = true
	}
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.MCAccountID = string(m[1])
	}
	out.BrokerPlugin = detectBrokerPlugin(body)
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseMCPortfolio parses .pls portfolio session body.
func ParseMCPortfolio(body []byte) MCFields {
	out := ParseMCWorkspace(body)
	out.HasPortfolioTrader = true
	out.PortfolioSymbolCount = int64(len(portfolioSymRE.FindAllIndex(body, -1)))
	return out
}

// ParseMCPLAStrategy parses an encrypted .pla strategy. Body
// can't be decoded — we just sniff the trailing plaintext
// header for symbol hints and CUIT.
func ParseMCPLAStrategy(body []byte) MCFields {
	var out MCFields
	if len(body) == 0 {
		return out
	}
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseMCELAStrategy parses an .ela export — same shape as .pla
// for our purposes (some body may decode as text).
func ParseMCELAStrategy(body []byte) MCFields {
	return ParseMCPLAStrategy(body)
}

// ParseMCNetScript parses a .cs C# script (MultiCharts.NET).
func ParseMCNetScript(body []byte) MCFields {
	var out MCFields
	if len(body) == 0 {
		return out
	}
	if passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	out.BrokerPlugin = detectBrokerPlugin(body)
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseMCPortfolioTraderConfig parses a Portfolio Trader cfg.
func ParseMCPortfolioTraderConfig(body []byte) MCFields {
	out := ParseMCConfig(body)
	out.HasPortfolioTrader = true
	if sendOrderRE.Match(body) {
		out.HasSendOrderStrategy = true
	}
	out.PortfolioSymbolCount = int64(len(portfolioSymRE.FindAllIndex(body, -1)))
	return out
}

// ParseMCDOMConfig parses a DOM Trading panel cfg.
func ParseMCDOMConfig(body []byte) MCFields {
	out := ParseMCConfig(body)
	if domArmedRE.Match(body) {
		out.HasDOMArmed = true
	}
	return out
}

// ParseMCBacktestReport parses a backtest-report CSV body.
func ParseMCBacktestReport(body []byte) MCFields {
	return ParseMCWorkspace(body)
}

// ParseMCTradeLog parses a trade-log body.
func ParseMCTradeLog(body []byte) MCFields {
	var out MCFields
	if len(body) == 0 {
		return out
	}
	out.FillCount = int64(len(orderEventRE.FindAllIndex(body, -1)))
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.MCAccountID = string(m[1])
	}
	out.BrokerPlugin = detectBrokerPlugin(body)
	out.PeakMsgPerSec = peakMessagesPerSecond(body)
	out.MATbaSymbolsCount, out.CMESymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseMCBrokerPlugin parses a broker-plugin DLL body — we
// can't parse PE, so we just sniff filename for plug-in
// identity.
func ParseMCBrokerPlugin(_ []byte, name string) MCFields {
	var out MCFields
	out.BrokerPlugin = detectBrokerPluginFromName(name)
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
// Order matters: AR-specific first, then section headers, then
// generic vendor tokens.
func detectBrokerPlugin(body []byte) BrokerPlugin {
	s := strings.ToLower(string(body))
	switch {
	case strings.Contains(s, "matbarofex") || strings.Contains(s, "matba_rofex") ||
		strings.Contains(s, "matba-rofex") || strings.Contains(s, "[matbarofex]"):
		return PluginMATbaRofex
	case strings.Contains(s, "[rithmic]") || strings.Contains(s, "rithmic_user") ||
		strings.Contains(s, "rithmic_server") || strings.Contains(s, "r|api"):
		return PluginRithmic
	case strings.Contains(s, "[cqg]") || strings.Contains(s, "[continuum]") ||
		strings.Contains(s, "cqg_continuum") || strings.Contains(s, "cqg_user"):
		return PluginCQG
	case strings.Contains(s, "[iqfeed]") || strings.Contains(s, "iqfeed_product") ||
		strings.Contains(s, "iqfeed_user"):
		return PluginIQFeed
	case strings.Contains(s, "[interactivedata]") ||
		strings.Contains(s, "interactive_data") || strings.Contains(s, "interactivedata"):
		return PluginInteractiveData
	case strings.Contains(s, "[tt]") || strings.Contains(s, "tradingtechnologies"):
		return PluginTT
	case strings.Contains(s, "[ib]") || strings.Contains(s, "ibcontroller") ||
		strings.Contains(s, "interactivebrokers") || strings.Contains(s, "ib_port"):
		return PluginIB
	case strings.Contains(s, "[tws]") || strings.Contains(s, "tws_port") ||
		strings.Contains(s, "tws.dll"):
		return PluginIB
	case strings.Contains(s, "[plugin]"):
		return PluginCustom
	}
	return PluginUnknown
}

// detectBrokerPluginFromName maps a DLL/cfg filename to plug-in
// identity.
func detectBrokerPluginFromName(name string) BrokerPlugin {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "matbarofex") || strings.Contains(n, "matba_rofex"):
		return PluginMATbaRofex
	case strings.Contains(n, "rithmic"):
		return PluginRithmic
	case strings.Contains(n, "cqg"):
		return PluginCQG
	case strings.Contains(n, "iqfeed"):
		return PluginIQFeed
	case strings.Contains(n, "interactive_data") || strings.Contains(n, "interactivedata"):
		return PluginInteractiveData
	case strings.Contains(n, "tradingtechnologies") || strings.Contains(n, "tt_"):
		return PluginTT
	case strings.Contains(n, "ibcontroller") || strings.Contains(n, "interactivebrokers"):
		return PluginIB
	case strings.Contains(n, "tws"):
		return PluginIB
	case strings.Contains(n, "ib"):
		return PluginIB
	case strings.Contains(n, "broker") || strings.Contains(n, "plugin"):
		return PluginCustom
	}
	return PluginUnknown
}

// classifySymbols returns counts of distinct MATba-Rofex, CME,
// and total symbols. Splits only on `/` (contract-month
// separator) — MATba symbols themselves contain `-`.
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
