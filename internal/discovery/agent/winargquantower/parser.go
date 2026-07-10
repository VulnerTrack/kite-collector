package winargquantower

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// QuantowerFields captures scalar fields the audit pipeline
// needs from a Quantower artifact.
type QuantowerFields struct {
	APIKey               string
	APISecret            string
	Username             string
	QuantowerAccountID   string
	ClienteCuitRaw       string
	BrokerPlugin         BrokerPlugin
	DistinctSymbols      int64
	MATbaSymbolsCount    int64
	CMESymbolsCount      int64
	USEquitySymbolsCount int64
	CryptoSymbolsCount   int64
	PeakMsgPerSec        int64
	StrategyCount        int64
	HasPassword          bool
	HasDOMArmed          bool
	HasPaperTradingMode  bool
	HasUSDTARSArbitrage  bool
}

// passwordRE matches a password row.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|quantower[_\-]?password|broker[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|quantower[_\-]?password|quantower[_\-]?secret|broker[_\-]?password|broker[_\-]?secret)\s*=\s*["'][^"']{1,}["']`,
)

// apiKeyRE matches a Quantower / plug-in API key / token.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(?:quantower[_\-]?api[_\-]?key|quantower[_\-]?token|binance[_\-]?api[_\-]?key|bybit[_\-]?api[_\-]?key|cqg[_\-]?token|rithmic[_\-]?token|broker[_\-]?token|api[_\-]?key|api[_\-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`,
)

// apiSecretRE matches a Quantower / plug-in API secret.
var apiSecretRE = regexp.MustCompile(
	`(?i)("|')?(?:api[_\-]?secret|binance[_\-]?api[_\-]?secret|bybit[_\-]?api[_\-]?secret|secret[_\-]?key|hmac[_\-]?secret)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`,
)

// usernameRE matches Quantower / broker login.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:quantower[_\-]?username|broker[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// accountIDRE matches a Quantower account ID.
var accountIDRE = regexp.MustCompile(
	`(?i)"?(?:quantower[_\-]?account|account[_\-]?id|accountid|broker[_\-]?account|trader[_\-]?id)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{3,32})`,
)

// domArmedRE detects DOM Trading panel armed state.
var domArmedRE = regexp.MustCompile(
	`(?i)(?:dom[_\- ]?armed\s*=\s*(?:1|true|on|yes)|dom[_\- ]?trading[_\- ]?enabled\s*=\s*(?:1|true)|auto[_\- ]?execute"?\s*[:=]\s*"?(?:true|1|on|yes)|one[_\- ]?click[_\- ]?trading\s*=\s*(?:1|true|on|yes))`,
)

// paperTradingRE detects paper-trading mode markers.
var paperTradingRE = regexp.MustCompile(
	`(?i)(?:paper[_\- ]?trading\s*[:=]\s*(?:true|1|on|enabled)|paper[_\- ]?mode\s*=\s*(?:true|1|on)|sim[_\- ]?account|simulation[_\- ]?mode|demo[_\- ]?account)`,
)

// strategyRE matches strategy / indicator class declarations
// in C# algo scripts.
var strategyRE = regexp.MustCompile(
	`(?i)(?:public\s+class\s+\w+\s*:\s*Strategy|public\s+class\s+\w+\s*:\s*Indicator|\bAddStrategy\(|\bRunStrategy\()`,
)

// pluginConfigRE matches a broker-plugin config section header.
var pluginConfigRE = regexp.MustCompile(
	`(?i)\[(?:Binance|Bybit|Bitfinex|Kraken|Coinbase|Rithmic|CQG|Continuum|TT|TradingTechnologies|IB|TWS|IBController|dxFeed|OANDA)\]`,
)

// pluginCredentialRE matches plug-in cleartext credential row.
var pluginCredentialRE = regexp.MustCompile(
	`(?i)(?:tws[_\- ]?port|ib[_\- ]?port|rithmic[_\- ]?(?:user|server)|cqg[_\- ]?user|binance[_\- ]?api[_\-]?key|bybit[_\- ]?api[_\-]?key|hmac[_\- ]?secret|api[_\- ]?username|client[_\- ]?id)\s*[:=]\s*\S+`,
)

// usdtArsArbitrageRE detects USDT/ARS arbitrage logic.
var usdtArsArbitrageRE = regexp.MustCompile(
	`(?i)(?:brecha[_\- ]?cambiaria|dolar[_\- ]?(?:blue|mep|ccl|tarjeta|oficial)|usdt[_\- ]?ars|usdc[_\- ]?ars|arbitrage|arbitraje|cross[_\- ]?venue[_\- ]?price)`,
)

// orderEventRE matches per-fill marker in trade log.
var orderEventRE = regexp.MustCompile(
	`(?i)(?:OrderFilled|FillEvent|FillID|fill[_\- ]?id|^\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}|execution[_\- ]?report)`,
)

// timestampRE matches `YYYY-MM-DD HH:MM:SS`.
var timestampRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`,
)

// messageMarkerRE matches per-message rate markers.
var messageMarkerRE = regexp.MustCompile(
	`(?i)(?:MarketDataUpdate|MarketDepthUpdate|DOMUpdate|HeartBeat|LogonResponse|TradeUpdate|OrderUpdate|QuoteUpdate|trade\s+received|depth\s+update)`,
)

// symbolEntryRE matches Quantower symbol entries.
var symbolEntryRE = regexp.MustCompile(
	`(?i)(?:"?(?:symbol(?:_\w+)?|sym|ticker|instrument|root)"?\s*[:=]\s*"?|<symbol[^>]*>|AddSymbol\(\s*"|Symbol\(\s*")([A-Za-z0-9_\-\./]{1,32})`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseQuantowerConfig parses a generic Quantower cfg body.
func ParseQuantowerConfig(body []byte) QuantowerFields {
	var out QuantowerFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	if m := apiSecretRE.FindSubmatch(body); len(m) > 3 {
		out.APISecret = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.QuantowerAccountID = string(m[1])
	}
	out.BrokerPlugin = detectBrokerPlugin(body)
	if paperTradingRE.Match(body) {
		out.HasPaperTradingMode = true
	}
	out.MATbaSymbolsCount, out.CMESymbolsCount,
		out.USEquitySymbolsCount, out.CryptoSymbolsCount,
		out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseQuantowerCredentials parses a credentials body.
func ParseQuantowerCredentials(body []byte) QuantowerFields {
	return ParseQuantowerConfig(body)
}

// ParseQuantowerWorkspace parses a .qwt workspace body.
func ParseQuantowerWorkspace(body []byte) QuantowerFields {
	return ParseQuantowerConfig(body)
}

// ParseQuantowerSymbols parses a Symbols.json body.
func ParseQuantowerSymbols(body []byte) QuantowerFields {
	var out QuantowerFields
	if len(body) == 0 {
		return out
	}
	out.MATbaSymbolsCount, out.CMESymbolsCount,
		out.USEquitySymbolsCount, out.CryptoSymbolsCount,
		out.DistinctSymbols = classifySymbols(body)
	return out
}

// ParseQuantowerConnectionConfig parses a per-broker plug-in
// connection config.
func ParseQuantowerConnectionConfig(body []byte) QuantowerFields {
	out := ParseQuantowerConfig(body)
	if pluginConfigRE.Match(body) && pluginCredentialRE.Match(body) {
		// HasBrokerPluginCredentials surfaces via the collector.
		out.HasPassword = out.HasPassword || true
	}
	return out
}

// ParseQuantowerAlgoSDKScript parses a C# algo strategy .cs body.
func ParseQuantowerAlgoSDKScript(body []byte) QuantowerFields {
	var out QuantowerFields
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
	if m := apiSecretRE.FindSubmatch(body); len(m) > 3 {
		out.APISecret = string(m[3])
	}
	if usdtArsArbitrageRE.Match(body) {
		out.HasUSDTARSArbitrage = true
	}
	out.BrokerPlugin = detectBrokerPlugin(body)
	out.MATbaSymbolsCount, out.CMESymbolsCount,
		out.USEquitySymbolsCount, out.CryptoSymbolsCount,
		out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseQuantowerAlgoBuilder parses Algo Builder visual cfg.
func ParseQuantowerAlgoBuilder(body []byte) QuantowerFields {
	return ParseQuantowerWorkspace(body)
}

// ParseQuantowerMultiStrategyLauncher parses a multi-strategy
// launcher batch cfg.
func ParseQuantowerMultiStrategyLauncher(body []byte) QuantowerFields {
	out := ParseQuantowerConfig(body)
	out.StrategyCount = int64(len(strategyRE.FindAllIndex(body, -1)))
	return out
}

// ParseQuantowerDOMConfig parses a DOM Trading panel cfg.
func ParseQuantowerDOMConfig(body []byte) QuantowerFields {
	out := ParseQuantowerConfig(body)
	if domArmedRE.Match(body) {
		out.HasDOMArmed = true
	}
	return out
}

// ParseQuantowerTradeLog parses a trade-log body.
func ParseQuantowerTradeLog(body []byte) QuantowerFields {
	var out QuantowerFields
	if len(body) == 0 {
		return out
	}
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.QuantowerAccountID = string(m[1])
	}
	out.PeakMsgPerSec = peakMessagesPerSecond(body)
	out.MATbaSymbolsCount, out.CMESymbolsCount,
		out.USEquitySymbolsCount, out.CryptoSymbolsCount,
		out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	_ = orderEventRE
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
	case strings.Contains(s, "[binance]") || strings.Contains(s, "binance_api_key"):
		return PluginBinance
	case strings.Contains(s, "[bybit]") || strings.Contains(s, "bybit_api_key"):
		return PluginBybit
	case strings.Contains(s, "[bitfinex]") || strings.Contains(s, "bitfinex_api_key"):
		return PluginBitfinex
	case strings.Contains(s, "[kraken]") || strings.Contains(s, "kraken_api_key"):
		return PluginKraken
	case strings.Contains(s, "[coinbase]") || strings.Contains(s, "coinbase_api_key"):
		return PluginCoinbase
	case strings.Contains(s, "[rithmic]") || strings.Contains(s, "rithmic_user"):
		return PluginRithmic
	case strings.Contains(s, "[cqg]") || strings.Contains(s, "[continuum]"):
		return PluginCQG
	case strings.Contains(s, "[tt]") || strings.Contains(s, "tradingtechnologies"):
		return PluginTT
	case strings.Contains(s, "[ib]") || strings.Contains(s, "ibcontroller") ||
		strings.Contains(s, "tws_port"):
		return PluginIB
	case strings.Contains(s, "[dxfeed]") || strings.Contains(s, "dxfeed_credentials"):
		return PluginDXFeed
	case strings.Contains(s, "[oanda]") || strings.Contains(s, "oanda_account"):
		return PluginOanda
	case strings.Contains(s, "[plugin]") || strings.Contains(s, "custom_plugin"):
		return PluginCustom
	}
	return PluginUnknown
}

// classifySymbols returns counts of MATba / CME / US / crypto
// and total distinct symbols.
func classifySymbols(body []byte) (matba, cme, us, crypto, total int64) {
	seen := map[string]struct{}{}
	mat := map[string]struct{}{}
	cm := map[string]struct{}{}
	usSet := map[string]struct{}{}
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
		case IsUSEquityStem(stem):
			usSet[stem] = struct{}{}
		}
	}
	return int64(len(mat)), int64(len(cm)), int64(len(usSet)),
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
