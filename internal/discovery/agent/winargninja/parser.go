package winargninja

import (
	"regexp"
	"strings"
)

// NinjaFields captures scalar fields the audit pipeline needs
// from a NinjaTrader 8 artifact.
type NinjaFields struct {
	APIKey              string
	Username            string
	NinjaAccountID      string
	ClienteCuitRaw      string
	DataFeed            DataFeed
	PropFirm            PropFirm
	DistinctSymbols     int64
	FuturesSymbolsCount int64
	MicroFuturesCount   int64
	OptionsSymbolsCount int64
	EnterOrderCallCount int64
	AddOnCount          int64
	FillCount           int64
	HasPassword         bool
	HasApexProp         bool
	HasTopstepXProp     bool
	HasEarn2TradeProp   bool
	HasPythonBridge     bool
	HasNinjaStrategy    bool
	HasNinjaIndicator   bool
	HasNinjaAddOn       bool
}

// passwordRE matches a password row.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|ninja[_\-]?password|ninja[_\-]?secret|broker[_\-]?password|connection[_\-]?password|continuum[_\-]?password|rithmic[_\-]?password|cqg[_\-]?password)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line in INI or
// JSON-quoted form.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|ninja[_\-]?password|ninja[_\-]?secret|broker[_\-]?password|connection[_\-]?password|continuum[_\-]?password|rithmic[_\-]?password|cqg[_\-]?password)\b"?\s*[:=]\s*["'][^"']{1,}["']`)

// passwordXMLRE matches `<password>secret</password>` for
// Connections.xml form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|ninja[_\-]?password|broker[_\-]?password|connection[_\-]?password)\s*>([^<]{1,})<\s*/`)

// apiKeyRE matches NinjaTrader / broker API key / token. INI,
// JSON, and XML separator forms (`[:=>]`) all supported.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(?:ninja[_\-]?api[_\-]?key|ninja[_\-]?token|broker[_\-]?token|continuum[_\-]?token|rithmic[_\-]?token|cqg[_\-]?token|api[_\-]?key|api[_\-]?token|access[_\-]?token)("|')?\s*[:=>]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`)

// usernameRE matches NinjaTrader / broker login. INI / JSON /
// XML separator forms (`[:=>]`) all supported.
var usernameRE = regexp.MustCompile(
	`(?i)"?(?:ninja[_\-]?username|ninja[_\-]?user|broker[_\-]?user|continuum[_\-]?user|rithmic[_\-]?user|cqg[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=>]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`)

// accountIDRE matches a NinjaTrader account ID. Apex / TopstepX
// use uppercase alphanumeric short tickers. INI / JSON / XML
// separator forms (`[:=>]`) all supported.
var accountIDRE = regexp.MustCompile(
	`(?i)"?(?:account[_\-]?id|ninja[_\-]?account[_\-]?id|account[_\-]?number|account[_\-]?code|user[_\-]?id|registration[_\-]?id)"?\s*[:=>]\s*"?([A-Za-z0-9_\-]{3,32})`)

// strategyClassRE matches a NinjaScript Strategy class definition.
var strategyClassRE = regexp.MustCompile(
	`(?im)(?:^|\s)public\s+class\s+\w+\s*:\s*Strategy\b`)

// indicatorClassRE matches a NinjaScript Indicator class definition.
var indicatorClassRE = regexp.MustCompile(
	`(?im)(?:^|\s)public\s+class\s+\w+\s*:\s*Indicator\b`)

// addOnClassRE matches a NinjaScript AddOnBase class definition.
var addOnClassRE = regexp.MustCompile(
	`(?im)(?:^|\s)public\s+class\s+\w+\s*:\s*(?:AddOnBase|NTWindow)\b`)

// enterOrderRE matches a NinjaScript order-submission call.
// `EnterLong`, `EnterShort`, `ExitLong`, `ExitShort`,
// `SubmitOrderUnmanaged`, `SubmitOrder` are the documented
// NinjaScript order-API surface.
var enterOrderRE = regexp.MustCompile(
	`(?i)\b(?:EnterLong|EnterShort|EnterLongLimit|EnterShortLimit|EnterLongStopMarket|EnterShortStopMarket|ExitLong|ExitShort|ExitLongLimit|ExitShortLimit|SubmitOrderUnmanaged|SubmitOrder)\s*\(`)

// pythonBridgeRE matches Python bridge invocation. NinjaTrader 8
// can host IronPython via a custom AddOn / pluggable runtime.
var pythonBridgeRE = regexp.MustCompile(
	`(?i)\b(?:IronPython|PythonScriptEngine|Py_Initialize|PyRun_String|Microsoft\.Scripting\.Hosting|python\.exe|python3\.exe)\b`)

// addOnReferenceRE matches an AddOn-class-reference idiom (used
// to count distinct AddOns).
var addOnReferenceRE = regexp.MustCompile(
	`(?im)(?:^|\s)public\s+class\s+(\w+)\s*:\s*(?:AddOnBase|NTWindow)\b`)

// optionsSymbolRE matches an OCC-style option chain symbol.
var optionsSymbolRE = regexp.MustCompile(
	`(?i)\b([A-Z]{1,5}_\d{6}[CP]\d{8})\b`)

// futureSymbolRE matches a CME-style continuous futures symbol
// (e.g. `ES 09-26`, `MES 09-26`, `MNQ-09-26`, `MES_09-26`).
// NinjaScript also supports bare stem references.
var futureSymbolRE = regexp.MustCompile(
	`(?i)\b([A-Z]{2,4})[_\s\-]?(\d{2}[\-/]\d{2})\b`)

// symbolEntryRE matches a per-symbol entry in workspaces /
// templates / trade-performance / chart def. TradePerformance.csv
// data rows start with `<Time>,<Account>,<Instrument>,<Side>,...`
// — anchor on `^<time>,<acct>,<TICKER>,` and on keyword markers.
var symbolEntryRE = regexp.MustCompile(
	`(?im)(?:"?(?:symbol(?:_\w+)?|sym|ticker|instrument|fullname)"?\s*[:=]\s*"?|<(?:symbol|instrument|fullname)[^>]*>|^(?:[\d:.]+,)?[A-Za-z0-9_\-]+,)([A-Z][A-Z0-9_\-\./]{0,7})`)

// orderFillRE matches a per-fill row in NinjaTrader 8
// TradePerformance CSV. Header form:
// `Instrument,Account,Strategy,MarketPosition,Quantity,Entry price,Exit price,...`
// Data rows have an instrument (CME-stem-with-contract or bare
// ticker), an account ID, a strategy name, and a position side.
var orderFillRE = regexp.MustCompile(
	`(?im)^[A-Z][A-Z0-9_\-\. /]{1,16},[A-Za-z0-9_\-]+,[A-Za-z0-9_\-]+,(?:Long|Short|LONG|SHORT|Flat|FLAT|Buy|Sell|BUY|SELL),`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N` in INI,
// JSON, or XML form (`[:=>]` separator class).
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseNinjaConfig parses a generic NinjaTrader cfg / XML body.
func ParseNinjaConfig(body []byte) NinjaFields {
	var out NinjaFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.NinjaAccountID = string(m[1])
	}
	out.DataFeed = detectDataFeed(body)
	pf, apex, top, e2t := detectPropFirm(body)
	out.PropFirm = pf
	out.HasApexProp = apex
	out.HasTopstepXProp = top
	out.HasEarn2TradeProp = e2t
	if pythonBridgeRE.Match(body) {
		out.HasPythonBridge = true
	}
	out.FuturesSymbolsCount, out.MicroFuturesCount, out.OptionsSymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseNinjaCredentials parses a credentials body.
func ParseNinjaCredentials(body []byte) NinjaFields {
	return ParseNinjaConfig(body)
}

// ParseNinjaStrategy parses a NinjaScript .cs strategy body.
func ParseNinjaStrategy(body []byte) NinjaFields {
	out := ParseNinjaConfig(body)
	if strategyClassRE.Match(body) {
		out.HasNinjaStrategy = true
	}
	out.EnterOrderCallCount = int64(len(enterOrderRE.FindAllIndex(body, -1)))
	if out.EnterOrderCallCount > 0 {
		out.HasNinjaStrategy = true
	}
	return out
}

// ParseNinjaIndicator parses a NinjaScript indicator body.
func ParseNinjaIndicator(body []byte) NinjaFields {
	out := ParseNinjaConfig(body)
	if indicatorClassRE.Match(body) {
		out.HasNinjaIndicator = true
	}
	return out
}

// ParseNinjaAddOn parses a NinjaScript AddOn body.
func ParseNinjaAddOn(body []byte) NinjaFields {
	out := ParseNinjaConfig(body)
	if addOnClassRE.Match(body) {
		out.HasNinjaAddOn = true
	}
	out.AddOnCount = int64(len(addOnReferenceRE.FindAllIndex(body, -1)))
	return out
}

// ParseNinjaWorkspace parses a workspace .xml body.
func ParseNinjaWorkspace(body []byte) NinjaFields {
	return ParseNinjaConfig(body)
}

// ParseNinjaConnection parses a Connections.xml body.
func ParseNinjaConnection(body []byte) NinjaFields {
	return ParseNinjaConfig(body)
}

// ParseNinjaTradePerformance parses a TradePerformance.csv body.
func ParseNinjaTradePerformance(body []byte) NinjaFields {
	var out NinjaFields
	if len(body) == 0 {
		return out
	}
	out.FillCount = int64(len(orderFillRE.FindAllIndex(body, -1)))
	if m := accountIDRE.FindSubmatch(body); len(m) > 1 {
		out.NinjaAccountID = string(m[1])
	}
	out.FuturesSymbolsCount, out.MicroFuturesCount, out.OptionsSymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseNinjaPropFirmConfig parses a prop-firm config body.
func ParseNinjaPropFirmConfig(body []byte) NinjaFields {
	return ParseNinjaConfig(body)
}

// ParseNinjaLog parses a trace / log body.
func ParseNinjaLog(body []byte) NinjaFields {
	out := ParseNinjaConfig(body)
	out.FillCount = int64(len(orderFillRE.FindAllIndex(body, -1)))
	return out
}

// cuitFromBody returns the first cliente CUIT match.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectDataFeed sniffs body for connection-feed markers.
func detectDataFeed(body []byte) DataFeed {
	s := strings.ToLower(string(body))
	switch {
	case strings.Contains(s, "continuum"):
		return FeedContinuum
	case strings.Contains(s, "rithmic"):
		return FeedRithmic
	case strings.Contains(s, "cqg"):
		return FeedCQG
	case strings.Contains(s, "kinetick"):
		return FeedKinetick
	case strings.Contains(s, "iqfeed") || strings.Contains(s, "iq_feed"):
		return FeedIQFeed
	case strings.Contains(s, "tradovate"):
		return FeedTradovate
	case strings.Contains(s, "amp_futures") ||
		strings.Contains(s, "amp-futures") ||
		strings.Contains(s, "amp futures"):
		return FeedAMPFutures
	case strings.Contains(s, "interactive_brokers") ||
		strings.Contains(s, "interactive-brokers") ||
		strings.Contains(s, "interactive brokers") ||
		strings.Contains(s, "ibgateway"):
		return FeedInteractiveBrokers
	case strings.Contains(s, "[connection]"):
		return FeedCustom
	}
	return FeedUnknown
}

// detectPropFirm sniffs body for prop-firm vendor markers.
//
// Returns the dominant PropFirm AND the three boolean flags for
// the three biggest prop firms in the AR retail futures market
// (Apex / TopstepX / Earn2Trade) since collectors aggregate
// across multi-firm wallets.
func detectPropFirm(body []byte) (pf PropFirm, apex, top, e2t bool) {
	s := strings.ToLower(string(body))
	if strings.Contains(s, "apex_trader_funding") ||
		strings.Contains(s, "apex-trader-funding") ||
		strings.Contains(s, "apex trader funding") ||
		strings.Contains(s, "apex_prop") ||
		strings.Contains(s, "apex-prop") ||
		strings.Contains(s, "apextrader") {
		apex = true
	}
	if strings.Contains(s, "topstepx") ||
		strings.Contains(s, "topstep_x") ||
		strings.Contains(s, "topstep x") ||
		strings.Contains(s, "top step x") {
		top = true
	}
	if strings.Contains(s, "earn2trade") ||
		strings.Contains(s, "earn_2_trade") ||
		strings.Contains(s, "earn-2-trade") ||
		strings.Contains(s, "earn 2 trade") {
		e2t = true
	}
	switch {
	case apex:
		pf = PropFirmApex
	case top:
		pf = PropFirmTopstepX
	case e2t:
		pf = PropFirmEarn2Trade
	case strings.Contains(s, "myfundedfutures") ||
		strings.Contains(s, "my_funded_futures") ||
		strings.Contains(s, "my-funded-futures") ||
		strings.Contains(s, "my funded futures"):
		pf = PropFirmMyFundedFutures
	case strings.Contains(s, "bulenox"):
		pf = PropFirmBulenox
	case strings.Contains(s, "the_trading_pit") ||
		strings.Contains(s, "the-trading-pit") ||
		strings.Contains(s, "the trading pit"):
		pf = PropFirmTheTradingPit
	case strings.Contains(s, "ftmo"):
		pf = PropFirmFTMO
	case strings.Contains(s, "[prop_firm]"):
		pf = PropFirmCustom
	default:
		pf = PropFirmUnknown
	}
	return pf, apex, top, e2t
}

// classifySymbols returns counts of futures, micro futures,
// options, and total distinct symbols.
func classifySymbols(body []byte) (fut, micro, opts, total int64) {
	seen := map[string]struct{}{}
	futSet := map[string]struct{}{}
	microSet := map[string]struct{}{}
	optSet := map[string]struct{}{}
	for _, m := range optionsSymbolRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
		optSet[s] = struct{}{}
	}
	for _, m := range futureSymbolRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" || !IsFuturesStem(s) {
			continue
		}
		seen[s] = struct{}{}
		futSet[s] = struct{}{}
		if IsMicroFuturesStem(s) {
			microSet[s] = struct{}{}
		}
	}
	for _, m := range symbolEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
		if IsFuturesStem(s) {
			futSet[s] = struct{}{}
			if IsMicroFuturesStem(s) {
				microSet[s] = struct{}{}
			}
		}
	}
	return int64(len(futSet)), int64(len(microSet)),
		int64(len(optSet)), int64(len(seen))
}
