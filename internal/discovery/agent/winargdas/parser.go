package winargdas

import (
	"regexp"
	"strings"
)

// DASFields captures scalar fields the audit pipeline needs from
// a DAS Trader Pro artifact.
type DASFields struct {
	APIKey               string
	Username             string
	DASTraderID          string
	ClienteCuitRaw       string
	ClearingFirm         ClearingFirm
	PropFirm             PropFirm
	DistinctSymbols      int64
	USEquitySymbolsCount int64
	OptionsSymbolsCount  int64
	HotKeyCount          int64
	ChordHotKeyCount     int64
	ScriptSendOrderCount int64
	FillCount            int64
	ShortLocateCount     int64
	HasPassword          bool
	HasDASInetRoute      bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|das[_\-]?password|das[_\-]?passwd|trader[_\-]?password|clearing[_\-]?password|stratos[_\-]?password|centerpoint[_\-]?password)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|das[_\-]?password|das[_\-]?secret|trader[_\-]?password|clearing[_\-]?password|fix[_\-]?password|mobile[_\-]?secret)\s*=\s*["'][^"']{1,}["']`)

// apiKeyRE matches DAS / DAS Mobile / clearing API key / token.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(?:das[_\-]?api[_\-]?key|das[_\-]?token|das[_\-]?mobile[_\-]?token|clearing[_\-]?token|fix[_\-]?token|api[_\-]?key|api[_\-]?token|access[_\-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`)

// usernameRE matches DAS / clearing login.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:das[_\-]?username|das[_\-]?user|trader[_\-]?user|clearing[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`)

// traderIDRE matches a DAS trader ID. DAS uses uppercase
// alphanumeric short tickers (3-8 chars) per trader / branch.
var traderIDRE = regexp.MustCompile(
	`(?i)"?(?:trader[_\-]?id|das[_\-]?trader[_\-]?id|trader[_\-]?code|account[_\-]?id|user[_\-]?id|registration[_\-]?id)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{3,16})`)

// dasScriptSendOrderRE matches a DASScript order-submission
// call. DASScript exposes `SEND_ORDER`, `PLACE_ORDER`, and
// `SUBMIT_ORDER` as keywords for placing orders programmatically.
var dasScriptSendOrderRE = regexp.MustCompile(
	`(?i)\b(?:SEND_ORDER|SUBMIT_ORDER|PLACE_ORDER|ROUTE_ORDER|EXEC_ORDER|SENDORDER|SENDMARKETORDER|SENDLIMITORDER|SENDSTOPORDER)\s*\(`)

// hotkeyRE matches a HotKey binding row. DAS HotKey forms span
// single-key (`F2=BUY`), single-mod (`Ctrl-1=SELL`), and chord
// (`Ctrl-Alt-1=BUY` two modifiers). Action keywords cover the
// DAS hotkey action lexicon (BUY/SELL/SHORT/COVER/CXL etc.).
var hotkeyRE = regexp.MustCompile(
	`(?i)(?:(?:Ctrl|Alt|Shift)[\-+](?:(?:Ctrl|Alt|Shift)[\-+])?\w+|F\d{1,2})\s*=\s*(?:BUY|SELL|SHORT|COVER|CANCEL|CXL|FLATTEN|EXIT|MARKET|LIMIT|STOP|ROUTE)`)

// chordHotkeyRE matches a chord (two-modifier) HotKey row.
// Sign of an advanced scalper's binding set.
var chordHotkeyRE = regexp.MustCompile(
	`(?i)(?:Ctrl|Alt|Shift)[\-+](?:Ctrl|Alt|Shift)[\-+]\w+\s*=\s*(?:BUY|SELL|SHORT|COVER|CANCEL|CXL|FLATTEN|EXIT|MARKET|LIMIT|STOP|ROUTE)`)

// dasInetRouteRE matches a DAS Inet routing keyword. DAS Inet
// is DAS's direct-market-access route layer; presence of the
// keyword signals a DMA-route config.
var dasInetRouteRE = regexp.MustCompile(
	`(?i)\b(?:DASINET|DAS_INET|DAS-INET|INET[_\-]?ROUTE|ROUTE[_\-]?INET|DIRECT[_\-]?ROUTE|ARCA|EDGX|BATS|NSDQ|NYSE|IEX)\b`)

// orderFillRE matches a per-fill row in DAS Trader OrderLog.csv.
// DAS OrderLog header: `Time,OrderID,Symbol,Side,Qty,Price,...`
// with numeric OrderID and uppercase ticker. Data rows lack
// keyword markers so we anchor on the
// `[<Time>,]<OrderID>,<TICKER>,<side>,` pattern. Side codes:
// B=Buy, S=Sell, SS=Short, BC=BuyCover, plus long-form
// BUY/SELL/SHORT/COVER.
var orderFillRE = regexp.MustCompile(
	`(?im)^(?:[\d:.]+,)?\d+,[A-Z][A-Z0-9.\-]{0,8},(?:BUY|SELL|SHORT|COVER|B|S|SS|BC),`)

// shortLocateRE matches a short-locate request row.
var shortLocateRE = regexp.MustCompile(
	`(?i)(?:short[_\- ]?locate|locate[_\- ]?req|locate[_\- ]?id|borrow[_\- ]?req|borrow[_\- ]?id|hard[_\- ]?to[_\- ]?borrow|htb[_\- ]?req)`)

// optionsSymbolRE matches an OCC-style option chain symbol.
// DAS uses `<root>_<expiry><strike><CP>` form.
var optionsSymbolRE = regexp.MustCompile(
	`(?i)\b([A-Z]{1,5}_\d{6}[CP]\d{8})\b`)

// symbolEntryRE matches a per-symbol entry in layouts / orderlog
// / chart def. Includes CSV-style rows because DAS OrderLog.csv
// lacks per-row keyword markers; matches `[<Time>,]<OrderID>,<TICKER>`.
var symbolEntryRE = regexp.MustCompile(
	`(?im)(?:"?(?:symbol(?:_\w+)?|sym|ticker|instrument)"?\s*[:=]\s*"?|<symbol[^>]*>|^(?:[\d:.]+,)?\d+,)([A-Z][A-Z0-9_\-\./]{0,7})`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N` in
// INI, JSON, or XML form (`[:=>]` separator class).
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseDASConfig parses a generic DAS cfg body.
func ParseDASConfig(body []byte) DASFields {
	var out DASFields
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
	if m := traderIDRE.FindSubmatch(body); len(m) > 1 {
		out.DASTraderID = string(m[1])
	}
	out.ClearingFirm = detectClearingFirm(body)
	out.PropFirm = detectPropFirm(body)
	out.USEquitySymbolsCount, out.OptionsSymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if dasInetRouteRE.Match(body) {
		out.HasDASInetRoute = true
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseDASCredentials parses a DAS credentials body.
func ParseDASCredentials(body []byte) DASFields {
	return ParseDASConfig(body)
}

// ParseDASLayout parses a .das layout body.
func ParseDASLayout(body []byte) DASFields {
	return ParseDASConfig(body)
}

// ParseDASHotKeys parses a HotKeys.cfg body.
func ParseDASHotKeys(body []byte) DASFields {
	var out DASFields
	if len(body) == 0 {
		return out
	}
	out.HotKeyCount = int64(len(hotkeyRE.FindAllIndex(body, -1)))
	out.ChordHotKeyCount = int64(len(chordHotkeyRE.FindAllIndex(body, -1)))
	return out
}

// ParseDASScript parses a .script / .dasscript body.
func ParseDASScript(body []byte) DASFields {
	out := ParseDASConfig(body)
	out.ScriptSendOrderCount = int64(len(dasScriptSendOrderRE.FindAllIndex(body, -1)))
	return out
}

// ParseDASRoute parses a DAS Inet route ticket body.
func ParseDASRoute(body []byte) DASFields {
	out := ParseDASConfig(body)
	out.HasDASInetRoute = true
	return out
}

// ParseDASClearingConfig parses a clearing config body.
func ParseDASClearingConfig(body []byte) DASFields {
	return ParseDASConfig(body)
}

// ParseDASOrderLog parses a daily OrderLog.csv body.
func ParseDASOrderLog(body []byte) DASFields {
	var out DASFields
	if len(body) == 0 {
		return out
	}
	out.FillCount = int64(len(orderFillRE.FindAllIndex(body, -1)))
	if m := traderIDRE.FindSubmatch(body); len(m) > 1 {
		out.DASTraderID = string(m[1])
	}
	out.USEquitySymbolsCount, out.OptionsSymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseDASShortLocateLog parses a short-locate log body.
func ParseDASShortLocateLog(body []byte) DASFields {
	var out DASFields
	if len(body) == 0 {
		return out
	}
	out.ShortLocateCount = int64(len(shortLocateRE.FindAllIndex(body, -1)))
	if m := traderIDRE.FindSubmatch(body); len(m) > 1 {
		out.DASTraderID = string(m[1])
	}
	out.USEquitySymbolsCount, out.OptionsSymbolsCount, out.DistinctSymbols = classifySymbols(body)
	return out
}

// ParseDASAPIToken parses a DAS API or DAS Mobile token body.
func ParseDASAPIToken(body []byte) DASFields {
	return ParseDASConfig(body)
}

// cuitFromBody returns the first cliente CUIT match.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectClearingFirm sniffs body for clearing-firm vendor
// markers. DAS Inc. partners with several US clearing firms;
// `_`, `-`, and space-separated brand forms are all detected.
func detectClearingFirm(body []byte) ClearingFirm {
	s := strings.ToLower(string(body))
	switch {
	case strings.Contains(s, "centerpoint_securities") ||
		strings.Contains(s, "centerpoint-securities") ||
		strings.Contains(s, "centerpoint securities"):
		return ClearingCenterpointSecurities
	case strings.Contains(s, "centerpoint"):
		return ClearingCenterpoint
	case strings.Contains(s, "stratos"):
		return ClearingStratos
	case strings.Contains(s, "alliance_trader") ||
		strings.Contains(s, "alliance-trader") ||
		strings.Contains(s, "alliance trader"):
		return ClearingAllianceTrader
	case strings.Contains(s, "velocity"):
		return ClearingVelocity
	case strings.Contains(s, "ironbeam"):
		return ClearingIronbeam
	case strings.Contains(s, "suretrader") ||
		strings.Contains(s, "sure-trader") ||
		strings.Contains(s, "sure trader"):
		return ClearingSureTrader
	case strings.Contains(s, "das_clearing") ||
		strings.Contains(s, "das-clearing") ||
		strings.Contains(s, "das clearing"):
		return ClearingDAS
	case strings.Contains(s, "[clearing]"):
		return ClearingCustom
	}
	return ClearingUnknown
}

// detectPropFirm sniffs body for prop-firm community markers.
// AR DAS users are typically Bear Bull Traders or Investors
// Underground (IU) members — Andrew Aziz / Nathan Michaud audiences.
func detectPropFirm(body []byte) PropFirm {
	s := strings.ToLower(string(body))
	switch {
	case strings.Contains(s, "bear_bull_traders") ||
		strings.Contains(s, "bear-bull-traders") ||
		strings.Contains(s, "bear bull traders") ||
		strings.Contains(s, "bbt"):
		return PropFirmBearBullTraders
	case strings.Contains(s, "investors_underground") ||
		strings.Contains(s, "investors-underground") ||
		strings.Contains(s, "investors underground"):
		return PropFirmInvestorsUnderground
	case strings.Contains(s, "warrior_trading") ||
		strings.Contains(s, "warrior-trading") ||
		strings.Contains(s, "warrior trading"):
		return PropFirmWarriorTrading
	case strings.Contains(s, "simplertrading") ||
		strings.Contains(s, "simpler_trading") ||
		strings.Contains(s, "simpler-trading") ||
		strings.Contains(s, "simpler trading"):
		return PropFirmSimplerTrading
	case strings.Contains(s, "tradenetstrategies") ||
		strings.Contains(s, "tradenet_strategies") ||
		strings.Contains(s, "tradenet-strategies") ||
		strings.Contains(s, "tradenet strategies"):
		return PropFirmTradeNetStrategies
	case strings.Contains(s, "maverick_trading") ||
		strings.Contains(s, "maverick-trading") ||
		strings.Contains(s, "maverick trading"):
		return PropFirmMaverickTrading
	case strings.Contains(s, "[prop_firm]"):
		return PropFirmCustom
	}
	return PropFirmUnknown
}

// classifySymbols returns counts of US equity, options, and
// total distinct symbols.
func classifySymbols(body []byte) (us, opts, total int64) {
	seen := map[string]struct{}{}
	usSet := map[string]struct{}{}
	optSet := map[string]struct{}{}
	for _, m := range optionsSymbolRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
		optSet[s] = struct{}{}
	}
	for _, m := range symbolEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
		if IsUSEquityStem(s) {
			usSet[s] = struct{}{}
		}
	}
	return int64(len(usSet)), int64(len(optSet)), int64(len(seen))
}
