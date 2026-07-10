package winargsterling

import (
	"regexp"
	"strconv"
	"strings"
)

// SterlingFields captures scalar fields the audit pipeline
// needs from a Sterling Trader artifact.
type SterlingFields struct {
	APIKey               string
	Username             string
	SterlingTraderID     string
	SterlingBranchID     string
	ClienteCuitRaw       string
	PropFirm             PropFirm
	DistinctSymbols      int64
	USEquitySymbolsCount int64
	OptionsSymbolsCount  int64
	HotKeyCount          int64
	FillCount            int64
	ShortLocateCount     int64
	DailyLossLimitUSD    int64
	MaxPositionUSD       int64
	HasPassword          bool
}

// passwordRE matches a password row.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|sterling[_\-]?password|clearing[_\-]?password|trader[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|sterling[_\-]?password|sterling[_\-]?secret|clearing[_\-]?password|trader[_\-]?password|fix[_\-]?password)\s*=\s*["'][^"']{1,}["']`,
)

// apiKeyRE matches Sterling / clearing API key / token.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(?:sterling[_\-]?api[_\-]?key|sterling[_\-]?token|clearing[_\-]?token|fix[_\-]?token|api[_\-]?key|api[_\-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`,
)

// usernameRE matches Sterling / clearing login.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:sterling[_\-]?username|trader[_\-]?user|clearing[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// traderIDRE matches a Sterling trader ID (typically 3-6
// alphanumeric).
var traderIDRE = regexp.MustCompile(
	`(?i)"?(?:trader[_\-]?id|sterling[_\-]?trader[_\-]?id|trader[_\-]?code|registration[_\-]?id)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{3,16})`,
)

// branchIDRE matches a Sterling branch / office ID.
var branchIDRE = regexp.MustCompile(
	`(?i)"?(?:branch[_\-]?id|sterling[_\-]?branch[_\-]?id|office[_\-]?id|branch[_\-]?code|office[_\-]?code)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{2,16})`,
)

// hotkeyRE matches a HotKey binding row. Common Sterling
// HotKey forms: `Ctrl+1=BUY`, `Alt-3=SHORT`, `F2=COVER`,
// `Alt+F=FLATTEN`. Function keys (F1-F12) bind directly to
// actions without a modifier; modifier-prefixed bindings
// (Ctrl/Alt/Shift) carry a `+` or `-` separator.
var hotkeyRE = regexp.MustCompile(
	`(?i)(?:(?:Ctrl|Alt|Shift)[\-+]\w+|F\d{1,2})\s*=\s*(?:BUY|SELL|SHORT|COVER|CANCEL|FLATTEN|EXIT|MARKET|LIMIT)`,
)

// fixRouteRE matches FIX SenderCompID / TargetCompID — sign
// of a direct FIX route to an exchange.
var fixRouteRE = regexp.MustCompile(
	`(?i)(?:SenderCompID|TargetCompID|49=|56=)\s*[:=]\s*[A-Z0-9_\-\.]{2,32}`,
)

// orderFillRE matches a per-fill row in Sterling OrderLog.csv.
// Sterling logs `OrdID,Symbol,Side,Qty,Px,FillTime` typical
// header; data rows have numeric OrdID + symbol + qty.
var orderFillRE = regexp.MustCompile(
	`(?im)^(?:OrdID|orderid|order_id)?,?\d+,[A-Z][A-Z0-9.\-]{1,8},(?:BUY|SELL|SHORT|COVER|B|S|SS|BC),`,
)

// shortLocateRE matches a short-locate request row.
var shortLocateRE = regexp.MustCompile(
	`(?i)(?:short[_\- ]?locate|locate[_\- ]?req|locate[_\- ]?id|borrow[_\- ]?req|borrow[_\- ]?id)`,
)

// dailyLossRE matches a per-trader daily loss limit field.
var dailyLossRE = regexp.MustCompile(
	`(?i)(?:daily[_\- ]?loss[_\- ]?limit|max[_\- ]?daily[_\- ]?loss|loss[_\- ]?cap)\s*[:=]\s*"?\$?(\d{2,12}(?:[.,]\d+)?)`,
)

// maxPositionRE matches a per-trader max-position cap field.
var maxPositionRE = regexp.MustCompile(
	`(?i)(?:max[_\- ]?position|position[_\- ]?cap|max[_\- ]?qty)\s*[:=]\s*"?\$?(\d{2,12}(?:[.,]\d+)?)`,
)

// optionsSymbolRE matches an option-chain symbol (Sterling's
// options use `<root>_<expiry><strike><CP>` form, e.g.
// `AAPL_240419P00170000`). Loose heuristic: any sym with
// `_` and length > 12 + ends in `[CP]` digits.
var optionsSymbolRE = regexp.MustCompile(
	`(?i)\b([A-Z]{1,5}_\d{6}[CP]\d{8})\b`,
)

// symbolEntryRE matches a per-symbol entry in layouts /
// orderlog / chart def. Also matches CSV-style data rows
// `<digit-OrdID>,<SYMBOL>,(BUY|SELL|SHORT|COVER),` because
// Sterling OrderLog.csv lacks per-row keyword markers.
var symbolEntryRE = regexp.MustCompile(
	`(?im)(?:"?(?:symbol(?:_\w+)?|sym|ticker|instrument)"?\s*[:=]\s*"?|<symbol[^>]*>|^\d+,)([A-Z][A-Z0-9_\-\./]{0,7})`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseSterlingConfig parses a generic Sterling cfg body.
func ParseSterlingConfig(body []byte) SterlingFields {
	var out SterlingFields
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
		out.SterlingTraderID = string(m[1])
	}
	if m := branchIDRE.FindSubmatch(body); len(m) > 1 {
		out.SterlingBranchID = string(m[1])
	}
	out.PropFirm = detectPropFirm(body)
	out.USEquitySymbolsCount, out.OptionsSymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseSterlingCredentials parses a credentials body.
func ParseSterlingCredentials(body []byte) SterlingFields {
	return ParseSterlingConfig(body)
}

// ParseSterlingLayout parses a .stx layout body.
func ParseSterlingLayout(body []byte) SterlingFields {
	return ParseSterlingConfig(body)
}

// ParseSterlingHotKeys parses a HotKeys.cfg body.
func ParseSterlingHotKeys(body []byte) SterlingFields {
	var out SterlingFields
	if len(body) == 0 {
		return out
	}
	out.HotKeyCount = int64(len(hotkeyRE.FindAllIndex(body, -1)))
	return out
}

// ParseSterlingChartDef parses a ChartDef.cfg body.
func ParseSterlingChartDef(body []byte) SterlingFields {
	return ParseSterlingConfig(body)
}

// ParseSterlingDMARoute parses a DMA route ticket body.
func ParseSterlingDMARoute(body []byte) SterlingFields {
	out := ParseSterlingConfig(body)
	return out
}

// ParseSterlingBranchConfig parses a Branch.cfg body.
func ParseSterlingBranchConfig(body []byte) SterlingFields {
	out := ParseSterlingConfig(body)
	if m := branchIDRE.FindSubmatch(body); len(m) > 1 {
		out.SterlingBranchID = string(m[1])
	}
	return out
}

// ParseSterlingTraderRiskLimits parses a TraderRiskLimits.cfg
// body. Extracts the daily-loss / max-position cap values.
func ParseSterlingTraderRiskLimits(body []byte) SterlingFields {
	out := ParseSterlingConfig(body)
	if m := dailyLossRE.FindSubmatch(body); len(m) > 1 {
		raw := strings.ReplaceAll(strings.ReplaceAll(
			string(m[1]), ",", "",
		), ".00", "")
		v, err := strconv.ParseInt(raw, 10, 64)
		if err == nil {
			out.DailyLossLimitUSD = v
		}
	}
	if m := maxPositionRE.FindSubmatch(body); len(m) > 1 {
		raw := strings.ReplaceAll(strings.ReplaceAll(
			string(m[1]), ",", "",
		), ".00", "")
		v, err := strconv.ParseInt(raw, 10, 64)
		if err == nil {
			out.MaxPositionUSD = v
		}
	}
	return out
}

// ParseSterlingClearingConfig parses a clearing config body.
func ParseSterlingClearingConfig(body []byte) SterlingFields {
	return ParseSterlingConfig(body)
}

// ParseSterlingOrderLog parses a daily OrderLog.csv body.
func ParseSterlingOrderLog(body []byte) SterlingFields {
	var out SterlingFields
	if len(body) == 0 {
		return out
	}
	out.FillCount = int64(len(orderFillRE.FindAllIndex(body, -1)))
	if m := traderIDRE.FindSubmatch(body); len(m) > 1 {
		out.SterlingTraderID = string(m[1])
	}
	out.USEquitySymbolsCount, out.OptionsSymbolsCount, out.DistinctSymbols = classifySymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseSterlingShortLocateLog parses a short-locate log body.
func ParseSterlingShortLocateLog(body []byte) SterlingFields {
	var out SterlingFields
	if len(body) == 0 {
		return out
	}
	out.ShortLocateCount = int64(len(shortLocateRE.FindAllIndex(body, -1)))
	if m := traderIDRE.FindSubmatch(body); len(m) > 1 {
		out.SterlingTraderID = string(m[1])
	}
	out.USEquitySymbolsCount, out.OptionsSymbolsCount, out.DistinctSymbols = classifySymbols(body)
	return out
}

// ParseSterlingFIXRoute parses a FIX direct-route cfg body.
func ParseSterlingFIXRoute(body []byte) SterlingFields {
	out := ParseSterlingConfig(body)
	if fixRouteRE.Match(body) {
		out.HasPassword = out.HasPassword || passwordInlineRE.Match(body)
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

// detectPropFirm sniffs body for prop-firm vendor markers.
func detectPropFirm(body []byte) PropFirm {
	s := strings.ToLower(string(body))
	switch {
	case strings.Contains(s, "smb_capital") || strings.Contains(s, "smb-capital") ||
		strings.Contains(s, "smb capital"):
		return PropFirmSMBCapital
	case strings.Contains(s, "t3_live") || strings.Contains(s, "t3-live") ||
		strings.Contains(s, "t3 live"):
		return PropFirmT3Live
	case strings.Contains(s, "centerpoint"):
		return PropFirmCenterPoint
	case strings.Contains(s, "bright_trading") || strings.Contains(s, "bright-trading") ||
		strings.Contains(s, "bright trading"):
		return PropFirmBrightTrading
	case strings.Contains(s, "hold_brothers") || strings.Contains(s, "hold-brothers") ||
		strings.Contains(s, "hold brothers"):
		return PropFirmHoldBrothers
	case strings.Contains(s, "great_point") || strings.Contains(s, "great-point") ||
		strings.Contains(s, "great point"):
		return PropFirmGreatPoint
	case strings.Contains(s, "kershner"):
		return PropFirmKershner
	case strings.Contains(s, "sterling_equities") ||
		strings.Contains(s, "sterling-equities") ||
		strings.Contains(s, "sterling equities"):
		return PropFirmSterlingEquities
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
