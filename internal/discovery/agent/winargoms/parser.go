package winargoms

import (
	"regexp"
	"strconv"
	"strings"
)

// OMSFields captures scalar fields the audit pipeline needs.
type OMSFields struct {
	OMSPlatform             OMSPlatform
	OrderSide               OrderSide
	OrderType               OrderType
	ExecutionVenue          ExecutionVenue
	SociedadGerenteCuitRaw  string
	FIXSenderCompID         string
	FIXTargetCompID         string
	OrderCount              int64
	FillCount               int64
	BrokerCount             int64
	RestrictedTickerCount   int64
	LargestOrderNotionalARS int64
	HasPassword             bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|oms[_\-]?password|fix[_\-]?password|api[_\-]?token|api[_\-]?key|api[_\-]?secret)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|oms[_\-]?password|fix[_\-]?password|bearer[_\-]?token)\b"?\s*[:=]\s*["'][^"']{1,}["']`,
)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|oms[_\-]?password|fix[_\-]?password)\s*>([^<]{1,})<\s*/`,
)

// omsPlatformRE matches an OMS platform marker in body.
var omsPlatformRE = regexp.MustCompile(
	`(?i)\b(charles river|charles-river|crims|fidessa|bloomberg aim|bloomberg-aim|bloomberg emsx|bloomberg-emsx|flextrade|eze[_\- ]?(?:soft|oms)?|itiviti|tradingscreen|imatch|portware)\b`,
)

// orderSideRE matches an order-side field.
var orderSideRE = regexp.MustCompile(
	`(?i)"?(?:order[_\- ]?side|side)"?\s*[:=>]\s*"?(buy|sell|short[_\- ]?sell|short|buy[_\- ]?cover|cover)"?`,
)

// orderTypeRE matches an order-type field.
var orderTypeRE = regexp.MustCompile(
	`(?i)"?(?:order[_\- ]?type|ord_type)"?\s*[:=>]\s*"?(market|mkt|limit|lmt|stop[_\- ]?limit|stop|vwap|twap|pegged|iceberg|dark[_\- ]?pool)"?`,
)

// executionVenueRE matches an execution-venue field.
var executionVenueRE = regexp.MustCompile(
	`(?i)"?(?:execution[_\- ]?venue|venue|exchange|mercado|ex[_\- ]?destination)"?\s*[:=>]\s*"?(byma|bcba|mae|matba[_\- ]?rofex|matba|rofex|mav|nyse|nasdaq|arca|bats|otc|dark[_\- ]?pool)"?`,
)

// sociedadGerenteCuitKeyRE matches sociedad-gerente CUIT field.
var sociedadGerenteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:sociedad[_\- ]?gerente[_\- ]?cuit|sg[_\- ]?cuit|gerente[_\- ]?cuit|alyc[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// fixSenderCompIDRE matches FIX SenderCompID field.
var fixSenderCompIDRE = regexp.MustCompile(
	`(?im)(?:^|[^a-z])(?:SenderCompID|sender[_\- ]?comp[_\- ]?id)\s*[:=>]\s*"?([A-Z0-9._\-]{1,64})"?`,
)

// fixTargetCompIDRE matches FIX TargetCompID field.
var fixTargetCompIDRE = regexp.MustCompile(
	`(?im)(?:^|[^a-z])(?:TargetCompID|target[_\- ]?comp[_\- ]?id)\s*[:=>]\s*"?([A-Z0-9._\-]{1,64})"?`,
)

// orderCountRE matches a total-order count.
var orderCountRE = regexp.MustCompile(
	`(?i)"?(?:order[_\- ]?count|total[_\- ]?orders|orders[_\- ]?total)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// fillCountRE matches a total-fill count.
var fillCountRE = regexp.MustCompile(
	`(?i)"?(?:fill[_\- ]?count|total[_\- ]?fills|fills[_\- ]?total|executions[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// brokerCountRE matches a broker-list count.
var brokerCountRE = regexp.MustCompile(
	`(?i)"?(?:broker[_\- ]?count|approved[_\- ]?brokers[_\- ]?count|brokers[_\- ]?total)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// restrictedCountRE matches a restricted-ticker count.
var restrictedCountRE = regexp.MustCompile(
	`(?i)"?(?:restricted[_\- ]?ticker[_\- ]?count|restricted[_\- ]?count|restricted[_\- ]?total)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// largestNotionalARSRE matches the largest-order notional in ARS.
var largestNotionalARSRE = regexp.MustCompile(
	`(?i)"?(?:largest[_\- ]?order[_\- ]?notional[_\- ]?ars|largest[_\- ]?notional[_\- ]?ars|max[_\- ]?notional[_\- ]?ars|biggest[_\- ]?order[_\- ]?ars)"?\s*[:=>]\s*"?(\d{1,15})`,
)

// ParseOMS parses any OMS artifact body (shared parser).
func ParseOMS(body []byte) OMSFields {
	var out OMSFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := omsPlatformRE.FindSubmatch(body); len(m) > 1 {
		out.OMSPlatform = detectOMSPlatform(string(m[1]))
	}
	if m := orderSideRE.FindSubmatch(body); len(m) > 1 {
		out.OrderSide = detectOrderSide(string(m[1]))
	}
	if m := orderTypeRE.FindSubmatch(body); len(m) > 1 {
		out.OrderType = detectOrderType(string(m[1]))
	}
	if m := executionVenueRE.FindSubmatch(body); len(m) > 1 {
		out.ExecutionVenue = detectExecutionVenue(string(m[1]))
	}
	if c := sociedadGerenteCuitFromBody(body); c != "" {
		out.SociedadGerenteCuitRaw = c
	}
	if m := fixSenderCompIDRE.FindSubmatch(body); len(m) > 1 {
		out.FIXSenderCompID = string(m[1])
	}
	if m := fixTargetCompIDRE.FindSubmatch(body); len(m) > 1 {
		out.FIXTargetCompID = string(m[1])
	}
	if m := orderCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.OrderCount = v
		}
	}
	if m := fillCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.FillCount = v
		}
	}
	if m := brokerCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.BrokerCount = v
		}
	}
	if m := restrictedCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.RestrictedTickerCount = v
		}
	}
	if m := largestNotionalARSRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.LargestOrderNotionalARS = v
		}
	}
	return out
}

// sociedadGerenteCuitFromBody returns the first sociedad-gerente
// CUIT match.
func sociedadGerenteCuitFromBody(body []byte) string {
	if m := sociedadGerenteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectOMSPlatform normalizes a platform string.
func detectOMSPlatform(s string) OMSPlatform {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "charles") || strings.Contains(t, "crims"):
		return PlatformCharlesRiver
	case strings.Contains(t, "fidessa"):
		return PlatformFidessa
	case strings.Contains(t, "emsx"):
		return PlatformBloombergEMSX
	case strings.Contains(t, "aim"):
		return PlatformBloombergAIM
	case strings.Contains(t, "flextrade"):
		return PlatformFlexTrade
	case strings.Contains(t, "eze"):
		return PlatformEze
	case strings.Contains(t, "itiviti"):
		return PlatformItiviti
	case strings.Contains(t, "tradingscreen"):
		return PlatformTradingScreen
	case strings.Contains(t, "imatch"):
		return PlatformIMatch
	case strings.Contains(t, "portware"):
		return PlatformPortware
	}
	return PlatformUnknown
}

// detectOrderSide normalizes an order-side string.
func detectOrderSide(s string) OrderSide {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "short"):
		return SideShortSell
	case strings.Contains(t, "cover"):
		return SideBuyCover
	case strings.Contains(t, "buy"):
		return SideBuy
	case strings.Contains(t, "sell"):
		return SideSell
	}
	return SideUnknown
}

// detectOrderType normalizes an order-type string.
func detectOrderType(s string) OrderType {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "stop") && strings.Contains(t, "limit"):
		return TypeStopLimit
	case strings.Contains(t, "stop"):
		return TypeStop
	case strings.Contains(t, "vwap"):
		return TypeVWAP
	case strings.Contains(t, "twap"):
		return TypeTWAP
	case strings.Contains(t, "pegged"):
		return TypePegged
	case strings.Contains(t, "iceberg"):
		return TypeIceberg
	case strings.Contains(t, "dark"):
		return TypeDarkPool
	case strings.Contains(t, "market") || t == "mkt":
		return TypeMarket
	case strings.Contains(t, "limit") || t == "lmt":
		return TypeLimit
	}
	return TypeUnknown
}

// detectExecutionVenue normalizes an execution-venue string.
func detectExecutionVenue(s string) ExecutionVenue {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "byma") || strings.Contains(t, "bcba"):
		return VenueBYMA
	case strings.Contains(t, "matba") || strings.Contains(t, "rofex"):
		return VenueMATbaRofex
	case t == "mae":
		return VenueMAE
	case t == "mav":
		return VenueMAV
	case strings.Contains(t, "nyse"):
		return VenueNYSE
	case strings.Contains(t, "nasdaq"):
		return VenueNASDAQ
	case strings.Contains(t, "arca"):
		return VenueARCA
	case strings.Contains(t, "bats"):
		return VenueBATS
	case strings.Contains(t, "dark"):
		return VenueDarkPool
	case t == "otc":
		return VenueOTC
	}
	return VenueUnknown
}
