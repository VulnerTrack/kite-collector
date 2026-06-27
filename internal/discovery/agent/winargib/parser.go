package winargib

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// IBFields captures scalar fields the audit pipeline needs
// from an IB artifact.
type IBFields struct {
	IBAccountSuffix4     string
	APISocketAddress     string
	Username             string
	ClienteCuitRaw       string
	DistinctSymbols      int64
	PortfolioAUMUSDCents int64
	AboveCapCount        int64
	APISocketPort        int
	HasPassword          bool
	HasAPIExposed        bool
	HasLive              bool
	HasUSEquity          bool
	HasGlobalEquity      bool
	HasFutures           bool
	HasForex             bool
	HasCrypto            bool
	HasFlexExport        bool
}

// passwordRE matches a password row (line-anchored INI/JSON).
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|TwsPassword)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret)\s*=\s*["'][^"']{1,}["']`)

// apiSocketRE matches the TWS API socket-port config row in
// jts.ini / gateway.cfg.
var apiSocketRE = regexp.MustCompile(
	`(?im)^\s*(?:LocalServerPort|api[_\-]?socket[_\-]?port|socketPort|tws[_\-]?api[_\-]?port|gateway[_\-]?port)\s*[:=]\s*(\d{4,5})`)

// ibConnectRE matches a Python `ib.connect(host, port, ...)` /
// `IB().connect(host, port, ...)` call (ibapi / ib_insync).
var ibConnectRE = regexp.MustCompile(
	`(?i)\bconnect\s*\(\s*["'][^"']{1,64}["']\s*,\s*(\d{4,5})`)

// apiSocketAddrRE matches the TWS API bind-address row.
var apiSocketAddrRE = regexp.MustCompile(
	`(?im)^\s*(?:LocalServerAddress|api[_\-]?socket[_\-]?addr|socketAddr|bind[_\-]?address)\s*[:=]\s*([0-9a-fA-F\.:]+)`)

// liveModeRE detects live-trading mode markers.
var liveModeRE = regexp.MustCompile(
	`(?i)(?:live[_\-]?mode\s*[:=]\s*(?:true|1|yes)|live[_\-]?trading\s*[:=]\s*(?:true|1|yes)|TradingMode\s*[:=]\s*live|ibgateway[_\-]?live)`)

// usernameRE matches IB username (often `TwsUsername` or
// `LoginId` in jts.ini).
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:TwsUsername|LoginId|UserId|username|user|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`)

// ibAccountKeyRE matches a `IBAccount: U1234567` key form.
var ibAccountKeyRE = regexp.MustCompile(
	`(?i)"?(?:ib[_\-]?account|account[_\-]?id|accountId|account[_\-]?nr|ibkr[_\-]?account)"?\s*[:=]\s*"?(U\d{7})`)

// usdAmountRE captures a USD amount row.
var usdAmountRE = regexp.MustCompile(
	`(?i)(?:notional[_\- ]?usd|usd[_\- ]?amount|importe[_\- ]?usd|monto[_\- ]?usd|valor[_\- ]?usd|market[_\- ]?value|portfolio[_\- ]?value|aum[_\- ]?usd|cash[_\- ]?balance)"?\s*[:=]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// flexExportRE detects Flex Query XML / CSV header markers.
var flexExportRE = regexp.MustCompile(
	`(?i)(?:FlexQueryResponse|FlexStatement|<FlexStatements|<Trade |<CashTransactions|FlexQuery|<AccountInformation)`)

// importIbapiRE detects ibapi / ib-insync Python import.
var importIbapiRE = regexp.MustCompile(
	`(?im)^\s*(?:from\s+ibapi|import\s+ibapi|from\s+ib_insync|import\s+ib_insync)`)

// symbolEntryRE matches a symbol entry in JSON/INI/XML form.
var symbolEntryRE = regexp.MustCompile(
	`(?i)"?(?:symbol|ticker|instrument|contract|conid)"?\s*[:=]\s*"?([A-Za-z0-9_\-\./\.]{2,32})`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseIBConfig parses a jts.ini / IB Gateway config body.
func ParseIBConfig(body []byte) IBFields {
	var out IBFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := apiSocketRE.FindSubmatch(body); len(m) > 1 {
		if p, err := strconv.Atoi(string(m[1])); err == nil {
			out.APISocketPort = p
			if IsLivePort(p) {
				out.HasLive = true
			}
		}
	}
	if m := apiSocketAddrRE.FindSubmatch(body); len(m) > 1 {
		addr := strings.TrimSpace(string(m[1]))
		out.APISocketAddress = addr
		// 0.0.0.0 / :: / empty bind = remote-exposure
		// surface (vs. localhost-only 127.0.0.1 / ::1).
		if addr == "0.0.0.0" || addr == "::" || addr == "*" {
			out.HasAPIExposed = true
		}
	}
	if liveModeRE.Match(body) {
		out.HasLive = true
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	out.IBAccountSuffix4 = ibAccountSuffixFromBody(body)
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseIBCredentials parses an IB credentials file.
func ParseIBCredentials(body []byte) IBFields {
	return ParseIBConfig(body)
}

// ParseIBGatewayConfig parses an IB Gateway config.
func ParseIBGatewayConfig(body []byte) IBFields {
	return ParseIBConfig(body)
}

// ParseIBTWSSettings parses TWS per-user settings.
func ParseIBTWSSettings(body []byte) IBFields {
	return ParseIBConfig(body)
}

// ParseIBPositions parses an IB positions cache.
func ParseIBPositions(body []byte) IBFields {
	var out IBFields
	if len(body) == 0 {
		return out
	}
	out.DistinctSymbols = countDistinctSymbols(body)
	out.PortfolioAUMUSDCents = sumUSDAmounts(body)
	out.AboveCapCount = countAboveCapTrades(body)
	out.HasUSEquity = HasUSEquityMarker(body)
	out.HasGlobalEquity = HasGlobalEquityMarker(body)
	out.HasFutures = HasCMEFuturesMarker(body)
	out.HasForex = HasForexMarker(body)
	out.HasCrypto = HasCryptoMarker(body)
	out.IBAccountSuffix4 = ibAccountSuffixFromBody(body)
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseIBOrders parses an IB orders cache.
func ParseIBOrders(body []byte) IBFields {
	out := ParseIBPositions(body)
	return out
}

// ParseIBStrategyPy parses an ibapi / ib_insync Python script.
func ParseIBStrategyPy(body []byte) IBFields {
	var out IBFields
	if len(body) == 0 {
		return out
	}
	if passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if importIbapiRE.Match(body) {
		// presence-only signal
		_ = importIbapiRE
	}
	if m := apiSocketRE.FindSubmatch(body); len(m) > 1 {
		if p, err := strconv.Atoi(string(m[1])); err == nil {
			out.APISocketPort = p
			if IsLivePort(p) {
				out.HasLive = true
			}
		}
	}
	// Python scripts call ib.connect(host, port, ...) — extract
	// the port from that call when the line-anchored config
	// regex didn't match.
	if out.APISocketPort == 0 {
		if m := ibConnectRE.FindSubmatch(body); len(m) > 1 {
			if p, err := strconv.Atoi(string(m[1])); err == nil {
				out.APISocketPort = p
				if IsLivePort(p) {
					out.HasLive = true
				}
			}
		}
	}
	out.HasUSEquity = HasUSEquityMarker(body)
	out.HasGlobalEquity = HasGlobalEquityMarker(body)
	out.HasFutures = HasCMEFuturesMarker(body)
	out.HasForex = HasForexMarker(body)
	out.HasCrypto = HasCryptoMarker(body)
	out.DistinctSymbols = countDistinctSymbols(body)
	out.IBAccountSuffix4 = ibAccountSuffixFromBody(body)
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseIBTradeLog parses an IB trade-execution log.
func ParseIBTradeLog(body []byte) IBFields {
	out := ParseIBPositions(body)
	return out
}

// ParseIBFlexQuery parses an IB Flex Query XML / CSV export.
func ParseIBFlexQuery(body []byte) IBFields {
	var out IBFields
	if len(body) == 0 {
		return out
	}
	if flexExportRE.Match(body) {
		out.HasFlexExport = true
	}
	out.IBAccountSuffix4 = ibAccountSuffixFromBody(body)
	out.HasUSEquity = HasUSEquityMarker(body)
	out.HasGlobalEquity = HasGlobalEquityMarker(body)
	out.HasFutures = HasCMEFuturesMarker(body)
	out.HasForex = HasForexMarker(body)
	out.HasCrypto = HasCryptoMarker(body)
	out.PortfolioAUMUSDCents = sumUSDAmounts(body)
	out.AboveCapCount = countAboveCapTrades(body)
	out.DistinctSymbols = countDistinctSymbols(body)
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseIBTaxStatement parses an annual tax statement.
func ParseIBTaxStatement(body []byte) IBFields {
	var out IBFields
	if len(body) == 0 {
		return out
	}
	out.PortfolioAUMUSDCents = sumUSDAmounts(body)
	out.IBAccountSuffix4 = ibAccountSuffixFromBody(body)
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// HasIbapiImport reports whether body imports ibapi.
func HasIbapiImport(body []byte) bool {
	return importIbapiRE.Match(body)
}

// ibAccountSuffixFromBody tries the IB key form first, then
// falls back to a body-wide `U\d{7}` scan.
func ibAccountSuffixFromBody(body []byte) string {
	if m := ibAccountKeyRE.FindSubmatch(body); len(m) > 1 {
		acc := string(m[1])
		if len(acc) >= 4 {
			return acc[len(acc)-4:]
		}
	}
	if s := IBAccountSuffix4(string(body)); s != "" {
		return s
	}
	return ""
}

// countDistinctSymbols returns distinct uppercase tickers.
func countDistinctSymbols(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range symbolEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	return int64(len(seen))
}

// sumUSDAmounts sums all USD-amount rows in body.
func sumUSDAmounts(body []byte) int64 {
	var total int64
	for _, m := range usdAmountRE.FindAllSubmatch(body, -1) {
		if c := decimalToCents(string(m[1])); c > 0 {
			total += c
		}
	}
	return total
}

// countAboveCapTrades counts USD-amount rows ≥ BCRA cap.
func countAboveCapTrades(body []byte) int64 {
	var n int64
	for _, m := range usdAmountRE.FindAllSubmatch(body, -1) {
		if c := decimalToCents(string(m[1])); c >= BCRAIndividualCapUSDCents {
			n++
		}
	}
	return n
}

// decimalToCents parses "1.234,56" or "1234.56" to cents.
func decimalToCents(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if strings.Count(s, ".") > 0 && strings.Count(s, ",") > 0 {
		s = strings.ReplaceAll(s, ".", "")
		s = strings.ReplaceAll(s, ",", ".")
	} else {
		s = strings.ReplaceAll(s, ",", ".")
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 {
		return 0
	}
	return int64(math.Round(f * 100))
}
