package winargtradingview

import (
	"bytes"
	"regexp"
	"strings"
)

// TVFields captures scalar fields the audit pipeline needs
// from a TradingView artifact.
type TVFields struct {
	ArgentineTickers map[string]struct{}
	StrategyName     string
	PineVersion      PineVersion
	APIKey           string
	WebhookURL       string
	ClienteCuitRaw   string
	AlertCount       int64
	WatchlistTickers int64
	HasStrategyFn    bool
	HasWebhookSecret bool
}

// strategyFnRE matches `strategy("Name", ...)` Pine call.
var strategyFnRE = regexp.MustCompile(
	`(?i)\bstrategy\s*\(\s*["']?([^"',)]{2,80})`,
)

// indicatorFnRE matches `indicator("Name", ...)` Pine call.
var indicatorFnRE = regexp.MustCompile(
	`(?i)\bindicator\s*\(\s*["']?([^"',)]{2,80})`,
)

// pineVersionRE matches `//@version=N` Pine version comment.
var pineVersionRE = regexp.MustCompile(
	`(?m)^\s*//\s*@\s*version\s*=\s*(\d)`,
)

// webhookURLRE matches a webhook URL row in alert config JSON.
var webhookURLRE = regexp.MustCompile(
	`(?i)("|')?(webhook[_\- ]?url|webhook|hook[_\- ]?url)("|')?\s*[:=]\s*"?(https?://[^\s"'<>]{8,})`,
)

// secretInWebhookRE matches a bearer / api_key / secret inside
// a webhook payload or header. Skips the optional `Bearer ` /
// `Basic ` scheme prefix before the captured value.
var secretInWebhookRE = regexp.MustCompile(
	`(?i)("|')?(api[_-]?key|bearer|secret|access[_-]?token|authorization)("|')?\s*[:=]\s*("|')?(?:Bearer\s+|Basic\s+)?([A-Za-z0-9_\-\.\+/=]{16,})`,
)

// alertEntryRE counts alert entries in a TradingView alert
// config body.
var alertEntryRE = regexp.MustCompile(
	`(?i)"(?:alert_name|alert_id|alertId|alertName)"\s*:`,
)

// watchlistTickerRE matches a ticker entry in a watchlist
// CSV / JSON. Accepts `_` and `(` as closer so Pine strings
// like `"GGAL_momentum"` still surface their leading ticker.
var watchlistTickerRE = regexp.MustCompile(
	`(?:^|[\s\|;,>"'<])([A-Z][A-Z0-9]{1,5})(?:[\s\|;,<"'/_()]|$)`,
)

// apiKeyInPineRE matches API key declarations inside a Pine
// source (in comments or strings).
var apiKeyInPineRE = regexp.MustCompile(
	`(?i)(?://|"|')\s*(api[_-]?key|bearer|secret|access[_-]?token)\s*[:=]\s*"?([A-Za-z0-9_\-]{16,})`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseTVPineScript parses a .pine source body and extracts
// strategy/indicator name, Pine version, Argentine tickers,
// and api-key markers.
func ParseTVPineScript(body []byte) TVFields {
	out := TVFields{ArgentineTickers: map[string]struct{}{}}
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	if m := strategyFnRE.FindSubmatch(body); m != nil {
		out.HasStrategyFn = true
		out.StrategyName = strings.TrimSpace(string(m[1]))
	} else if m := indicatorFnRE.FindSubmatch(body); m != nil {
		out.StrategyName = strings.TrimSpace(string(m[1]))
	}
	if m := pineVersionRE.FindSubmatch(body); m != nil {
		switch string(m[1]) {
		case "3":
			out.PineVersion = PineV3
		case "4":
			out.PineVersion = PineV4
		case "5":
			out.PineVersion = PineV5
		case "6":
			out.PineVersion = PineV6
		default:
			out.PineVersion = PineOther
		}
	}
	// Argentine ticker scan.
	for _, m := range watchlistTickerRE.FindAllSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		t := strings.ToUpper(string(m[1]))
		if IsArgentineTicker(t) {
			out.ArgentineTickers[t] = struct{}{}
		}
	}
	// API key in Pine source.
	if m := apiKeyInPineRE.FindSubmatch(body); len(m) > 2 {
		out.APIKey = string(m[2])
	}
	return out
}

// ParseTVWebhookConfig parses an alert / webhook config body
// and extracts webhook URL + secret presence.
func ParseTVWebhookConfig(body []byte) TVFields {
	out := TVFields{ArgentineTickers: map[string]struct{}{}}
	if len(body) == 0 {
		return out
	}
	if m := webhookURLRE.FindSubmatch(body); len(m) > 4 {
		out.WebhookURL = string(m[4])
	}
	if m := secretInWebhookRE.FindSubmatch(body); len(m) > 5 {
		out.HasWebhookSecret = true
		out.APIKey = string(m[5])
	}
	out.AlertCount = int64(len(alertEntryRE.FindAllIndex(body, -1)))
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseTVWatchlist parses a watchlist CSV / JSON body. Counts
// total tickers + Argentine-ticker subset.
func ParseTVWatchlist(body []byte) TVFields {
	out := TVFields{ArgentineTickers: map[string]struct{}{}}
	if len(body) == 0 {
		return out
	}
	seen := map[string]struct{}{}
	for _, m := range watchlistTickerRE.FindAllSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		t := strings.ToUpper(string(m[1]))
		if _, found := seen[t]; found {
			continue
		}
		seen[t] = struct{}{}
		if IsArgentineTicker(t) {
			out.ArgentineTickers[t] = struct{}{}
		}
	}
	out.WatchlistTickers = int64(len(seen))
	return out
}
