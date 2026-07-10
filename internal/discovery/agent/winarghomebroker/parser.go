package winarghomebroker

import (
	"regexp"
	"strings"
)

// HBFields captures scalar fields the audit pipeline needs
// from a HomeBroker artifact.
type HBFields struct {
	SignalRToken     string
	Username         string
	ClienteCuitRaw   string
	BrokerMatricula  string
	ALYCBranding     string
	SessionFirstSeen string
	SessionLastSeen  string
	DistinctSymbols  int64
	OrderEventCount  int64
	CancelEventCount int64
	FillEventCount   int64
	HasPassword      bool
}

// signalrTokenRE matches a SignalR connection token / bearer.
var signalrTokenRE = regexp.MustCompile(
	`(?i)("|')?(?:connection[_-]?token|access[_-]?token|bearer|api[_-]?token|jwt|hub[_-]?token|signalr[_-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{20,})`,
)

// usernameRE matches `username` / `user` / `email`.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:username|user|email|usuario)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// passwordRE matches a password row (line-anchored INI/JSON/XML).
var passwordRE = regexp.MustCompile(
	`(?im)^\s*(?:<\s*)?"?(?:password|clave|pass|passwd)"?\s*(?:[:=>]|>)\s*\S+`,
)

// passwordXMLRE matches `<password>…</password>` on a single line.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|clave)\s*>[^<\n]{1,}<\s*/\s*(?:password|clave)\s*>`,
)

// timestampRE matches `YYYY-MM-DD HH:MM[:SS]`.
var timestampRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`,
)

// signalrEventRE matches a SignalR hub-method event line.
var signalrEventRE = regexp.MustCompile(
	`(?i)(?:SendOrder|NewOrder|OrderRequest|hub\.invoke|hub\.send|invokeMethod)`,
)

// orderEventRE matches an order placement event.
var orderEventRE = regexp.MustCompile(
	`(?i)(?:SendOrder|NewOrder|OrderRequest|order[_\- ]?new|order[_\- ]?placed|order[_\- ]?submitted|enviar[_\- ]?orden|nueva[_\- ]?orden)`,
)

// cancelEventRE matches an order cancel event.
var cancelEventRE = regexp.MustCompile(
	`(?i)(?:CancelOrder|order[_\- ]?cancel(?:led)?|cancelar[_\- ]?orden|orden[_\- ]?cancelada|cancel[_\- ]?request)`,
)

// fillEventRE matches an order fill / execution event.
var fillEventRE = regexp.MustCompile(
	`(?i)(?:OrderFilled|order[_\- ]?fill(?:ed)?|execution[_\- ]?report|trade[_\- ]?executed|orden[_\- ]?ejecutada|orden[_\- ]?confirmada|fill[_\- ]?notification)`,
)

// symbolJSONRE matches a JSON / INI symbol entry.
var symbolJSONRE = regexp.MustCompile(
	`(?i)"?(?:symbol|simbolo|s[ií]mbolo|ticker|especie|instrumento)"?\s*[:=]\s*"?([A-Za-z0-9_\-\./]{2,32})`,
)

// symbolXMLRE matches `<symbol>…</symbol>`.
var symbolXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:symbol|simbolo|ticker|instrument)\s*>([A-Za-z0-9_\-\./]{2,32})<\s*/\s*(?:symbol|simbolo|ticker|instrument)\s*>`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// clienteCuitXMLRE matches `<cliente_cuit>…</cliente_cuit>`.
var clienteCuitXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:cliente[_\-]?cuit|cuit[_\-]?cliente|titular[_\-]?cuit|cuit)\s*>(\d{2}-?\d{8}-?\d)`,
)

// ParseHBCredentials parses a credentials / token file.
func ParseHBCredentials(body []byte, name string) HBFields {
	var out HBFields
	if len(body) == 0 {
		return out
	}
	if m := signalrTokenRE.FindSubmatch(body); len(m) > 3 {
		out.SignalRToken = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if passwordXMLRE.Match(body) || passwordRE.Match(body) {
		out.HasPassword = true
	}
	out.ClienteCuitRaw = cuitFromBody(body)
	out.BrokerMatricula = MatriculaFromText(string(body))
	out.ALYCBranding = DetectALYCBranding(body, name)
	return out
}

// ParseHBConfig parses a HomeBroker config.json / settings file.
func ParseHBConfig(body []byte, name string) HBFields {
	return ParseHBCredentials(body, name)
}

// ParseHBWatchlist parses a watchlist artifact.
func ParseHBWatchlist(body []byte, name string) HBFields {
	var out HBFields
	if len(body) == 0 {
		return out
	}
	out.DistinctSymbols = countDistinctSymbols(body)
	out.ALYCBranding = DetectALYCBranding(body, name)
	return out
}

// ParseHBPositions parses a positions cache.
func ParseHBPositions(body []byte, name string) HBFields {
	var out HBFields
	if len(body) == 0 {
		return out
	}
	out.DistinctSymbols = countDistinctSymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	out.ALYCBranding = DetectALYCBranding(body, name)
	return out
}

// ParseHBOrders parses an orders cache.
func ParseHBOrders(body []byte, name string) HBFields {
	var out HBFields
	if len(body) == 0 {
		return out
	}
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	out.OrderEventCount = int64(len(orderEventRE.FindAllIndex(body, -1)))
	out.CancelEventCount = int64(len(cancelEventRE.FindAllIndex(body, -1)))
	out.FillEventCount = int64(len(fillEventRE.FindAllIndex(body, -1)))
	out.DistinctSymbols = countDistinctSymbols(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	out.ALYCBranding = DetectALYCBranding(body, name)
	return out
}

// ParseHBSignalRLog parses a SignalR hub session log.
func ParseHBSignalRLog(body []byte, name string) HBFields {
	var out HBFields
	if len(body) == 0 {
		return out
	}
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	out.OrderEventCount = int64(len(orderEventRE.FindAllIndex(body, -1)))
	out.CancelEventCount = int64(len(cancelEventRE.FindAllIndex(body, -1)))
	out.FillEventCount = int64(len(fillEventRE.FindAllIndex(body, -1)))
	if m := signalrTokenRE.FindSubmatch(body); len(m) > 3 {
		out.SignalRToken = string(m[3])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	out.ALYCBranding = DetectALYCBranding(body, name)
	return out
}

// ParseHBSkin parses a skin / theme CSS / branding XML to
// detect ALYC slug.
func ParseHBSkin(body []byte, name string) HBFields {
	var out HBFields
	out.ALYCBranding = DetectALYCBranding(body, name)
	return out
}

// cuitFromBody runs the key and XML form variants.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	if m := clienteCuitXMLRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// countDistinctSymbols returns the count of unique tickers.
func countDistinctSymbols(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range symbolJSONRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	for _, m := range symbolXMLRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	return int64(len(seen))
}

// HasSignalRMarker reports whether the body contains a SignalR
// hub-invoke marker (useful as a presence signal).
func HasSignalRMarker(body []byte) bool {
	return signalrEventRE.Match(body)
}
