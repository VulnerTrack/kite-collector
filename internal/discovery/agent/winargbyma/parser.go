package winargbyma

import (
	"bytes"
	"encoding/xml"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// BYMAFields captures scalar fields the audit pipeline
// needs from a BYMA artifact (config / blotter / api).
type BYMAFields struct {
	TickersByName       map[string]struct{}
	BrokerMatricula     string
	OperatorCuitRaw     string
	ClienteCuitRaw      string
	APIKeyHash          string
	SessionFirstSeen    string
	SessionLastSeen     string
	Period              string
	CEDEARCount         int64
	SovereignCount      int64
	DistinctCount       int64
	TradeCount          int64
	MaxNotionalCents    int64
	TotalCents          int64
	MaxPositionPct      int
	CaucionMaxTenorDays int
	HasAPIKey           bool
	HasMEPCCLArbitrage  bool
}

// apiKeyRE detects an api_key / bearer / secret / token in a
// JSON/YAML/INI body. Captures the value so we can hash it.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(api[_-]?key|bearer|access[_-]?token|secret|client[_-]?secret|password)("|')?\s*[:=]\s*("|')?([a-z0-9_\-\.\+/=]{12,})`,
)

// matriculaIniRE matches `Matricula=NNNN` / `BrokerMatricula=NNNN`
// or `matricula_byma = NNNN` (with optional snake/dash suffix).
var matriculaIniRE = regexp.MustCompile(
	`(?im)^\s*"?(?:Matricula|BrokerMatricula|Matricula[_\- ]?BYMA|matricula[_\- ]?byma|broker[_\- ]?matricula|Matricula[_\- ]?Broker)"?\s*[:=]\s*"?(\d{1,5})"?`,
)

// timestampRE matches a `YYYY-MM-DD HH:MM[:SS]` or
// `YYYY/MM/DD HH:MM[:SS]` token at line start (BYMA logs).
var timestampRE = regexp.MustCompile(
	`(?m)^\s*(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`,
)

// caucionTenorRE matches a caución tenor row.
// `Plazo=NN` / `Tenor=NN` / `<plazo>NN</plazo>`.
var caucionTenorRE = regexp.MustCompile(
	`(?i)(?:plazo|tenor|dias?_caucion|caucion_dias)\s*[:=>]\s*(\d{1,3})`,
)

// tickerRE matches a ticker token: 2-6 upper-alphanumeric.
// Argentine sovereign tickers (AL30/GD30D) carry digits, so
// alpha-only matching misses them.
var tickerRE = regexp.MustCompile(
	`(?:^|[\s\|;,>"'<])([A-Z][A-Z0-9]{1,5})(?:[\s\|;,<"'/]|$)`,
)

// clienteCuitKeyRE matches a key labeled `cliente_cuit` /
// `cuit_cliente` / `client_cuit` followed by a CUIT-like
// value. Used to route the CUIT to ClienteCuitRaw even when
// its prefix would normally classify as a human-operator.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|client[_\- ]?cuit|titular[_\- ]?cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// operatorCuitKeyRE matches a key labeled `operador_cuit` /
// `cuit_operador` followed by a CUIT-like value.
var operatorCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:operador[_\- ]?cuit|cuit[_\- ]?operador|operator[_\- ]?cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseBYMAConfig parses an Edge / Aries / SX / Connect API
// config body. Captures matrícula + api-key presence + key
// fingerprint.
func ParseBYMAConfig(body []byte) BYMAFields {
	out := BYMAFields{TickersByName: map[string]struct{}{}}
	if len(body) == 0 {
		return out
	}
	if m := apiKeyRE.FindSubmatch(body); m != nil {
		out.HasAPIKey = true
		// m[5] is the value-capture group. Hash + retain.
		if len(m) >= 6 && len(m[5]) > 0 {
			out.APIKeyHash = HashSecret(string(m[5]))
		}
	}
	if m := matriculaIniRE.FindSubmatch(body); m != nil {
		out.BrokerMatricula = string(m[1])
	}
	// Prefer key-labeled CUITs over the first-found heuristic
	// — they carry semantic intent (cliente vs operador).
	if m := operatorCuitKeyRE.FindSubmatch(body); m != nil {
		out.OperatorCuitRaw = string(m[1])
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	// Fallback for configs without explicit cliente/operador
	// labels — pick the first CUIT in the body.
	if out.OperatorCuitRaw == "" && out.ClienteCuitRaw == "" {
		if m := cuitRE.FindSubmatch(body); m != nil {
			out.OperatorCuitRaw = string(m[1]) + string(m[2]) + string(m[3])
		}
	}
	return out
}

// ParseBYMABlotter parses an RV blotter / CEDEAR-pos / BCV /
// liquidación / caución body in XML or CSV form.
func ParseBYMABlotter(body []byte) BYMAFields {
	out := BYMAFields{TickersByName: map[string]struct{}{}}
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out
	}
	if trimmed[0] == '<' {
		parseBlotterXML(body, &out)
	} else {
		parseBlotterText(body, &out)
	}
	if tenor := maxCaucionTenor(body); tenor > 0 {
		out.CaucionMaxTenorDays = tenor
	}
	if out.BrokerMatricula == "" {
		if m := matriculaIniRE.FindSubmatch(body); m != nil {
			out.BrokerMatricula = string(m[1])
		}
	}
	finalize(&out)
	return out
}

type blotterXMLEnvelope struct {
	XMLName  xml.Name
	Children []blotterXMLNode `xml:",any"`
}

type blotterXMLNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr       `xml:",any,attr"`
	Value    string           `xml:",chardata"`
	Children []blotterXMLNode `xml:",any"`
}

func parseBlotterXML(body []byte, out *BYMAFields) {
	var env blotterXMLEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return
	}
	walkBlotterNodes(env.Children, out)
}

func walkBlotterNodes(nodes []blotterXMLNode, out *BYMAFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "trade", "operacion", "concertacion", "boleto",
			"posicion", "position":
			out.TradeCount++
			processTrade(n, out)
		case "ticker", "especie", "instrumento", "symbol":
			if val != "" {
				registerTicker(out, val)
			}
		case "cuit_cliente", "cliente_cuit":
			if out.ClienteCuitRaw == "" && val != "" {
				out.ClienteCuitRaw = val
			}
		case "cuit_operador", "operador_cuit":
			if out.OperatorCuitRaw == "" && val != "" {
				out.OperatorCuitRaw = val
			}
		case "matricula_broker", "matricula", "broker_matricula":
			if out.BrokerMatricula == "" && val != "" {
				out.BrokerMatricula = val
			}
		case "fecha_hora", "hora_concertacion", "timestamp":
			if out.SessionFirstSeen == "" && val != "" {
				out.SessionFirstSeen = val
			}
			if val != "" {
				out.SessionLastSeen = val
			}
		case "periodo":
			if out.Period == "" && val != "" {
				out.Period = val
			}
		}
		if len(n.Children) > 0 {
			walkBlotterNodes(n.Children, out)
		}
	}
}

func processTrade(n blotterXMLNode, out *BYMAFields) {
	var notRaw, ticker string
	var walk func(nodes []blotterXMLNode)
	walk = func(nodes []blotterXMLNode) {
		for _, c := range nodes {
			cn := strings.ToLower(c.XMLName.Local)
			cv := strings.TrimSpace(c.Value)
			switch cn {
			case "importe", "monto", "valor",
				"nominal", "notional", "valor_mercado":
				if notRaw == "" && cv != "" {
					notRaw = cv
				}
			case "ticker", "especie", "instrumento",
				"symbol":
				if ticker == "" && cv != "" {
					ticker = cv
				}
			}
			if len(c.Children) > 0 {
				walk(c.Children)
			}
		}
	}
	walk(n.Children)
	if ticker != "" {
		registerTicker(out, ticker)
	}
	if cents := decimalToCents(notRaw); cents > 0 {
		out.TotalCents += cents
		if cents > out.MaxNotionalCents {
			out.MaxNotionalCents = cents
		}
	}
}

// parseBlotterText parses CSV/TSV/pipe-delimited blotter
// bodies. Each non-empty non-comment line is one trade row.
func parseBlotterText(body []byte, out *BYMAFields) {
	lines := bytes.Split(body, []byte("\n"))
	for _, raw := range lines {
		line := bytes.TrimSpace(raw)
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' || line[0] == ';' || line[0] == '/' {
			continue
		}
		out.TradeCount++
		// inline notional
		if m := regexp.MustCompile(
			`(?i)(?:Importe|Monto|Valor|Nominal|Notional)\s*[:=]\s*([0-9][0-9\.,]*)`,
		).
			FindSubmatch(line); m != nil {
			if cents := decimalToCents(string(m[1])); cents > 0 {
				out.TotalCents += cents
				if cents > out.MaxNotionalCents {
					out.MaxNotionalCents = cents
				}
			}
		}
		// tickers anywhere on the line
		for _, m := range tickerRE.FindAllSubmatch(line, -1) {
			registerTicker(out, string(m[1]))
		}
	}
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
}

// registerTicker upserts a ticker into the by-name set,
// incrementing CEDEAR / sovereign counters as appropriate.
func registerTicker(out *BYMAFields, raw string) {
	t := strings.ToUpper(strings.TrimSpace(raw))
	if t == "" {
		return
	}
	if _, seen := out.TickersByName[t]; seen {
		return
	}
	out.TickersByName[t] = struct{}{}
	switch {
	case IsCEDEARTicker(t):
		out.CEDEARCount++
	case IsSovereignTicker(t):
		out.SovereignCount++
	}
}

// maxCaucionTenor returns the largest tenor (days) found in
// the body matching `plazo|tenor|...`.
func maxCaucionTenor(body []byte) int {
	matches := caucionTenorRE.FindAllSubmatch(body, -1)
	if len(matches) == 0 {
		return 0
	}
	max := 0
	for _, m := range matches {
		v, err := strconv.Atoi(string(m[1]))
		if err != nil {
			continue
		}
		if v > max {
			max = v
		}
	}
	return max
}

// finalize computes derived counters (distinct ticker count,
// max-position-pct, MEP/CCL pairing flag).
func finalize(out *BYMAFields) {
	out.DistinctCount = int64(len(out.TickersByName))
	if out.TotalCents > 0 && out.MaxNotionalCents > 0 {
		out.MaxPositionPct = int(out.MaxNotionalCents * 100 / out.TotalCents)
		if out.MaxPositionPct > 100 {
			out.MaxPositionPct = 100
		}
	}
	if out.SovereignCount >= 2 {
		tickers := make([]string, 0, len(out.TickersByName))
		for t := range out.TickersByName {
			if IsSovereignTicker(t) {
				tickers = append(tickers, t)
			}
		}
		for i := 0; i < len(tickers); i++ {
			for j := i + 1; j < len(tickers); j++ {
				if IsMEPCCLPair(tickers[i], tickers[j]) {
					out.HasMEPCCLArbitrage = true
					return
				}
			}
		}
	}
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
