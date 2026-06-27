package winargsiopel

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// SIOPELFields captures scalar fields the audit pipeline
// needs from a SIOPEL artifact (config / rueda / log).
type SIOPELFields struct {
	OperatorMatricula   string
	OperatorCuitRaw     string
	ClienteCuitRaw      string
	DealerCode          string
	SessionFirstSeen    string
	SessionLastSeen     string
	Period              string
	TradeCount          int64
	ConcertacionCount   int64
	BajaCount           int64
	MaxNotionalCents    int64
	CaucionMaxTenorDays int
	HasPasswordInline   bool
	HasMEPCCLArbitrage  bool
}

// passwordRE detects SIOPEL config password rows. SIOPEL
// keeps operator credentials in either Password=, Clave=, or
// PasswordOp= keys, sometimes with the prefix "siopel.".
var passwordRE = regexp.MustCompile(
	`(?im)^\s*(?:siopel\.)?(?:password(?:op)?|clave|claveop|passop|operadorpwd)\s*=\s*\S+`)

// matriculaIniRE matches `Operador=NNNN` / `Matricula=NNNN`
// in INI files.
var matriculaIniRE = regexp.MustCompile(
	`(?im)^\s*(?:Operador|MatriculaOperador|Matricula)\s*=\s*(\d{1,5})`)

// dealerIniRE matches `Dealer=ABCD` in INI files.
var dealerIniRE = regexp.MustCompile(
	`(?im)^\s*Dealer(?:Code)?\s*=\s*([A-Za-z]{3,5})`)

// concertacionRE matches a SIOPEL log "CONCERTACION OK" /
// "CONCERTACION-OK" / "Concertación realizada" marker.
var concertacionRE = regexp.MustCompile(
	`(?i)concertaci[oó]n[\s_\-]*(?:ok|realizada|exitosa|aceptada)`)

// bajaRE matches a log baja / cancel marker.
var bajaRE = regexp.MustCompile(
	`(?i)(?:baja|cancelaci[oó]n)[\s_\-]*(?:ok|realizada|aceptada)`)

// timestampRE matches a `YYYY-MM-DD HH:MM[:SS]` or
// `YYYY/MM/DD HH:MM[:SS]` token at line start (SIOPEL logs).
var timestampRE = regexp.MustCompile(
	`(?m)^\s*(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`)

// caucionTenorRE matches a `Plazo=NN` / `Tenor=NN` /
// `<plazo>NN</plazo>` (in days) entry from a rueda-caución
// record. Accepts ini/csv key=value form and xml >value<
// form on either side of the separator.
var caucionTenorRE = regexp.MustCompile(
	`(?i)(?:plazo|tenor|dias?_caucion|caucion_dias)\s*[:=>]\s*(\d{1,3})`)

// mepRE / cclRE detect MEP / CCL operation markers used to
// surface the MEP-CCL arbitrage pattern (paired in-session).
var (
	mepRE = regexp.MustCompile(`(?i)\b(?:MEP|dollar[_\s-]mep|d[oó]lar[_\s-]mep)\b`)
	cclRE = regexp.MustCompile(`(?i)\b(?:CCL|contado[_\s-]liqui|contadoconliqui)\b`)
)

// notionalInlineRE matches an `Importe=NN,NN` anywhere on a
// pipe/semicolon-delimited line (per-line CSV/TSV scan).
var notionalInlineRE = regexp.MustCompile(
	`(?i)(?:Importe|Monto|Valor|Nominal|Notional)\s*[:=]\s*([0-9][0-9\.,]*)`)

// ParseSIOPELConfig parses a SIOPEL INI / CFG body.
//
// Captures: matrícula, dealer code, cleartext password flag.
func ParseSIOPELConfig(body []byte) SIOPELFields {
	var out SIOPELFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) {
		out.HasPasswordInline = true
	}
	if m := matriculaIniRE.FindSubmatch(body); m != nil {
		out.OperatorMatricula = string(m[1])
	}
	if m := dealerIniRE.FindSubmatch(body); m != nil {
		out.DealerCode = strings.ToUpper(string(m[1]))
	}
	// Look for an operator CUIT anywhere in the file body
	// (SIOPEL configs often list the operator CUIT in an
	// adjacent `CuitOperador=` row).
	if m := cuitRE.FindSubmatch(body); m != nil {
		out.OperatorCuitRaw = strings.Join(
			[]string{string(m[1]), string(m[2]), string(m[3])}, "")
	}
	return out
}

// ParseSIOPELLog parses a SIOPEL session-log body.
//
// Captures: first/last timestamp, concertación count, baja
// count, dealer code, operator CUIT, MEP/CCL pairing.
func ParseSIOPELLog(body []byte) SIOPELFields {
	var out SIOPELFields
	if len(body) == 0 {
		return out
	}
	out.ConcertacionCount = int64(len(concertacionRE.FindAllIndex(body, -1)))
	out.BajaCount = int64(len(bajaRE.FindAllIndex(body, -1)))
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	hasMEP := mepRE.Match(body)
	hasCCL := cclRE.Match(body)
	if hasMEP && hasCCL {
		out.HasMEPCCLArbitrage = true
	}
	if m := dealerIniRE.FindSubmatch(body); m != nil {
		out.DealerCode = strings.ToUpper(string(m[1]))
	}
	if m := cuitRE.FindSubmatch(body); m != nil {
		out.OperatorCuitRaw = string(m[1]) + string(m[2]) + string(m[3])
	}
	// trade-count approximated by per-line concertación + baja.
	out.TradeCount = out.ConcertacionCount + out.BajaCount
	return out
}

// ParseSIOPELRueda parses a SIOPEL rueda XML / CSV body.
//
// XML form: <rueda><operacion>...</operacion>...</rueda>
// CSV form: pipe / semicolon separated per-line.
func ParseSIOPELRueda(body []byte) SIOPELFields {
	var out SIOPELFields
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out
	}
	if trimmed[0] == '<' {
		parseRuedaXML(body, &out)
	} else {
		parseRuedaText(body, &out)
	}
	// Across-form scans (regex-friendly tokens).
	if caucionMax := maxCaucionTenor(body); caucionMax > 0 {
		out.CaucionMaxTenorDays = caucionMax
	}
	hasMEP := mepRE.Match(body)
	hasCCL := cclRE.Match(body)
	if hasMEP && hasCCL {
		out.HasMEPCCLArbitrage = true
	}
	if out.OperatorMatricula == "" {
		if m := matriculaIniRE.FindSubmatch(body); m != nil {
			out.OperatorMatricula = string(m[1])
		}
	}
	if out.OperatorCuitRaw == "" {
		if m := cuitRE.FindSubmatch(body); m != nil {
			out.OperatorCuitRaw = string(m[1]) + string(m[2]) + string(m[3])
		}
	}
	if out.DealerCode == "" {
		if m := dealerIniRE.FindSubmatch(body); m != nil {
			out.DealerCode = strings.ToUpper(string(m[1]))
		}
	}
	return out
}

type ruedaXMLEnvelope struct {
	XMLName  xml.Name
	Children []ruedaXMLNode `xml:",any"`
}

type ruedaXMLNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr     `xml:",any,attr"`
	Value    string         `xml:",chardata"`
	Children []ruedaXMLNode `xml:",any"`
}

func parseRuedaXML(body []byte, out *SIOPELFields) {
	var env ruedaXMLEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return
	}
	walkRuedaNodes(env.Children, out)
}

func walkRuedaNodes(nodes []ruedaXMLNode, out *SIOPELFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "operacion", "concertacion", "trade":
			out.TradeCount++
			out.ConcertacionCount++
			processOperacion(n, out)
		case "baja", "cancelacion":
			out.BajaCount++
		case "cuit_operador", "operador_cuit":
			if out.OperatorCuitRaw == "" && val != "" {
				out.OperatorCuitRaw = val
			}
		case "cuit_cliente", "cliente_cuit":
			if out.ClienteCuitRaw == "" && val != "" {
				out.ClienteCuitRaw = val
			}
		case "matricula_operador", "operador":
			if out.OperatorMatricula == "" && val != "" {
				out.OperatorMatricula = val
			}
		case "dealer", "dealer_code":
			if out.DealerCode == "" && val != "" {
				out.DealerCode = strings.ToUpper(val)
			}
		case "fecha_hora", "timestamp", "hora_concertacion":
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
			walkRuedaNodes(n.Children, out)
		}
	}
}

func processOperacion(n ruedaXMLNode, out *SIOPELFields) {
	var notRaw string
	var walk func(nodes []ruedaXMLNode)
	walk = func(nodes []ruedaXMLNode) {
		for _, c := range nodes {
			cn := strings.ToLower(c.XMLName.Local)
			cv := strings.TrimSpace(c.Value)
			switch cn {
			case "importe", "monto", "valor",
				"nominal", "notional":
				if notRaw == "" && cv != "" {
					notRaw = cv
				}
			}
			if len(c.Children) > 0 {
				walk(c.Children)
			}
		}
	}
	walk(n.Children)
	if cents := decimalToCents(notRaw); cents > out.MaxNotionalCents {
		out.MaxNotionalCents = cents
	}
}

func parseRuedaText(body []byte, out *SIOPELFields) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		// Skip CSV/TSV comment + header lines so they don't
		// pollute the per-line trade approximation.
		if raw[0] == '#' || raw[0] == ';' || raw[0] == '/' {
			continue
		}
		// Each non-empty line ≈ 1 trade row in a CSV/TSV rueda
		// export. Concertación count = trade count for text form.
		out.TradeCount++
		out.ConcertacionCount++
		if m := notionalInlineRE.FindSubmatch(raw); m != nil {
			if cents := decimalToCents(string(m[1])); cents > out.MaxNotionalCents {
				out.MaxNotionalCents = cents
			}
		}
	}
	// timestamps: first + last across body
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
}

// maxCaucionTenor scans the body for caución `Plazo=NN`
// markers and returns the largest NN found.
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

// decimalToCents parses "1.234,56" or "1234.56" to cents.
func decimalToCents(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// Normalize: drop thousand-separators when both comma and
	// dot present; otherwise treat comma as decimal separator.
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
