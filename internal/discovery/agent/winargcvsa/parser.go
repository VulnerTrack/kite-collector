package winargcvsa

import (
	"bytes"
	"encoding/xml"
	"math"
	"strconv"
	"strings"
)

// CustodyFields captures scalar fields the audit pipeline
// needs. Counts are computed during parsing.
type CustodyFields struct {
	BrokerMatricula   string
	BrokerCuitRaw     string
	ClienteCuitRaw    string
	CuentaComitenteID string
	Period            string
	HasForeignOwner   bool
	InstrumentCount   int64
	CotitularesCount  int64
	MaxPositionCents  int64
	TotalCents        int64
}

type genericNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr    `xml:",any,attr"`
	Value    string        `xml:",chardata"`
	Children []genericNode `xml:",any"`
}

type xmlEnvelope struct {
	XMLName  xml.Name
	Children []genericNode `xml:",any"`
}

// ParseCVSAArtifact extracts CustodyFields from XML body.
// Returns ok=false on empty / unparseable input. .cda
// archives are out-of-scope for content parsing — the
// collector still records hash + finding-flag bits.
func ParseCVSAArtifact(body []byte) (CustodyFields, bool) {
	var out CustodyFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out, false
	}
	if trimmed[0] != '<' {
		// CSV / fixed-width — out of scope for structured parse
		// at this iteration (still returns ok=false so collector
		// keeps the row from filename-derived fields only).
		return out, false
	}
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out, false
	}
	walkXML(env.Children, &out)
	if !hasAny(out) {
		return out, false
	}
	return out, true
}

func hasAny(f CustodyFields) bool {
	return f.BrokerMatricula != "" || f.BrokerCuitRaw != "" ||
		f.ClienteCuitRaw != "" || f.CuentaComitenteID != "" ||
		f.Period != "" || f.InstrumentCount > 0 ||
		f.CotitularesCount > 0 || f.TotalCents > 0
}

func walkXML(nodes []genericNode, out *CustodyFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "broker_matricula", "matricula_broker",
			"alyc_matricula":
			if out.BrokerMatricula == "" && val != "" {
				out.BrokerMatricula = val
			}
		case "broker_cuit", "cuit_broker":
			if out.BrokerCuitRaw == "" && val != "" {
				out.BrokerCuitRaw = val
			}
		case "cliente_cuit", "cuit_cliente", "titular_cuit",
			"cuit_titular":
			if out.ClienteCuitRaw == "" && val != "" {
				out.ClienteCuitRaw = val
			}
		case "cuenta_comitente", "comitente", "numero_cuenta":
			if out.CuentaComitenteID == "" && val != "" {
				out.CuentaComitenteID = val
			}
		case "periodo", "periodo_corte", "fecha_corte":
			if out.Period == "" && val != "" {
				out.Period = val
			}
		case "residencia", "residencia_fiscal", "pais_titular":
			if isForeignResidence(val) {
				out.HasForeignOwner = true
			}
		case "tenencia", "posicion", "instrumento":
			processTenencia(n, out)
		case "cotitular", "titular":
			out.CotitularesCount++
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

// processTenencia counts an instrument and accumulates its
// market-value cents (importe / valor_mercado / monto).
func processTenencia(n genericNode, out *CustodyFields) {
	var valuRaw string
	var walk func(nodes []genericNode)
	walk = func(nodes []genericNode) {
		for _, c := range nodes {
			cn := strings.ToLower(c.XMLName.Local)
			cv := strings.TrimSpace(c.Value)
			switch cn {
			case "valor_mercado", "importe", "monto",
				"market_value":
				if valuRaw == "" && cv != "" {
					valuRaw = cv
				}
			}
			if len(c.Children) > 0 {
				walk(c.Children)
			}
		}
	}
	walk(n.Children)
	out.InstrumentCount++
	if cents := decimalToCents(valuRaw); cents > 0 {
		out.TotalCents += cents
		if cents > out.MaxPositionCents {
			out.MaxPositionCents = cents
		}
	}
}

func isForeignResidence(s string) bool {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, tok := range []string{
		"exterior", "extranjero", "no residente",
		"foreign", "non-resident", "non resident",
	} {
		if strings.Contains(t, tok) {
			return true
		}
	}
	// 3-letter ISO codes other than ARG.
	if len(t) == 3 && t != "arg" {
		ok := true
		for _, c := range t {
			if c < 'a' || c > 'z' {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func decimalToCents(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	s = strings.ReplaceAll(s, ",", ".")
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	if f <= 0 {
		return 0
	}
	return int64(math.Round(f * 100))
}
