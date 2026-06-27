package winargbcraforex

import (
	"bytes"
	"encoding/xml"
	"math"
	"strconv"
	"strings"
)

// ForexFields captures scalar fields the audit pipeline needs.
type ForexFields struct {
	DeclarantCuitRaw    string
	BrokerMatricula     string
	CounterpartyCountry string
	MonedaText          string
	ConceptoBCRA        string
	OperacionText       string
	FechaOperacion      string
	MontoUSDCents       int64
	MontoARSCents       int64
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

// ParseBCRAForex extracts ForexFields from an XML / CSV / JSON
// body. Returns ok=false on garbage / empty input.
func ParseBCRAForex(body []byte) (ForexFields, bool) {
	var out ForexFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out, false
	}
	if trimmed[0] == '<' {
		var env xmlEnvelope
		if err := xml.Unmarshal(body, &env); err != nil {
			return out, false
		}
		walkXML(env.Children, &out)
	}
	// Cross-format narrative scan for speculative-concepto tokens.
	lower := strings.ToLower(string(body))
	if out.ConceptoBCRA == "" {
		for _, c := range SpeculativeConceptos() {
			needle := strings.ToLower(c)
			if strings.Contains(lower, " "+needle+" ") ||
				strings.Contains(lower, ">"+needle+"<") {
				out.ConceptoBCRA = c
				break
			}
		}
	}
	if hasAny(out) {
		return out, true
	}
	return out, false
}

func hasAny(f ForexFields) bool {
	return f.DeclarantCuitRaw != "" || f.BrokerMatricula != "" ||
		f.CounterpartyCountry != "" || f.ConceptoBCRA != "" ||
		f.MontoUSDCents > 0 || f.MontoARSCents > 0 ||
		f.FechaOperacion != "" || f.OperacionText != ""
}

func walkXML(nodes []genericNode, out *ForexFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cuit_declarante", "cuitdeclarante", "cuit_operador",
			"cuitoperador", "declarante":
			if out.DeclarantCuitRaw == "" && val != "" {
				out.DeclarantCuitRaw = val
			}
		case "broker_matricula", "brokermatricula", "matricula_broker",
			"alyc_matricula":
			if out.BrokerMatricula == "" && val != "" {
				out.BrokerMatricula = val
			}
		case "pais_contraparte", "paiscontraparte", "country",
			"destino_pais", "contraparte_pais":
			if out.CounterpartyCountry == "" && val != "" {
				out.CounterpartyCountry = val
			}
		case "moneda", "moneda_operacion", "currency":
			if out.MonedaText == "" && val != "" {
				out.MonedaText = val
			}
		case "concepto", "concepto_bcra", "conceptobcra",
			"codigo_concepto":
			if out.ConceptoBCRA == "" && val != "" {
				out.ConceptoBCRA = val
			}
		case "operacion", "tipo_operacion", "tipooperacion",
			"operation_type":
			if out.OperacionText == "" && val != "" {
				out.OperacionText = val
			}
		case "fecha_operacion", "fechaoperacion", "fecha":
			if out.FechaOperacion == "" && val != "" {
				out.FechaOperacion = val
			}
		case "monto_usd", "montousd", "importe_usd", "amount_usd":
			if out.MontoUSDCents == 0 && val != "" {
				out.MontoUSDCents = toCents(val)
			}
		case "monto_ars", "montoars", "importe_ars", "amount_ars",
			"monto":
			if out.MontoARSCents == 0 && val != "" {
				out.MontoARSCents = toCents(val)
			}
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

func toCents(s string) int64 {
	v := strings.TrimSpace(s)
	if v == "" {
		return 0
	}
	v = strings.ReplaceAll(v, ",", ".")
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return int64(math.Round(f * 100))
}
