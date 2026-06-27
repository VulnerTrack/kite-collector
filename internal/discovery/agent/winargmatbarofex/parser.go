package winargmatbarofex

import (
	"bytes"
	"encoding/xml"
	"math"
	"strconv"
	"strings"
)

// MatbaFields captures the scalar position fields the audit
// pipeline cares about across XML / CSV inputs.
type MatbaFields struct {
	BrokerMatricula  string
	AccountCuitRaw   string
	BrokerCuitRaw    string
	ContractMonth    string
	OpenContracts    int
	NotionalUSDCents int64
	HasMarginCall    bool
	HasConcentration bool
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

// ParseMatbaArtifact extracts MatbaFields from XML or CSV
// body. Returns ok=false on empty input.
func ParseMatbaArtifact(body []byte) (MatbaFields, bool) {
	var out MatbaFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out, false
	}
	switch trimmed[0] {
	case '<':
		out = parseXMLArtifact(body)
	default:
		out = parseTextArtifact(body)
	}
	if hasAny(out) {
		return out, true
	}
	return out, false
}

func hasAny(f MatbaFields) bool {
	return f.OpenContracts > 0 || f.NotionalUSDCents > 0 ||
		f.BrokerMatricula != "" || f.AccountCuitRaw != "" ||
		f.BrokerCuitRaw != "" || f.HasMarginCall ||
		f.ContractMonth != ""
}

// -- XML --------------------------------------------------------

func parseXMLArtifact(body []byte) MatbaFields {
	var out MatbaFields
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out
	}
	walkXML(env.Children, &out)
	return out
}

func walkXML(nodes []genericNode, out *MatbaFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "open_contracts", "opencontracts", "contratos",
			"cantidad_contratos", "cantidadcontratos":
			if out.OpenContracts == 0 && val != "" {
				if n, err := strconv.Atoi(val); err == nil {
					out.OpenContracts = n
				}
			}
		case "notional_usd", "notionalusd", "notional":
			if out.NotionalUSDCents == 0 && val != "" {
				out.NotionalUSDCents = arsToCents(val)
			}
		case "matricula", "matricula_cnv", "broker_matricula":
			if out.BrokerMatricula == "" && val != "" {
				out.BrokerMatricula = val
			}
		case "cuit_cuenta", "cuitcuenta", "cuit_cliente":
			if out.AccountCuitRaw == "" && val != "" {
				out.AccountCuitRaw = val
			}
		case "cuit_broker", "cuitbroker", "cuit_agente":
			if out.BrokerCuitRaw == "" && val != "" {
				out.BrokerCuitRaw = val
			}
		case "margin_call", "llamada_margen", "llamadamargen":
			if val != "" && val != "0" && val != "false" {
				out.HasMarginCall = true
			}
		case "contract_month", "contractmonth", "mes_contrato":
			if out.ContractMonth == "" && val != "" {
				out.ContractMonth = val
			}
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

// -- CSV / text scrape -----------------------------------------

func parseTextArtifact(body []byte) MatbaFields {
	var out MatbaFields
	s := string(body)
	lower := strings.ToLower(s)

	// Margin-call narrative detection.
	for _, marker := range []string{
		"margin call", "llamada de margen", "llamada-margen",
		"intimacion margen", "margen insuficiente",
	} {
		if strings.Contains(lower, marker) {
			out.HasMarginCall = true
			break
		}
	}

	// Simple line-based extraction for CSV/TXT bodies.
	for _, line := range strings.Split(s, "\n") {
		ll := strings.ToLower(line)
		if strings.HasPrefix(ll, "matricula") || strings.Contains(ll, "matricula:") {
			if v := afterColon(line); v != "" {
				out.BrokerMatricula = v
			}
		}
		if strings.HasPrefix(ll, "contratos") || strings.Contains(ll, "contratos:") {
			if v := afterColon(line); v != "" {
				if n, err := strconv.Atoi(strings.Fields(v)[0]); err == nil {
					out.OpenContracts = n
				}
			}
		}
	}
	return out
}

func afterColon(line string) string {
	idx := strings.IndexByte(line, ':')
	if idx < 0 || idx == len(line)-1 {
		return ""
	}
	return strings.TrimSpace(line[idx+1:])
}

func arsToCents(s string) int64 {
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
