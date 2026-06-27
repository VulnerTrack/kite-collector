package winargcnvalyc

import (
	"bytes"
	"encoding/xml"
	"math"
	"strconv"
	"strings"
)

// ALYCFields captures the scalar broker fields the audit
// pipeline cares about across XML / XBRL inputs.
type ALYCFields struct {
	AlycCuitRaw       string
	AlycDenominacion  string
	AlycMatricula     string
	Period            string
	ClientCount       int
	SpecieCount       int
	TotalAUMARSCents  int64
	MaxClientPct      int
	HasForeignCustody bool
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

// ParseALYCDisclosure extracts ALYCFields from XML body.
// Returns ok=false on garbage / non-ALYC input.
func ParseALYCDisclosure(body []byte) (ALYCFields, bool) {
	var out ALYCFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '<' {
		return out, false
	}
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out, false
	}

	state := &walkState{
		clientCuits: make(map[string]struct{}),
		specieCodes: make(map[string]struct{}),
	}
	walkXML(env.Children, state)

	out.AlycCuitRaw = state.alycCuitRaw
	out.AlycDenominacion = state.alycDenominacion
	out.AlycMatricula = state.alycMatricula
	out.Period = state.period
	out.ClientCount = len(state.clientCuits)
	out.SpecieCount = len(state.specieCodes)
	out.TotalAUMARSCents = state.totalAUMCents
	out.HasForeignCustody = state.hasForeignCustody

	// Compute max-client-% from per-client AUM balances.
	if state.totalAUMCents > 0 && len(state.clientAUMCents) > 0 {
		maxClient := int64(0)
		for _, v := range state.clientAUMCents {
			if v > maxClient {
				maxClient = v
			}
		}
		pct := int((maxClient * 100) / state.totalAUMCents)
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		out.MaxClientPct = pct
	}

	if hasAny(out) {
		return out, true
	}
	return out, false
}

func hasAny(f ALYCFields) bool {
	return f.AlycCuitRaw != "" || f.AlycMatricula != "" ||
		f.ClientCount > 0 || f.SpecieCount > 0 ||
		f.TotalAUMARSCents > 0
}

type walkState struct {
	clientCuits       map[string]struct{}
	specieCodes       map[string]struct{}
	clientAUMCents    map[string]int64
	alycCuitRaw       string
	alycDenominacion  string
	alycMatricula     string
	period            string
	totalAUMCents     int64
	hasForeignCustody bool
}

func walkXML(nodes []genericNode, st *walkState) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cuit_agente", "cuitalyc", "cuit_alyc", "cuitagente":
			if st.alycCuitRaw == "" && val != "" {
				st.alycCuitRaw = val
			}
		case "denominacion_agente", "denominacion", "razonsocial_agente":
			if st.alycDenominacion == "" && val != "" {
				st.alycDenominacion = val
			}
		case "matricula", "matricula_cnv", "matricula_alyc":
			if st.alycMatricula == "" && val != "" {
				st.alycMatricula = val
			}
		case "periodo", "period", "periodo_informe":
			if st.period == "" && val != "" {
				st.period = val
			}
		case "tenencia", "saldo_cliente", "saldocliente":
			processClienteNode(&n, st)
		case "cuit_cliente", "cuitcliente":
			if val != "" {
				st.clientCuits[val] = struct{}{}
			}
		case "especie", "instrumento", "codigo_especie":
			if val != "" {
				st.specieCodes[val] = struct{}{}
			}
		case "total_aum", "totalaum", "monto_total_custodia":
			if st.totalAUMCents == 0 && val != "" {
				st.totalAUMCents = arsToCents(val)
			}
		case "moneda", "monedacustodia":
			if isForeignCurrency(val) {
				st.hasForeignCustody = true
			}
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, st)
		}
	}
}

func processClienteNode(n *genericNode, st *walkState) {
	if st.clientAUMCents == nil {
		st.clientAUMCents = make(map[string]int64)
	}
	var clientID, monto, moneda string
	for _, c := range n.Children {
		name := strings.ToLower(c.XMLName.Local)
		val := strings.TrimSpace(c.Value)
		switch name {
		case "cuit_cliente", "cuitcliente", "cuit":
			clientID = val
		case "monto", "saldo", "valor_custodia":
			monto = val
		case "moneda", "moneda_balance":
			moneda = val
		}
	}
	if clientID != "" {
		st.clientCuits[clientID] = struct{}{}
		if monto != "" {
			cents := arsToCents(monto)
			st.clientAUMCents[clientID] += cents
		}
	}
	if isForeignCurrency(moneda) {
		st.hasForeignCustody = true
	}
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

func isForeignCurrency(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	switch t {
	case "", "ARS", "PES", "PESO", "PESOS":
		return false
	}
	return true
}
