package winargfci

import (
	"bytes"
	"encoding/xml"
	"math"
	"strconv"
	"strings"
)

// FCIFields captures the scalar fund-level fields the audit
// pipeline cares about.
type FCIFields struct {
	FciMatricula               string
	FciDenominacion            string
	SociedadGerenteCuitRaw     string
	SociedadDepositariaCuitRaw string
	NavARSCents                int64
	AumARSCents                int64
	CuotapartistasCount        int
	MaxCuotapartistaPct        int
	ForeignCurrencyWeightPct   int
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

// ParseFCIArtifact extracts FCIFields from XML / CSV body.
// Returns ok=false on garbage / empty input.
func ParseFCIArtifact(body []byte) (FCIFields, bool) {
	var out FCIFields
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

func hasAny(f FCIFields) bool {
	return f.FciMatricula != "" || f.FciDenominacion != "" ||
		f.SociedadGerenteCuitRaw != "" || f.NavARSCents > 0 ||
		f.AumARSCents > 0 || f.CuotapartistasCount > 0
}

// -- XML --------------------------------------------------------

func parseXMLArtifact(body []byte) FCIFields {
	var out FCIFields
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out
	}
	state := &walkState{
		cuotapartistas: make(map[string]struct{}),
		clientAUMCents: make(map[string]int64),
	}
	walkXML(env.Children, state)
	out.FciMatricula = state.fciMatricula
	out.FciDenominacion = state.fciDenominacion
	out.SociedadGerenteCuitRaw = state.sociedadGerenteCuit
	out.SociedadDepositariaCuitRaw = state.sociedadDepositariaCuit
	out.NavARSCents = state.navARSCents
	out.AumARSCents = state.aumARSCents
	out.CuotapartistasCount = len(state.cuotapartistas)
	// Concentration from per-investor AUM balances.
	if state.aumARSCents > 0 && len(state.clientAUMCents) > 0 {
		maxClient := int64(0)
		for _, v := range state.clientAUMCents {
			if v > maxClient {
				maxClient = v
			}
		}
		pct := int((maxClient * 100) / state.aumARSCents)
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		out.MaxCuotapartistaPct = pct
	}
	// Foreign-currency weight from portfolio composition.
	if state.totalAssetWeight > 0 {
		pct := int((state.foreignAssetWeight * 100) / state.totalAssetWeight)
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		out.ForeignCurrencyWeightPct = pct
	}
	return out
}

type walkState struct {
	cuotapartistas          map[string]struct{}
	clientAUMCents          map[string]int64
	fciMatricula            string
	fciDenominacion         string
	sociedadGerenteCuit     string
	sociedadDepositariaCuit string
	navARSCents             int64
	aumARSCents             int64
	foreignAssetWeight      int64
	totalAssetWeight        int64
}

func walkXML(nodes []genericNode, st *walkState) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "fci_matricula", "matricula_fci", "matricula":
			if st.fciMatricula == "" && val != "" {
				st.fciMatricula = val
			}
		case "fci_denominacion", "denominacion_fci", "denominacion":
			if st.fciDenominacion == "" && val != "" {
				st.fciDenominacion = val
			}
		case "cuit_sociedad_gerente", "sociedad_gerente_cuit",
			"cuitsociedadgerente":
			if st.sociedadGerenteCuit == "" && val != "" {
				st.sociedadGerenteCuit = val
			}
		case "cuit_sociedad_depositaria", "sociedad_depositaria_cuit",
			"cuitsociedaddepositaria":
			if st.sociedadDepositariaCuit == "" && val != "" {
				st.sociedadDepositariaCuit = val
			}
		case "nav", "valor_cuotaparte", "valorcuotaparte":
			if st.navARSCents == 0 && val != "" {
				st.navARSCents = arsToCents(val)
			}
		case "aum", "aum_total", "patrimonio_neto", "patrimonioneto":
			if st.aumARSCents == 0 && val != "" {
				st.aumARSCents = arsToCents(val)
			}
		case "cuotapartista":
			processCuotapartistaNode(&n, st)
		case "activo", "instrumento":
			processActivoNode(&n, st)
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, st)
		}
	}
}

func processCuotapartistaNode(n *genericNode, st *walkState) {
	var cuit, monto string
	for _, c := range n.Children {
		name := strings.ToLower(c.XMLName.Local)
		val := strings.TrimSpace(c.Value)
		switch name {
		case "cuit", "cuit_cuotapartista":
			cuit = val
		case "monto", "valor", "valor_cuotaparte":
			monto = val
		}
	}
	if cuit != "" {
		st.cuotapartistas[cuit] = struct{}{}
		if monto != "" {
			st.clientAUMCents[cuit] += arsToCents(monto)
		}
	}
}

func processActivoNode(n *genericNode, st *walkState) {
	var moneda, peso string
	for _, c := range n.Children {
		name := strings.ToLower(c.XMLName.Local)
		val := strings.TrimSpace(c.Value)
		switch name {
		case "moneda", "currency":
			moneda = val
		case "peso", "weight", "porcentaje":
			peso = val
		}
	}
	pesoVal := arsToCents(peso) / 100 // accept e.g. "12.5" as 12 weight units
	if pesoVal == 0 {
		pesoVal = 1
	}
	st.totalAssetWeight += pesoVal
	if isForeignCurrency(moneda) {
		st.foreignAssetWeight += pesoVal
	}
}

// -- CSV / text scrape -----------------------------------------

func parseTextArtifact(body []byte) FCIFields {
	var out FCIFields
	s := string(body)
	for _, line := range strings.Split(s, "\n") {
		ll := strings.ToLower(line)
		switch {
		case strings.HasPrefix(ll, "matricula") || strings.Contains(ll, "matricula:"):
			if v := afterColon(line); v != "" {
				out.FciMatricula = v
			}
		case strings.HasPrefix(ll, "nav") || strings.Contains(ll, "valor_cuotaparte:"):
			if v := afterColon(line); v != "" {
				out.NavARSCents = arsToCents(v)
			}
		case strings.HasPrefix(ll, "aum") || strings.Contains(ll, "patrimonio_neto:"):
			if v := afterColon(line); v != "" {
				out.AumARSCents = arsToCents(v)
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

func isForeignCurrency(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	switch t {
	case "", "ARS", "PES", "PESO", "PESOS":
		return false
	}
	return true
}
