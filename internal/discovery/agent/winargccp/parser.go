package winargccp

import (
	"bytes"
	"encoding/xml"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// CCPFields captures scalar fields the audit pipeline needs
// from a CCP artifact (margin / settlement / haircut).
type CCPFields struct {
	ClearingMemberMatricula      string
	ClienteCuitRaw               string
	SettlementDate               string
	Period                       string
	MarginRequiredCents          int64
	MarginPostedCents            int64
	MarginCallCents              int64
	MaxHaircutPct                int
	CompensadorBalanceCents      int64
	DefaultFundContributionCents int64
	StressTestVarCents           int64
	HasMarginCallActive          bool
	HasStressBreach              bool
	HasDefaultFundCall           bool
}

// marginRequiredRE matches `margin_required` / `margen_requerido`.
var marginRequiredRE = regexp.MustCompile(
	`(?i)("|')?(margin[_\- ]?required|margen[_\- ]?requerido|requerido)("|')?\s*[:=>]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// marginPostedRE matches `margin_posted` / `margen_aportado` / `posted_collateral`.
var marginPostedRE = regexp.MustCompile(
	`(?i)("|')?(margin[_\- ]?posted|margen[_\- ]?aportado|posted[_\- ]?collateral|aportado|garantia_aportada)("|')?\s*[:=>]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// marginCallRE matches `margin_call_amount` / `llamada_margen_monto`.
var marginCallRE = regexp.MustCompile(
	`(?i)("|')?(margin[_\- ]?call(?:[_\- ]?amount)?|llamada[_\- ]?margen(?:[_\- ]?monto)?|call[_\- ]?amount)("|')?\s*[:=>]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// haircutRE matches a `haircut`/`aforo` percent row.
var haircutRE = regexp.MustCompile(
	`(?i)("|')?(haircut|aforo|risk[_\- ]?factor)("|')?\s*[:=>]\s*"?([0-9]+(?:\.[0-9]+)?)\s*%?`)

// compensadorBalanceRE matches `compensador_balance` row.
var compensadorBalanceRE = regexp.MustCompile(
	`(?i)("|')?(compensador[_\- ]?balance|saldo[_\- ]?compensador|clearing[_\- ]?balance|balance)("|')?\s*[:=>]\s*"?(-?[0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// defaultFundRE matches `default_fund_contribution`.
var defaultFundRE = regexp.MustCompile(
	`(?i)("|')?(default[_\- ]?fund(?:[_\- ]?contribution)?|fondo[_\- ]?garantia(?:[_\- ]?aporte)?|contribucion[_\- ]?fondo)("|')?\s*[:=>]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// stressTestVarRE matches `stress_test_var` / `var_99`.
var stressTestVarRE = regexp.MustCompile(
	`(?i)("|')?(stress[_\- ]?test[_\- ]?var|var[_\- ]?99|var_estress)("|')?\s*[:=>]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// settlementDateRE matches `settlement_date: YYYY-MM-DD`.
var settlementDateRE = regexp.MustCompile(
	`(?i)("|')?(settlement[_\- ]?date|fecha[_\- ]?liquidacion|fecha_liq)("|')?\s*[:=>]\s*"?(20\d{2}-\d{2}-\d{2})`)

// stressBreachRE detects a stress-test-breach marker.
var stressBreachRE = regexp.MustCompile(
	`(?i)(?:stress[_\- ]?breach|stress[_\- ]?failed|test[_\- ]?breach|excede[_\- ]?umbral|breach[_\- ]?threshold)`)

// defaultFundCallRE detects an extra default-fund call.
var defaultFundCallRE = regexp.MustCompile(
	`(?i)(?:default[_\- ]?fund[_\- ]?call|extra[_\- ]?contribution|aporte[_\- ]?extraordinario|llamada[_\- ]?fondo)`)

// matriculaIniRE matches `clearing_member_matricula` row.
var matriculaIniRE = regexp.MustCompile(
	`(?im)^\s*"?(?:matricula|clearing[_\- ]?member|compensador[_\- ]?matricula)"?\s*[:=>]\s*"?(\d{1,5})"?`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseCCPArtifact parses a CCP body (XML / JSON / CSV) and
// extracts margin / settlement / haircut scalars.
func ParseCCPArtifact(body []byte) CCPFields {
	var out CCPFields
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	// Try structured XML first to get authoritative tags.
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '<' {
		parseCCPXML(body, &out)
	} else {
		// CSV / TSV / pipe-delimited haircut table — scan
		// header for a haircut/aforo column and read per-row
		// percentages.
		parseHaircutCSV(body, &out)
	}

	// Regex fallbacks (XML body may not match all tags; CSV
	// and INI bodies need flat-key scans).
	if out.MarginRequiredCents == 0 {
		if m := marginRequiredRE.FindSubmatch(body); len(m) > 4 {
			out.MarginRequiredCents = decimalToCents(string(m[4]))
		}
	}
	if out.MarginPostedCents == 0 {
		if m := marginPostedRE.FindSubmatch(body); len(m) > 4 {
			out.MarginPostedCents = decimalToCents(string(m[4]))
		}
	}
	if out.MarginCallCents == 0 {
		if m := marginCallRE.FindSubmatch(body); len(m) > 4 {
			cents := decimalToCents(string(m[4]))
			if cents > 0 {
				out.MarginCallCents = cents
				out.HasMarginCallActive = true
			}
		}
	}
	if out.MaxHaircutPct == 0 {
		for _, m := range haircutRE.FindAllSubmatch(body, -1) {
			if len(m) < 5 {
				continue
			}
			pct := decimalToPct(string(m[4]))
			if pct > out.MaxHaircutPct {
				out.MaxHaircutPct = pct
			}
		}
	}
	if out.CompensadorBalanceCents == 0 {
		if m := compensadorBalanceRE.FindSubmatch(body); len(m) > 4 {
			out.CompensadorBalanceCents = decimalToCentsSigned(string(m[4]))
		}
	}
	if out.DefaultFundContributionCents == 0 {
		if m := defaultFundRE.FindSubmatch(body); len(m) > 4 {
			out.DefaultFundContributionCents = decimalToCents(string(m[4]))
		}
	}
	if out.StressTestVarCents == 0 {
		if m := stressTestVarRE.FindSubmatch(body); len(m) > 4 {
			out.StressTestVarCents = decimalToCents(string(m[4]))
		}
	}
	if out.SettlementDate == "" {
		if m := settlementDateRE.FindSubmatch(body); len(m) > 4 {
			out.SettlementDate = string(m[4])
		}
	}
	if out.ClearingMemberMatricula == "" {
		if m := matriculaIniRE.FindSubmatch(body); m != nil {
			out.ClearingMemberMatricula = string(m[1])
		}
	}
	if out.ClienteCuitRaw == "" {
		if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
			out.ClienteCuitRaw = string(m[1])
		}
	}
	if out.ClienteCuitRaw == "" {
		if m := cuitRE.FindSubmatch(body); m != nil {
			out.ClienteCuitRaw = string(m[1]) + string(m[2]) + string(m[3])
		}
	}
	if stressBreachRE.Match(body) {
		out.HasStressBreach = true
	}
	if defaultFundCallRE.Match(body) {
		out.HasDefaultFundCall = true
	}
	return out
}

type ccpXMLEnvelope struct {
	XMLName  xml.Name
	Children []ccpXMLNode `xml:",any"`
}

type ccpXMLNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr   `xml:",any,attr"`
	Value    string       `xml:",chardata"`
	Children []ccpXMLNode `xml:",any"`
}

func parseCCPXML(body []byte, out *CCPFields) {
	var env ccpXMLEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return
	}
	walkCCPNodes(env.Children, out)
}

func walkCCPNodes(nodes []ccpXMLNode, out *CCPFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "margin_required", "margen_requerido", "requerido":
			if c := decimalToCents(val); c > 0 {
				out.MarginRequiredCents = c
			}
		case "margin_posted", "margen_aportado", "aportado",
			"garantia_aportada":
			if c := decimalToCents(val); c > 0 {
				out.MarginPostedCents = c
			}
		case "margin_call", "llamada_margen", "call_amount":
			if c := decimalToCents(val); c > 0 {
				out.MarginCallCents = c
				out.HasMarginCallActive = true
			}
		case "compensador_balance", "saldo_compensador",
			"clearing_balance", "balance":
			if c := decimalToCentsSigned(val); c != 0 {
				out.CompensadorBalanceCents = c
			}
		case "default_fund", "fondo_garantia", "contribucion_fondo":
			if c := decimalToCents(val); c > 0 {
				out.DefaultFundContributionCents = c
			}
		case "stress_test_var", "var_99", "var_estress":
			if c := decimalToCents(val); c > 0 {
				out.StressTestVarCents = c
			}
		case "settlement_date", "fecha_liquidacion", "fecha_liq":
			if out.SettlementDate == "" && val != "" {
				out.SettlementDate = val
			}
		case "periodo":
			if out.Period == "" && val != "" {
				out.Period = val
			}
		case "matricula", "clearing_member", "compensador_matricula":
			if out.ClearingMemberMatricula == "" && val != "" {
				out.ClearingMemberMatricula = val
			}
		case "cliente_cuit", "cuit_cliente", "titular_cuit":
			if out.ClienteCuitRaw == "" && val != "" {
				out.ClienteCuitRaw = val
			}
		case "haircut", "aforo":
			if p := decimalToPct(val); p > out.MaxHaircutPct {
				out.MaxHaircutPct = p
			}
		}
		if len(n.Children) > 0 {
			walkCCPNodes(n.Children, out)
		}
	}
}

// parseHaircutCSV scans a CSV / TSV body for a haircut column
// and updates out.MaxHaircutPct with the largest value.
//
// Header row is identified by the presence of a "haircut" /
// "aforo" / "factor_riesgo" token. Subsequent rows are parsed
// by the same delimiter inferred from the header.
func parseHaircutCSV(body []byte, out *CCPFields) {
	lines := bytes.Split(body, []byte("\n"))
	if len(lines) < 2 {
		return
	}
	// Find header.
	headerIdx := -1
	var delim byte
	for i, raw := range lines {
		line := bytes.TrimSpace(raw)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		lower := bytes.ToLower(line)
		if !bytes.Contains(lower, []byte("haircut")) &&
			!bytes.Contains(lower, []byte("aforo")) &&
			!bytes.Contains(lower, []byte("factor_riesgo")) {
			continue
		}
		headerIdx = i
		delim = inferDelim(line)
		break
	}
	if headerIdx < 0 || delim == 0 {
		return
	}
	// Find which column index holds the haircut value.
	cols := bytes.Split(bytes.TrimSpace(lines[headerIdx]), []byte{delim})
	haircutCol := -1
	for c, raw := range cols {
		col := bytes.ToLower(bytes.TrimSpace(raw))
		if bytes.Equal(col, []byte("haircut")) ||
			bytes.Equal(col, []byte("aforo")) ||
			bytes.Equal(col, []byte("factor_riesgo")) ||
			bytes.Equal(col, []byte("risk_factor")) {
			haircutCol = c
			break
		}
	}
	if haircutCol < 0 {
		return
	}
	for i := headerIdx + 1; i < len(lines); i++ {
		row := bytes.TrimSpace(lines[i])
		if len(row) == 0 || row[0] == '#' {
			continue
		}
		cells := bytes.Split(row, []byte{delim})
		if haircutCol >= len(cells) {
			continue
		}
		val := strings.TrimSpace(string(cells[haircutCol]))
		if p := decimalToPct(val); p > out.MaxHaircutPct {
			out.MaxHaircutPct = p
		}
	}
}

// inferDelim picks the most-likely CSV/TSV delimiter from a
// header line (comma, semicolon, tab, pipe).
func inferDelim(line []byte) byte {
	for _, d := range []byte{',', ';', '\t', '|'} {
		if bytes.Contains(line, []byte{d}) {
			return d
		}
	}
	return 0
}

// decimalToCents parses positive decimal to cents.
func decimalToCents(s string) int64 {
	c := decimalToCentsSigned(s)
	if c < 0 {
		return 0
	}
	return c
}

// decimalToCentsSigned parses signed decimal to cents.
func decimalToCentsSigned(s string) int64 {
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
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return int64(math.Round(f * 100))
}

// decimalToPct parses a percent number; clamps to [0, 100].
// Accepts integer / float form. Fractional <1 values are
// treated as ratios (0.65 -> 65 %).
func decimalToPct(s string) int {
	s = strings.TrimSpace(strings.TrimRight(s, "% "))
	if s == "" {
		return 0
	}
	s = strings.ReplaceAll(s, ",", ".")
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	if f > 0 && f <= 1 {
		f *= 100
	}
	if f < 0 {
		return 0
	}
	if f > 100 {
		return 100
	}
	return int(math.Round(f))
}
