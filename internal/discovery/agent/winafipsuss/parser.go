package winafipsuss

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// elevenDigitsRE captures the first 11 consecutive digits for
// raw-CUIT extraction off declaration meta lines.
var elevenDigitsRE = regexp.MustCompile(`(\d{11})`)

// SussSummary captures aggregate stats from a SUSS body.
type SussSummary struct {
	EmpleadorCuitRaw       string
	Period                 string
	ConvenioColectivo      string
	EmpleadosCount         int64
	MaxRemuneracionCents   int64
	TotalRemuneracionCents int64
	ObrasocialCodesCount   int64
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

// ParseSuss extracts aggregate stats. F931 is XML; SICOSS
// aplicativo dumps are fixed-width; nomina CSV. The XML
// walker handles F931; line scan handles the rest.
func ParseSuss(body []byte) (SussSummary, bool) {
	var out SussSummary
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
	} else {
		scanLines(body, &out)
	}
	if !hasAny(out) {
		return out, false
	}
	return out, true
}

func hasAny(s SussSummary) bool {
	return s.EmpleadorCuitRaw != "" || s.Period != "" ||
		s.ConvenioColectivo != "" || s.EmpleadosCount > 0 ||
		s.TotalRemuneracionCents > 0 || s.ObrasocialCodesCount > 0
}

func walkXML(nodes []genericNode, out *SussSummary) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cuit_empleador", "cuitempleador",
			"empleador_cuit":
			if out.EmpleadorCuitRaw == "" && val != "" {
				out.EmpleadorCuitRaw = val
			}
		case "periodo", "periodo_fiscal":
			if out.Period == "" && val != "" {
				out.Period = val
			}
		case "cct", "convenio_colectivo",
			"convenio":
			if out.ConvenioColectivo == "" && val != "" {
				out.ConvenioColectivo = val
			}
		case "empleado", "trabajador", "relacion_laboral":
			processEmpleado(n, out)
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

// processEmpleado counts one empleado and accumulates
// remuneración + obra social presence.
func processEmpleado(n genericNode, out *SussSummary) {
	var remunRaw, obraRaw string
	var walk func(nodes []genericNode)
	walk = func(nodes []genericNode) {
		for _, c := range nodes {
			cn := strings.ToLower(c.XMLName.Local)
			cv := strings.TrimSpace(c.Value)
			switch cn {
			case "remuneracion", "remuneracion_bruta",
				"remuneracion_total", "sueldo_bruto":
				if remunRaw == "" && cv != "" {
					remunRaw = cv
				}
			case "obra_social", "codigo_obra_social",
				"obrasocial_codigo":
				if obraRaw == "" && cv != "" {
					obraRaw = cv
				}
			}
			if len(c.Children) > 0 {
				walk(c.Children)
			}
		}
	}
	walk(n.Children)
	out.EmpleadosCount++
	if cents := decimalToCents(remunRaw); cents > 0 {
		out.TotalRemuneracionCents += cents
		if cents > out.MaxRemuneracionCents {
			out.MaxRemuneracionCents = cents
		}
	}
	if obraRaw != "" {
		out.ObrasocialCodesCount++
	}
}

// scanLines walks each non-XML line, counts CUIL entries and
// sums the rightmost ARS amount.
func scanLines(body []byte, out *SussSummary) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if isHeaderOnlyLine(line) {
			continue
		}
		if isEmpleadorMetaLine(line) {
			if out.EmpleadorCuitRaw == "" {
				if raw := first11Digits(line); raw != "" {
					out.EmpleadorCuitRaw = raw
				}
			}
			continue
		}
		if has11DigitCuit(line) {
			out.EmpleadosCount++
			if cents := rightmostARSCents(line); cents > 0 {
				out.TotalRemuneracionCents += cents
				if cents > out.MaxRemuneracionCents {
					out.MaxRemuneracionCents = cents
				}
			}
		}
	}
}

func isHeaderOnlyLine(line string) bool {
	for _, c := range line {
		if c >= '0' && c <= '9' {
			return false
		}
	}
	return true
}

func isEmpleadorMetaLine(line string) bool {
	l := strings.ToLower(line)
	for _, tok := range []string{
		"cuit_empleador", "cuit_agente", "cuit del empleador",
		"empleador_cuit",
	} {
		if strings.Contains(l, tok) {
			return true
		}
	}
	return false
}

func has11DigitCuit(line string) bool {
	return cuitRE.MatchString(line)
}

func first11Digits(line string) string {
	m := elevenDigitsRE.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	return m[1]
}

func rightmostARSCents(line string) int64 {
	parts := strings.FieldsFunc(line, func(r rune) bool {
		switch r {
		case ',', ';', '|', '\t', ' ':
			return true
		}
		return false
	})
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if cents := decimalToCents(p); cents > 0 {
			return cents
		}
	}
	return 0
}

func decimalToCents(s string) int64 {
	s = strings.ReplaceAll(s, "$", "")
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if !strings.ContainsAny(s, ".,") {
		if len(s) >= 6 {
			return 0
		}
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
