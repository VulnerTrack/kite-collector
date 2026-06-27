package winargmav

import (
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// MAVFields captures scalar fields the audit pipeline needs
// from a MAV artifact.
type MAVFields struct {
	MemberMatricula      string
	LibradorCuitRaw      string
	ReceptorCuitRaw      string
	ClienteCuitRaw       string
	SGRName              string
	Provincia            string
	Moneda               Moneda
	FechaVencimiento     string
	FechaLibramiento     string
	Period               string
	MontoCents           int64
	TotalPortfolioCents  int64
	MaxConcentrationPct  int
	InstrumentCount      int64
	HasDefaultMarker     bool
	HasProvDefaultMarker bool
}

// sgrNameRE matches an SGR-name token. SGRs in Argentina
// follow a naming pattern: "SGR <X>", "<X> SGR", "<X> Garantía
// Mutual", "Garantizar S.G.R.", etc.
var sgrNameRE = regexp.MustCompile(
	`(?i)\b((?:[A-Za-záéíóúñÁÉÍÓÚÑ][A-Za-z0-9.&\-_ áéíóúñÁÉÍÓÚÑ]{1,40}\s+)?(?:S\.?G\.?R\.?|sgr)|garantizar|garantia mutual|aval\s+rural)\b`)

// sgrKeyRE matches an explicit `sgr_name: <X>` key.
var sgrKeyRE = regexp.MustCompile(
	`(?i)("|')?(sgr[_\- ]?name|sgr|avalista)("|')?\s*[:=>]\s*"?([A-Za-z0-9.&\-_ áéíóúñÁÉÍÓÚÑ]{3,80})"?`)

// provinciaKeyRE matches a `provincia: <name>` row.
var provinciaKeyRE = regexp.MustCompile(
	`(?i)("|')?(provincia|jurisdiccion[_\- ]?provincial)("|')?\s*[:=>]\s*"?([A-Za-z áéíóúñÁÉÍÓÚÑ]{2,40})"?`)

// monedaKeyRE matches `moneda: <code>` rows.
var monedaKeyRE = regexp.MustCompile(
	`(?i)("|')?(moneda|currency|moneda[_\- ]?nominal)("|')?\s*[:=>]\s*"?([A-Z€$£¥]{1,8})"?`)

// montoRE matches `monto: <decimal>` / `importe: <decimal>` rows.
var montoRE = regexp.MustCompile(
	`(?i)("|')?(monto|importe|valor[_\- ]?nominal|nominal|notional|capital)("|')?\s*[:=>]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// totalPortfolioRE matches a `total_portfolio: <decimal>` row.
var totalPortfolioRE = regexp.MustCompile(
	`(?i)("|')?(total[_\- ]?portfolio|valor[_\- ]?cartera|total[_\- ]?cartera)("|')?\s*[:=>]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// concentrationRE matches a `concentration_pct: NN` row.
var concentrationRE = regexp.MustCompile(
	`(?i)("|')?(concentration[_\- ]?pct|max[_\- ]?concentration|concentracion[_\- ]?max)("|')?\s*[:=>]\s*"?([0-9]+(?:[.,][0-9]+)?)\s*%?`)

// fechaVencimientoRE matches `fecha_vencimiento: YYYY-MM-DD`.
var fechaVencimientoRE = regexp.MustCompile(
	`(?i)("|')?(fecha[_\- ]?vencimiento|vencimiento[_\- ]?fecha|expiry[_\- ]?date|maturity[_\- ]?date)("|')?\s*[:=>]\s*"?(20\d{2}-\d{2}-\d{2})`)

// fechaLibramientoRE matches `fecha_libramiento: YYYY-MM-DD`.
var fechaLibramientoRE = regexp.MustCompile(
	`(?i)("|')?(fecha[_\- ]?libramiento|libramiento[_\- ]?fecha|issue[_\- ]?date)("|')?\s*[:=>]\s*"?(20\d{2}-\d{2}-\d{2})`)

// matriculaIniRE matches a `Matricula` / `MemberMatricula` key
// in INI / JSON / YAML bodies.
var matriculaIniRE = regexp.MustCompile(
	`(?im)^\s*"?(?:Matricula|MemberMatricula|MAVMatricula|MavMatricula)"?\s*[:=>]\s*"?(\d{1,5})"?`)

// matriculaXMLRE matches `<matricula>NNN</matricula>` so XML
// bodies don't need a separate parser.
var matriculaXMLRE = regexp.MustCompile(
	`(?i)<(?:matricula|member_matricula|mav_matricula)>(\d{1,5})</`)

// xmlPairRE generates a tag-form matcher for a labeled value.
// Used inline for sgr_name / librador_cuit / receptor_cuit /
// cliente_cuit when the body is XML.
//
// We pre-compile the most-used ones below.
var sgrNameXMLRE = regexp.MustCompile(
	`(?is)<(?:sgr_name|sgr|avalista)>([^<]{3,80})</`)

var libradorXMLRE = regexp.MustCompile(
	`(?is)<(?:librador_cuit|cuit_librador)>(\d{2}-?\d{8}-?\d)</`)

var receptorXMLRE = regexp.MustCompile(
	`(?is)<(?:receptor_cuit|cuit_receptor|beneficiario_cuit)>(\d{2}-?\d{8}-?\d)</`)

var clienteXMLRE = regexp.MustCompile(
	`(?is)<(?:cliente_cuit|cuit_cliente|titular_cuit)>(\d{2}-?\d{8}-?\d)</`)

var monedaXMLRE = regexp.MustCompile(
	`(?is)<(?:moneda|currency)>([A-Z€$£¥]{1,8})</`)

var montoXMLRE = regexp.MustCompile(
	`(?is)<(?:monto|importe|valor_nominal|nominal|capital)>([0-9.,]+)</`)

var fechaVencimientoXMLRE = regexp.MustCompile(
	`(?is)<(?:fecha_vencimiento|vencimiento|expiry_date|maturity_date)>(20\d{2}-\d{2}-\d{2})</`)

var fechaLibramientoXMLRE = regexp.MustCompile(
	`(?is)<(?:fecha_libramiento|libramiento|issue_date)>(20\d{2}-\d{2}-\d{2})</`)

var provinciaXMLRE = regexp.MustCompile(
	`(?is)<(?:provincia|jurisdiccion_provincial)>([A-Za-zÁÉÍÓÚáéíóúñÑ ]{2,40})</`)

// libradorCuitKeyRE matches `librador_cuit: NN-NNNNNNNN-N`.
var libradorCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:librador[_\- ]?cuit|cuit[_\- ]?librador)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// receptorCuitKeyRE matches `receptor_cuit: NN-NNNNNNNN-N`.
var receptorCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:receptor[_\- ]?cuit|cuit[_\- ]?receptor|beneficiario[_\- ]?cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// defaultMarkerRE detects a default marker.
var defaultMarkerRE = regexp.MustCompile(
	`(?i)(?:\bdefault\b|moroso|incumplimiento|default[_\- ]?risk|rechazo[_\- ]?pago|cheque[_\- ]?rechazado)`)

// provincialDefaultMarkerRE detects a provincial-default marker.
var provincialDefaultMarkerRE = regexp.MustCompile(
	`(?i)(?:provincia[_\- ]?en[_\- ]?default|default[_\- ]?provincial|sub[_\- ]?sovereign[_\- ]?default|rating[_\- ]?downgrade)`)

// ParseMAVArtifact parses a MAV body (XML / CSV / JSON / INI)
// and extracts scalar fields.
func ParseMAVArtifact(body []byte) MAVFields {
	var out MAVFields
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	if m := sgrKeyRE.FindSubmatch(body); len(m) > 4 {
		out.SGRName = strings.TrimSpace(string(m[4]))
	}
	if out.SGRName == "" {
		if m := sgrNameRE.FindSubmatch(body); len(m) > 1 {
			out.SGRName = strings.TrimSpace(string(m[1]))
		}
	}
	if m := provinciaKeyRE.FindSubmatch(body); len(m) > 4 {
		p := strings.TrimSpace(string(m[4]))
		if IsArgentineProvince(p) {
			out.Provincia = p
		}
	}
	if m := monedaKeyRE.FindSubmatch(body); len(m) > 4 {
		out.Moneda = NormalizeMoneda(string(m[4]))
	}
	if m := montoRE.FindSubmatch(body); len(m) > 4 {
		out.MontoCents = decimalToCents(string(m[4]))
	}
	if m := totalPortfolioRE.FindSubmatch(body); len(m) > 4 {
		out.TotalPortfolioCents = decimalToCents(string(m[4]))
	}
	if m := concentrationRE.FindSubmatch(body); len(m) > 4 {
		out.MaxConcentrationPct = decimalToPct(string(m[4]))
	}
	if m := fechaVencimientoRE.FindSubmatch(body); len(m) > 4 {
		out.FechaVencimiento = string(m[4])
	}
	if m := fechaLibramientoRE.FindSubmatch(body); len(m) > 4 {
		out.FechaLibramiento = string(m[4])
	}
	if m := matriculaIniRE.FindSubmatch(body); m != nil {
		out.MemberMatricula = string(m[1])
	}
	if out.MemberMatricula == "" {
		if m := matriculaXMLRE.FindSubmatch(body); m != nil {
			out.MemberMatricula = string(m[1])
		}
	}
	if m := libradorCuitKeyRE.FindSubmatch(body); m != nil {
		out.LibradorCuitRaw = string(m[1])
	}
	if out.LibradorCuitRaw == "" {
		if m := libradorXMLRE.FindSubmatch(body); m != nil {
			out.LibradorCuitRaw = string(m[1])
		}
	}
	if m := receptorCuitKeyRE.FindSubmatch(body); m != nil {
		out.ReceptorCuitRaw = string(m[1])
	}
	if out.ReceptorCuitRaw == "" {
		if m := receptorXMLRE.FindSubmatch(body); m != nil {
			out.ReceptorCuitRaw = string(m[1])
		}
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	if out.ClienteCuitRaw == "" {
		if m := clienteXMLRE.FindSubmatch(body); m != nil {
			out.ClienteCuitRaw = string(m[1])
		}
	}
	// XML-form fallback for SGR / moneda / monto / dates /
	// provincia.
	if out.SGRName == "" {
		if m := sgrNameXMLRE.FindSubmatch(body); m != nil {
			out.SGRName = strings.TrimSpace(string(m[1]))
		}
	}
	if out.Moneda == MonedaNone {
		if m := monedaXMLRE.FindSubmatch(body); m != nil {
			out.Moneda = NormalizeMoneda(string(m[1]))
		}
	}
	if out.MontoCents == 0 {
		if m := montoXMLRE.FindSubmatch(body); m != nil {
			out.MontoCents = decimalToCents(string(m[1]))
		}
	}
	if out.FechaVencimiento == "" {
		if m := fechaVencimientoXMLRE.FindSubmatch(body); m != nil {
			out.FechaVencimiento = string(m[1])
		}
	}
	if out.FechaLibramiento == "" {
		if m := fechaLibramientoXMLRE.FindSubmatch(body); m != nil {
			out.FechaLibramiento = string(m[1])
		}
	}
	if out.Provincia == "" {
		if m := provinciaXMLRE.FindSubmatch(body); m != nil {
			p := strings.TrimSpace(string(m[1]))
			if IsArgentineProvince(p) {
				out.Provincia = p
			}
		}
	}
	if out.ClienteCuitRaw == "" &&
		out.LibradorCuitRaw == "" &&
		out.ReceptorCuitRaw == "" {
		if m := cuitRE.FindSubmatch(body); m != nil {
			out.ClienteCuitRaw = string(m[1]) + string(m[2]) + string(m[3])
		}
	}
	if defaultMarkerRE.Match(body) {
		out.HasDefaultMarker = true
	}
	if provincialDefaultMarkerRE.Match(body) {
		out.HasProvDefaultMarker = true
	}
	return out
}

// decimalToCents parses positive decimal to cents.
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

// decimalToPct parses a percent number; clamps to [0, 100].
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
