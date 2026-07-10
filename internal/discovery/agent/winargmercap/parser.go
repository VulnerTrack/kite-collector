package winargmercap

import (
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// MercapFields captures scalar fields the audit pipeline
// needs from a Mercap artifact.
type MercapFields struct {
	BrokerMatricula         string
	ClienteCuitRaw          string
	CuentaComitenteID       string
	KYCLastReviewDate       string
	Period                  string
	SaldoCents              int64
	TotalSettlementCents    int64
	MaxSettlementDays       int
	CommissionPctMax        int
	ReconciliationDiffCents int64
}

// saldoRE matches `saldo: <signed-decimal>` rows.
var saldoRE = regexp.MustCompile(
	`(?i)("|')?(saldo|saldo[_\- ]?cliente|balance|saldo[_\- ]?cuenta)("|')?\s*[:=>]\s*"?(-?[0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`,
)

// settleDaysRE matches `T+N` settlement-day markers.
var settleDaysRE = regexp.MustCompile(
	`(?i)\bT\+([0-9]{1,2})\b`,
)

// commissionRE matches `comision: NN.NN%` / `commission_pct=NN`.
var commissionRE = regexp.MustCompile(
	`(?i)("|')?(comisi[oó]n|commission|fee)([_\- ]?pct)?("|')?\s*[:=>]\s*"?([0-9]+(?:[.,][0-9]+)?)\s*%?`,
)

// commissionAmountRE matches `commission_amount=NN` AND trade
// notional for ratio computation. Used as secondary signal.
var commissionAmountRE = regexp.MustCompile(
	`(?i)("|')?(commission[_\- ]?amount|comision[_\- ]?monto)("|')?\s*[:=>]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`,
)

// notionalRE matches a trade notional row.
var notionalRE = regexp.MustCompile(
	`(?i)("|')?(importe|monto|valor|nominal|notional|total)("|')?\s*[:=>]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`,
)

// reconciliationDiffRE matches `diferencia_cvsa: <signed>`.
var reconciliationDiffRE = regexp.MustCompile(
	`(?i)("|')?(diferencia[_\- ]?cvsa|reconciliation[_\- ]?diff|mismatch[_\- ]?amount|delta_cvsa)("|')?\s*[:=>]\s*"?(-?[0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`,
)

// kycReviewDateRE matches `kyc_last_review_date: YYYY-MM-DD`.
var kycReviewDateRE = regexp.MustCompile(
	`(?i)("|')?(kyc[_\- ]?last[_\- ]?review[_\- ]?date|fecha[_\- ]?revision[_\- ]?kyc|ultima[_\- ]?revision[_\- ]?kyc)("|')?\s*[:=>]\s*"?(20\d{2}-\d{2}-\d{2})`,
)

// matriculaIniRE matches `BrokerMatricula=NNN` / `Matricula=NNN`
// in INI / JSON / YAML bodies (line-anchored).
var matriculaIniRE = regexp.MustCompile(
	`(?im)^\s*"?(?:Matricula|BrokerMatricula|MatriculaBroker|Alyc[_\- ]?Matricula)"?\s*[:=>]\s*"?(\d{1,5})"?`,
)

// matriculaXMLRE matches `<matricula>NNN</matricula>` so XML
// bodies don't need a separate parser.
var matriculaXMLRE = regexp.MustCompile(
	`(?i)<(?:matricula|broker_matricula|matricula_broker)>(\d{1,5})</`,
)

// cuentaKeyRE matches `cuenta_comitente: NNNNN`.
var cuentaKeyRE = regexp.MustCompile(
	`(?i)("|')?(cuenta[_\- ]?comitente|cuenta[_\- ]?id|account[_\- ]?id|comitente)("|')?\s*[:=>]\s*"?(\d{4,12})"?`,
)

// clienteCuitKeyRE matches a labeled cliente CUIT.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseMercapArtifact parses a Mercap body (XML / CSV / JSON /
// INI) and extracts scalar fields.
//
// We use flat regex scans rather than format-specific parsers
// — Mercap exports come in multiple formats and the same keys
// appear across forms.
func ParseMercapArtifact(body []byte) MercapFields {
	var out MercapFields
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	// Saldo cliente (signed) — INI / JSON / XML key-value form.
	if m := saldoRE.FindSubmatch(body); len(m) > 4 {
		out.SaldoCents = decimalToCentsSigned(string(m[4]))
	}
	// CSV-aware fallback: header column named `saldo*` whose
	// per-row value can be negative.
	if out.SaldoCents == 0 {
		if s := parseSaldoFromCSV(body); s != 0 {
			out.SaldoCents = s
		}
	}
	// Max settlement days from T+N markers.
	for _, m := range settleDaysRE.FindAllSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		n, err := strconv.Atoi(string(m[1]))
		if err != nil {
			continue
		}
		if n > out.MaxSettlementDays {
			out.MaxSettlementDays = n
		}
	}
	// Commission pct max — direct % keys (INI/JSON form).
	for _, m := range commissionRE.FindAllSubmatch(body, -1) {
		if len(m) < 6 {
			continue
		}
		pct := decimalToPct(string(m[5]))
		if pct > out.CommissionPctMax {
			out.CommissionPctMax = pct
		}
	}
	// CSV-aware fallback for `comision_pct` / `commission_pct`
	// column.
	if csvPct := parseCommissionFromCSV(body); csvPct > out.CommissionPctMax {
		out.CommissionPctMax = csvPct
	}
	// Commission pct max — ratio of commission_amount/notional.
	commission, notional := commissionAmountMatches(body), notionalMatches(body)
	if commission > 0 && notional > 0 {
		pct := int(math.Round(float64(commission) * 100 / float64(notional)))
		if pct > out.CommissionPctMax {
			out.CommissionPctMax = pct
		}
		out.TotalSettlementCents = notional
	}
	// Reconciliation diff (CVSA mismatch).
	if m := reconciliationDiffRE.FindSubmatch(body); len(m) > 4 {
		out.ReconciliationDiffCents = decimalToCentsSigned(string(m[4]))
	}
	// KYC review date.
	if m := kycReviewDateRE.FindSubmatch(body); len(m) > 4 {
		out.KYCLastReviewDate = string(m[4])
	}
	// Broker matrícula — INI/JSON form first, then XML form.
	if m := matriculaIniRE.FindSubmatch(body); m != nil {
		out.BrokerMatricula = string(m[1])
	}
	if out.BrokerMatricula == "" {
		if m := matriculaXMLRE.FindSubmatch(body); m != nil {
			out.BrokerMatricula = string(m[1])
		}
	}
	// Cuenta comitente.
	if m := cuentaKeyRE.FindSubmatch(body); len(m) > 4 {
		out.CuentaComitenteID = string(m[4])
	}
	// Cliente CUIT.
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	if out.ClienteCuitRaw == "" {
		if m := cuitRE.FindSubmatch(body); m != nil {
			out.ClienteCuitRaw = string(m[1]) + string(m[2]) + string(m[3])
		}
	}
	return out
}

// commissionAmountMatches returns the largest commission-
// amount value found in the body, in cents.
func commissionAmountMatches(body []byte) int64 {
	var max int64
	for _, m := range commissionAmountRE.FindAllSubmatch(body, -1) {
		if len(m) < 5 {
			continue
		}
		c := decimalToCents(string(m[4]))
		if c > max {
			max = c
		}
	}
	return max
}

// notionalMatches returns the largest notional value found in
// the body, in cents.
func notionalMatches(body []byte) int64 {
	var max int64
	for _, m := range notionalRE.FindAllSubmatch(body, -1) {
		if len(m) < 5 {
			continue
		}
		c := decimalToCents(string(m[4]))
		if c > max {
			max = c
		}
	}
	return max
}

// parseSaldoFromCSV scans a CSV/TSV body for a saldo* column
// and returns the most-negative balance found (so the
// negative-balance signal trips). When no negative is present,
// returns the largest positive value.
func parseSaldoFromCSV(body []byte) int64 {
	lines := bytes.Split(body, []byte("\n"))
	if len(lines) < 2 {
		return 0
	}
	headerIdx := -1
	var delim byte
	for i, raw := range lines {
		line := bytes.TrimSpace(raw)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		lower := bytes.ToLower(line)
		if !bytes.Contains(lower, []byte("saldo")) {
			continue
		}
		headerIdx = i
		delim = inferDelim(line)
		break
	}
	if headerIdx < 0 || delim == 0 {
		return 0
	}
	cols := bytes.Split(bytes.TrimSpace(lines[headerIdx]), []byte{delim})
	saldoCol := -1
	for c, raw := range cols {
		col := bytes.ToLower(bytes.TrimSpace(raw))
		if bytes.Equal(col, []byte("saldo")) ||
			bytes.HasPrefix(col, []byte("saldo_")) ||
			bytes.HasPrefix(col, []byte("saldo-")) ||
			bytes.Equal(col, []byte("balance")) {
			saldoCol = c
			break
		}
	}
	if saldoCol < 0 {
		return 0
	}
	var minSeen int64 = 0
	var maxSeen int64 = 0
	for i := headerIdx + 1; i < len(lines); i++ {
		row := bytes.TrimSpace(lines[i])
		if len(row) == 0 || row[0] == '#' {
			continue
		}
		cells := bytes.Split(row, []byte{delim})
		if saldoCol >= len(cells) {
			continue
		}
		val := strings.TrimSpace(string(cells[saldoCol]))
		c := decimalToCentsSigned(val)
		if c < minSeen {
			minSeen = c
		}
		if c > maxSeen {
			maxSeen = c
		}
	}
	if minSeen < 0 {
		return minSeen
	}
	return maxSeen
}

// parseCommissionFromCSV scans a CSV/TSV body for a commission
// pct column and returns the largest pct value found.
func parseCommissionFromCSV(body []byte) int {
	lines := bytes.Split(body, []byte("\n"))
	if len(lines) < 2 {
		return 0
	}
	headerIdx := -1
	var delim byte
	for i, raw := range lines {
		line := bytes.TrimSpace(raw)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		lower := bytes.ToLower(line)
		if !bytes.Contains(lower, []byte("comision")) &&
			!bytes.Contains(lower, []byte("commission")) {
			continue
		}
		headerIdx = i
		delim = inferDelim(line)
		break
	}
	if headerIdx < 0 || delim == 0 {
		return 0
	}
	cols := bytes.Split(bytes.TrimSpace(lines[headerIdx]), []byte{delim})
	pctCol := -1
	for c, raw := range cols {
		col := bytes.ToLower(bytes.TrimSpace(raw))
		if bytes.Contains(col, []byte("comision")) ||
			bytes.Contains(col, []byte("commission")) {
			pctCol = c
			break
		}
	}
	if pctCol < 0 {
		return 0
	}
	max := 0
	for i := headerIdx + 1; i < len(lines); i++ {
		row := bytes.TrimSpace(lines[i])
		if len(row) == 0 || row[0] == '#' {
			continue
		}
		cells := bytes.Split(row, []byte{delim})
		if pctCol >= len(cells) {
			continue
		}
		val := strings.TrimSpace(string(cells[pctCol]))
		if p := decimalToPct(val); p > max {
			max = p
		}
	}
	return max
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
// Accepts integer / float / `0.05` ratio form.
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
