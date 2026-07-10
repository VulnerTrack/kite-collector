package winargallaria

import (
	"bufio"
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// AllariaFields captures scalar fields the audit pipeline
// needs from an Allaria artifact.
type AllariaFields struct {
	BearerToken           string
	Username              string
	ClienteCuitRaw        string
	BrokerMatricula       string
	DistinctSymbols       int64
	PortfolioAUMUSDCents  int64
	BlockTradeCount       int64
	BlockTradeMaxUSDCents int64
	FCICustodyReconCount  int64
	PensionFundCount      int64
	InsuranceCount        int64
	CERUVAPositionCount   int64
	LetrasPositionCount   int64
	HasPassword           bool
}

// bearerRE matches an access-token / bearer in INI / JSON form.
var bearerRE = regexp.MustCompile(
	`(?i)("|')?(?:access[_-]?token|bearer|api[_-]?token|jwt|allaria[_-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{20,})`,
)

// bearerXMLRE matches XML-tag form `<access_token>val</...>`.
var bearerXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:access[_\-]?token|bearer|api[_\-]?token|jwt|allaria[_\-]?token)\s*>([A-Za-z0-9_\-\.\+/=]{20,})`,
)

// bearerFromBody extracts a bearer token from either form.
func bearerFromBody(body []byte) string {
	if m := bearerRE.FindSubmatch(body); len(m) > 3 {
		return string(m[3])
	}
	if m := bearerXMLRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// usernameRE matches `username` / `user` / `email` in INI/JSON.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:username|user|email|usuario)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// usernameXMLRE matches `<username>val</username>` form.
var usernameXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:username|user|email|usuario)\s*>([A-Za-z0-9_.@\-]{3,80})<`,
)

// usernameFromBody extracts a username from either form.
func usernameFromBody(body []byte) string {
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	if m := usernameXMLRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// passwordRE matches a password row (line-anchored INI/JSON).
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|clave|pass|passwd)"?\s*[:=]\s*\S+`,
)

// passwordXMLRE matches `<password>…</password>`.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|clave)\s*>[^<\n]{1,}<\s*/\s*(?:password|clave)\s*>`,
)

// blockTradeMarkerRE detects block-trade markers.
var blockTradeMarkerRE = regexp.MustCompile(
	`(?i)(?:block[_\- ]?trade|bloque[_\- ]?cruzado|cross[_\- ]?bloque|off[_\- ]?book|pre[_\- ]?arranged|agreed[_\- ]?cross|negociacion[_\- ]?previa)`,
)

// custodyReconMarkerRE detects FCI custody-reconciliation markers.
var custodyReconMarkerRE = regexp.MustCompile(
	`(?i)(?:custody[_\- ]?recon|custody[_\- ]?reconciliation|custodia[_\- ]?conciliacion|sociedad[_\- ]?depositaria|depositary[_\- ]?bank|recon[_\- ]?cuotapartes)`,
)

// pensionMarkerRE detects ANSeS / FCAA pension-fund markers.
var pensionMarkerRE = regexp.MustCompile(
	`(?i)(?:anses|fcaa|fondo[_\- ]?garantia[_\- ]?sustentabilidad|fgs|pension[_\- ]?fund|fondo[_\- ]?previsional)`,
)

// insuranceMarkerRE detects SSN / insurance markers.
var insuranceMarkerRE = regexp.MustCompile(
	`(?i)(?:ssn|superintendencia[_\- ]?seguros|aseguradora|insurance[_\- ]?company|cobertura[_\- ]?seguro|resol[_\- ]?38708)`,
)

// symbolEntryRE matches a JSON/INI symbol entry.
var symbolEntryRE = regexp.MustCompile(
	`(?i)"?(?:symbol|simbolo|s[ií]mbolo|ticker|especie|instrumento)"?\s*[:=]\s*"?([A-Za-z0-9_\-\./]{2,32})`,
)

// symbolXMLRE matches `<symbol>val</symbol>` form.
var symbolXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:symbol|simbolo|ticker|especie|instrumento)\s*>([A-Za-z0-9_\-\./]{2,32})<\s*/\s*(?:symbol|simbolo|ticker|especie|instrumento)\s*>`,
)

// notionalUSDRE matches USD-denominated amounts.
var notionalUSDRE = regexp.MustCompile(
	`(?i)(?:notional[_\- ]?usd|usd[_\- ]?amount|importe[_\- ]?usd|monto[_\- ]?usd|valor[_\- ]?usd|valor_mercado_usd|market_value_usd|aum_usd|block[_\- ]?usd)"?\s*[:=]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`,
)

// blockTradeEntryRE matches a per-row block-trade entry.
var blockTradeEntryRE = regexp.MustCompile(
	`(?i)(?:block_id|trade_id|bloque_id|operacion_id)`,
)

// reconEntryRE matches a per-row custody-recon entry.
var reconEntryRE = regexp.MustCompile(
	`(?i)(?:recon_id|conciliacion_id|custodia_id|cuota_parte_id|fci_id)`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// clienteCuitXMLRE matches `<cliente_cuit>…</cliente_cuit>`.
var clienteCuitXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:cliente[_\-]?cuit|cuit[_\-]?cliente|titular[_\-]?cuit|cuit)\s*>(\d{2}-?\d{8}-?\d)`,
)

// ParseAllariaCredentials parses a credentials / config body.
func ParseAllariaCredentials(body []byte) AllariaFields {
	var out AllariaFields
	if len(body) == 0 {
		return out
	}
	if passwordXMLRE.Match(body) || passwordRE.Match(body) {
		out.HasPassword = true
	}
	if t := bearerFromBody(body); t != "" {
		out.BearerToken = t
	}
	if u := usernameFromBody(body); u != "" {
		out.Username = u
	}
	out.ClienteCuitRaw = cuitFromBody(body)
	out.BrokerMatricula = MatriculaFromText(string(body))
	return out
}

// ParseAllariaPositions parses a positions cache.
func ParseAllariaPositions(body []byte) AllariaFields {
	var out AllariaFields
	if len(body) == 0 {
		return out
	}
	syms := collectSymbols(body)
	out.DistinctSymbols = int64(len(syms))
	out.CERUVAPositionCount = countCERUVA(syms)
	out.LetrasPositionCount = countLetras(syms)
	out.PortfolioAUMUSDCents = sumUSDAmounts(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseAllariaOrders parses an orders cache.
func ParseAllariaOrders(body []byte) AllariaFields {
	return ParseAllariaPositions(body)
}

// ParseAllariaBlockTrade parses a block-trade book.
func ParseAllariaBlockTrade(body []byte) AllariaFields {
	var out AllariaFields
	if len(body) == 0 {
		return out
	}
	out.BlockTradeCount = countBlockTradesCSVAware(body)
	out.BlockTradeMaxUSDCents = maxUSDAmount(body)
	out.PortfolioAUMUSDCents = sumUSDAmounts(body)
	syms := collectSymbols(body)
	out.DistinctSymbols = int64(len(syms))
	out.CERUVAPositionCount = countCERUVA(syms)
	out.LetrasPositionCount = countLetras(syms)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseAllariaCustodyReport parses a daily custody report.
func ParseAllariaCustodyReport(body []byte) AllariaFields {
	var out AllariaFields
	if len(body) == 0 {
		return out
	}
	syms := collectSymbols(body)
	out.DistinctSymbols = int64(len(syms))
	out.CERUVAPositionCount = countCERUVA(syms)
	out.LetrasPositionCount = countLetras(syms)
	out.PortfolioAUMUSDCents = sumUSDAmounts(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	out.BrokerMatricula = MatriculaFromText(string(body))
	return out
}

// ParseAllariaCustodyRecon parses an FCI custody reconciliation.
func ParseAllariaCustodyRecon(body []byte) AllariaFields {
	var out AllariaFields
	if len(body) == 0 {
		return out
	}
	out.FCICustodyReconCount = int64(len(reconEntryRE.FindAllIndex(body, -1)))
	if out.FCICustodyReconCount == 0 && custodyReconMarkerRE.Match(body) {
		out.FCICustodyReconCount = 1
	}
	syms := collectSymbols(body)
	out.DistinctSymbols = int64(len(syms))
	out.CERUVAPositionCount = countCERUVA(syms)
	out.LetrasPositionCount = countLetras(syms)
	out.PortfolioAUMUSDCents = sumUSDAmounts(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseAllariaANSeSFlows parses an ANSeS / FCAA counterparty
// flows file. ANSeS flow files don't always use a `symbol:`
// key — letras stems appear as bare tokens in the body.
func ParseAllariaANSeSFlows(body []byte) AllariaFields {
	var out AllariaFields
	if len(body) == 0 {
		return out
	}
	out.PensionFundCount = max64(1,
		int64(len(pensionMarkerRE.FindAllIndex(body, -1))))
	out.PortfolioAUMUSDCents = sumUSDAmounts(body)
	syms := collectSymbols(body)
	out.LetrasPositionCount = countLetras(syms)
	if out.LetrasPositionCount == 0 {
		out.LetrasPositionCount = scanLetrasPresence(body)
	}
	out.CERUVAPositionCount = countCERUVA(syms)
	if out.CERUVAPositionCount == 0 {
		out.CERUVAPositionCount = scanCERUVAPresence(body)
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseAllariaSSNHoldings parses an insurance / SSN holdings
// file. Similar to ANSeS, letras stems may appear as XML-tag
// or bare-token values.
func ParseAllariaSSNHoldings(body []byte) AllariaFields {
	var out AllariaFields
	if len(body) == 0 {
		return out
	}
	out.InsuranceCount = max64(1,
		int64(len(insuranceMarkerRE.FindAllIndex(body, -1))))
	out.PortfolioAUMUSDCents = sumUSDAmounts(body)
	syms := collectSymbols(body)
	out.LetrasPositionCount = countLetras(syms)
	if out.LetrasPositionCount == 0 {
		out.LetrasPositionCount = scanLetrasPresence(body)
	}
	out.CERUVAPositionCount = countCERUVA(syms)
	if out.CERUVAPositionCount == 0 {
		out.CERUVAPositionCount = scanCERUVAPresence(body)
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// cuitFromBody runs the key and XML form variants.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	if m := clienteCuitXMLRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// collectSymbols returns distinct uppercase symbols seen via
// JSON / INI / XML forms.
func collectSymbols(body []byte) []string {
	seen := map[string]struct{}{}
	for _, m := range symbolEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	for _, m := range symbolXMLRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// scanLetrasPresence returns the count of distinct curated
// Letras stems found anywhere in body (used for ANSeS / SSN
// files that don't use a `symbol:` key but do mention LECAP /
// BONCER / AL30 etc. as bare tokens).
func scanLetrasPresence(body []byte) int64 {
	seen := map[string]struct{}{}
	up := strings.ToUpper(string(body))
	for _, sym := range LetrasSymbols() {
		if strings.Contains(up, sym) {
			seen[sym] = struct{}{}
		}
	}
	return int64(len(seen))
}

// scanCERUVAPresence returns the count of distinct CER/UVA
// stems found anywhere in body.
func scanCERUVAPresence(body []byte) int64 {
	seen := map[string]struct{}{}
	up := strings.ToUpper(string(body))
	for _, sym := range CERUVASymbols() {
		if strings.Contains(up, sym) {
			seen[sym] = struct{}{}
		}
	}
	return int64(len(seen))
}

// countCERUVA returns the count of CER/UVA inflation-linked
// symbols.
func countCERUVA(syms []string) int64 {
	var n int64
	for _, s := range syms {
		if IsCERUVASymbol(s) {
			n++
		}
	}
	return n
}

// countLetras returns the count of LECAP / BONCER / sovereign
// short-term debt symbols.
func countLetras(syms []string) int64 {
	var n int64
	for _, s := range syms {
		if IsLetraSymbol(s) {
			n++
		}
	}
	return n
}

// countBlockTradesCSVAware counts CSV data rows when body looks
// like a CSV with a recognizable block-trade header; falls back
// to regex marker count.
func countBlockTradesCSVAware(body []byte) int64 {
	if csv := csvDataRowCount(body); csv > 0 {
		return csv
	}
	n := int64(len(blockTradeEntryRE.FindAllIndex(body, -1)))
	if n == 0 && blockTradeMarkerRE.Match(body) {
		return 1
	}
	return n
}

// csvDataRowCount returns the number of non-empty data rows
// (lines after the header) when body looks like a CSV.
func csvDataRowCount(body []byte) int64 {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	if !scanner.Scan() {
		return 0
	}
	header := scanner.Text()
	delim := ""
	for _, d := range []string{",", ";", "\t", "|"} {
		if strings.Count(header, d) >= 1 {
			delim = d
			break
		}
	}
	if delim == "" {
		return 0
	}
	cols := strings.Split(header, delim)
	if len(cols) < 2 {
		return 0
	}
	// Detect block-trade-shaped header.
	hl := strings.ToLower(header)
	if !strings.Contains(hl, "block") && !strings.Contains(hl, "bloque") &&
		!strings.Contains(hl, "trade") {
		return 0
	}
	var n int64
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		n++
	}
	return n
}

// sumUSDAmounts sums all USD-amount rows in body. CSV-aware
// path takes priority when body has a `notional_usd` (or
// similar) column header.
func sumUSDAmounts(body []byte) int64 {
	if total, _ := sumUSDAmountsCSV(body); total > 0 {
		return total
	}
	var total int64
	for _, m := range notionalUSDRE.FindAllSubmatch(body, -1) {
		if c := decimalToCents(string(m[1])); c > 0 {
			total += c
		}
	}
	return total
}

// maxUSDAmount returns the largest single USD-amount row.
func maxUSDAmount(body []byte) int64 {
	if _, peak := sumUSDAmountsCSV(body); peak > 0 {
		return peak
	}
	var peak int64
	for _, m := range notionalUSDRE.FindAllSubmatch(body, -1) {
		if c := decimalToCents(string(m[1])); c > peak {
			peak = c
		}
	}
	return peak
}

// sumUSDAmountsCSV detects a `notional_usd` / `usd_amount` /
// `importe_usd` column in a CSV header and returns (total,
// peak) of column values. Returns (0, 0) when body isn't CSV-
// shaped or no recognizable column is present.
func sumUSDAmountsCSV(body []byte) (total, peak int64) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	if !scanner.Scan() {
		return 0, 0
	}
	header := scanner.Text()
	delim := ""
	for _, d := range []string{",", ";", "\t", "|"} {
		if strings.Count(header, d) >= 1 {
			delim = d
			break
		}
	}
	if delim == "" {
		return 0, 0
	}
	cols := strings.Split(header, delim)
	if len(cols) < 2 {
		return 0, 0
	}
	idx := -1
	for i, c := range cols {
		hl := strings.ToLower(strings.TrimSpace(c))
		switch hl {
		case "notional_usd", "notional-usd", "usd_amount", "usd-amount",
			"importe_usd", "monto_usd", "amount_usd", "valor_usd",
			"market_value_usd", "aum_usd", "notional", "importe",
			"monto", "valor", "amount":
			idx = i
		}
		if idx >= 0 {
			break
		}
	}
	if idx < 0 {
		return 0, 0
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		row := strings.Split(line, delim)
		if idx >= len(row) {
			continue
		}
		c := decimalToCents(row[idx])
		if c <= 0 {
			continue
		}
		total += c
		if c > peak {
			peak = c
		}
	}
	return total, peak
}

// decimalToCents parses "1.234,56" or "1234.56" to cents.
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

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
