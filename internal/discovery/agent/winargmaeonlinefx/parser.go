package winargmaeonlinefx

import (
	"bufio"
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// MAEFXFields captures scalar fields the audit pipeline needs
// from a MAE OnlineFX artifact.
type MAEFXFields struct {
	ParticipantID          string
	ClienteCuitRaw         string
	FIXSenderCompID        string
	FIXTargetCompID        string
	SessionFirstSeen       string
	SessionLastSeen        string
	TradeCount             int64
	SpotCount              int64
	ForwardCount           int64
	NDFCount               int64
	USDTCount              int64
	BRLCount               int64
	EURCount               int64
	TotalVolumeUSDCents    int64
	AboveCapCount          int64
	DistinctCounterparties int64
	HasPassword            bool
	HasFIXDropCopy         bool
}

// passwordRE matches a password row (line-anchored INI/JSON/XML).
var passwordRE = regexp.MustCompile(
	`(?im)^\s*(?:<\s*)?"?(?:password|clave|pass|passwd)"?\s*(?:[:=>]|>)\s*\S+`)

// passwordXMLRE matches `<password>…</password>` on a single line.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|clave)\s*>[^<\n]{1,}<\s*/\s*(?:password|clave)\s*>`)

// fixDropCopyRE detects FIX 4.x drop-copy session markers.
var fixDropCopyRE = regexp.MustCompile(
	`(?i)(?:8=FIX\.4\.[24]|8=FIXT\.1\.1|drop[_\- ]?copy|DropCopySession|TargetSubID=DROP|10010=DROP|TradeCaptureReport)`)

// fixSenderRE matches FIX SenderCompID.
var fixSenderRE = regexp.MustCompile(
	`(?i)(?:49=|SenderCompID["'\s:=]+)([A-Z0-9_\-\.]{2,32})`)

// fixTargetRE matches FIX TargetCompID.
var fixTargetRE = regexp.MustCompile(
	`(?i)(?:56=|TargetCompID["'\s:=]+)([A-Z0-9_\-\.]{2,32})`)

// timestampRE matches `YYYY-MM-DD HH:MM[:SS]`.
var timestampRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`)

// tradeEventRE matches a per-row trade marker.
var tradeEventRE = regexp.MustCompile(
	`(?i)(?:trade_id|trade[_\- ]?id|operacion_id|operacion[_\- ]?id|deal[_\- ]?id|ticket[_\- ]?id|nro[_\- ]?operacion)`)

// usdAmountRE captures a USD-denominated amount row.
var usdAmountRE = regexp.MustCompile(
	`(?i)(?:notional[_\- ]?usd|usd[_\- ]?amount|amount[_\- ]?usd|importe[_\- ]?usd|monto[_\- ]?usd|notional|importe|monto)"?\s*[:=]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit|counterparty[_\- ]?cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// clienteCuitXMLRE matches `<cliente_cuit>…</cliente_cuit>`.
var clienteCuitXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:cliente[_\-]?cuit|cuit[_\-]?cliente|titular[_\-]?cuit|cuit|counterparty[_\-]?cuit)\s*>(\d{2}-?\d{8}-?\d)`)

// ParseMAEFXCredentials parses a config / credentials body.
func ParseMAEFXCredentials(body []byte) MAEFXFields {
	var out MAEFXFields
	if len(body) == 0 {
		return out
	}
	if passwordXMLRE.Match(body) || passwordRE.Match(body) {
		out.HasPassword = true
	}
	out.ParticipantID = ParticipantIDFromText(string(body))
	out.ClienteCuitRaw = cuitFromBody(body)
	return out
}

// ParseMAEFXQuotesCache parses an FX quotes cache.
func ParseMAEFXQuotesCache(body []byte) MAEFXFields {
	var out MAEFXFields
	if len(body) == 0 {
		return out
	}
	out.SpotCount, out.ForwardCount, out.NDFCount,
		out.USDTCount, out.BRLCount, out.EURCount = countTradeRowsPerProduct(body)
	out.TradeCount = out.SpotCount + out.ForwardCount + out.NDFCount +
		out.USDTCount + out.BRLCount + out.EURCount
	out.TotalVolumeUSDCents = sumUSDAmounts(body)
	out.AboveCapCount = countAboveCapTrades(body)
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	out.ParticipantID = ParticipantIDFromText(string(body))
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseMAEFXTradeBlotter parses a trade blotter file.
func ParseMAEFXTradeBlotter(body []byte) MAEFXFields {
	out := ParseMAEFXQuotesCache(body)
	if out.TradeCount == 0 {
		out.TradeCount = int64(len(tradeEventRE.FindAllIndex(body, -1)))
	}
	return out
}

// ParseMAEFXForwardBook parses a forward-book file. CSV
// shape is common (one row per fwd contract); fall back to
// per-row CSV count when the trade-event regex matches only
// the header.
func ParseMAEFXForwardBook(body []byte) MAEFXFields {
	var out MAEFXFields
	if len(body) == 0 {
		return out
	}
	if csv := csvDataRowCount(body); csv > 0 {
		out.ForwardCount = csv
	} else {
		out.ForwardCount = int64(len(tradeEventRE.FindAllIndex(body, -1)))
		if out.ForwardCount == 0 && HasUSDARSForwardMarker(body) {
			out.ForwardCount = 1
		}
	}
	out.TotalVolumeUSDCents = sumUSDAmounts(body)
	out.AboveCapCount = countAboveCapTrades(body)
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
	out.ParticipantID = ParticipantIDFromText(string(body))
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseMAEFXNDFBook parses an NDF-book file. CSV-aware.
func ParseMAEFXNDFBook(body []byte) MAEFXFields {
	var out MAEFXFields
	if len(body) == 0 {
		return out
	}
	if csv := csvDataRowCount(body); csv > 0 {
		out.NDFCount = csv
	} else {
		out.NDFCount = int64(len(tradeEventRE.FindAllIndex(body, -1)))
		if out.NDFCount == 0 && HasUSDARSNDFMarker(body) {
			out.NDFCount = 1
		}
	}
	out.TotalVolumeUSDCents = sumUSDAmounts(body)
	out.AboveCapCount = countAboveCapTrades(body)
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
	out.ParticipantID = ParticipantIDFromText(string(body))
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseMAEFXUSDTBook parses a USDT/ARS book file. CSV-aware.
func ParseMAEFXUSDTBook(body []byte) MAEFXFields {
	var out MAEFXFields
	if len(body) == 0 {
		return out
	}
	if csv := csvDataRowCount(body); csv > 0 {
		out.USDTCount = csv
	} else {
		out.USDTCount = int64(len(tradeEventRE.FindAllIndex(body, -1)))
		if out.USDTCount == 0 && HasUSDTARSMarker(body) {
			out.USDTCount = 1
		}
	}
	out.TotalVolumeUSDCents = sumUSDAmounts(body)
	out.AboveCapCount = countAboveCapTrades(body)
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
	out.ParticipantID = ParticipantIDFromText(string(body))
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseMAEFXFIXDropCopy parses a FIX drop-copy log.
func ParseMAEFXFIXDropCopy(body []byte) MAEFXFields {
	var out MAEFXFields
	if len(body) == 0 {
		return out
	}
	if fixDropCopyRE.Match(body) {
		out.HasFIXDropCopy = true
	}
	if m := fixSenderRE.FindSubmatch(body); len(m) > 1 {
		out.FIXSenderCompID = string(m[1])
	}
	if m := fixTargetRE.FindSubmatch(body); len(m) > 1 {
		out.FIXTargetCompID = string(m[1])
	}
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	out.SpotCount, out.ForwardCount, out.NDFCount,
		out.USDTCount, out.BRLCount, out.EURCount = countTradeRowsPerProduct(body)
	out.TradeCount = out.SpotCount + out.ForwardCount + out.NDFCount +
		out.USDTCount + out.BRLCount + out.EURCount
	out.TotalVolumeUSDCents = sumUSDAmounts(body)
	out.AboveCapCount = countAboveCapTrades(body)
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
	return out
}

// ParseMAEFXSessionLog parses a terminal session log.
func ParseMAEFXSessionLog(body []byte) MAEFXFields {
	var out MAEFXFields
	if len(body) == 0 {
		return out
	}
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	out.ParticipantID = ParticipantIDFromText(string(body))
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

// countTradeRowsPerProduct walks body line-by-line and counts
// trade rows per FX product, classifying each row by its
// currency-pair marker.
func countTradeRowsPerProduct(body []byte) (spot, fwd, ndf, usdt, brl, eur int64) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if !tradeEventRE.Match(line) {
			continue
		}
		switch {
		case HasUSDARSNDFMarker(line):
			ndf++
		case HasUSDARSForwardMarker(line):
			fwd++
		case HasUSDTARSMarker(line):
			usdt++
		case HasBRLARSMarker(line):
			brl++
		case HasEURARSMarker(line):
			eur++
		case HasUSDARSSpotMarker(line):
			spot++
		}
	}
	return spot, fwd, ndf, usdt, brl, eur
}

// sumUSDAmounts sums all USD-amount rows in body. Tries the
// CSV column-aware sum first (header detection + per-row
// column extract), then falls back to the `key=value` regex.
func sumUSDAmounts(body []byte) int64 {
	if csv := sumUSDAmountsCSV(body); csv > 0 {
		return csv
	}
	var total int64
	for _, m := range usdAmountRE.FindAllSubmatch(body, -1) {
		if c := decimalToCents(string(m[1])); c > 0 {
			total += c
		}
	}
	return total
}

// sumUSDAmountsCSV detects a notional / amount column in a
// CSV header + sums values from that column. Returns 0 when
// the body isn't CSV-shaped or no recognizable column is
// present.
func sumUSDAmountsCSV(body []byte) int64 {
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
	idx := -1
	for i, c := range cols {
		hl := strings.ToLower(strings.TrimSpace(c))
		switch hl {
		case "notional_usd", "notional-usd", "usd_amount", "usd-amount",
			"importe_usd", "monto_usd", "amount_usd", "notional", "importe",
			"monto", "valor", "amount":
			idx = i
		}
		if idx >= 0 {
			break
		}
	}
	if idx < 0 {
		return 0
	}
	var total int64
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		row := strings.Split(line, delim)
		if idx >= len(row) {
			continue
		}
		if c := decimalToCents(row[idx]); c > 0 {
			total += c
		}
	}
	return total
}

// csvDataRowCount returns the number of non-empty data rows
// (lines after the header) when body looks like a CSV with
// `,` / `;` / `\t` / `|` delimiters. Returns 0 when the body
// isn't CSV-shaped (no delimiter on first line, <2 columns).
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
	var n int64
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		n++
	}
	return n
}

// countAboveCapTrades counts USD-amount rows above the BCRA
// Com. A 7916 natural-person monthly cap.
func countAboveCapTrades(body []byte) int64 {
	var n int64
	for _, m := range usdAmountRE.FindAllSubmatch(body, -1) {
		if c := decimalToCents(string(m[1])); c >= BCRAIndividualCapUSDCents {
			n++
		}
	}
	return n
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
