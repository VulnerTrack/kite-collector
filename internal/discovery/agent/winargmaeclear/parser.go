package winargmaeclear

import (
	"bufio"
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// MAEClearFields captures scalar fields the audit pipeline
// needs from a MAEclear artifact.
type MAEClearFields struct {
	ParticipantID          string
	ClienteCuitRaw         string
	FIXSenderCompID        string
	FIXTargetCompID        string
	SessionFirstSeen       string
	SessionLastSeen        string
	SettlementCount        int64
	SettlementFailCount    int64
	AffirmationCount       int64
	RepoCount              int64
	RepoMaxTenorDays       int64
	LeliqSettlementCount   int64
	SovereignOTCCount      int64
	FXForwardCount         int64
	TotalVolumeCents       int64
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
	`(?i)(?:8=FIX\.4\.[24]|8=FIXT\.1\.1|drop[_\- ]?copy|DropCopySession|TargetSubID=DROP|10010=DROP)`)

// fixSenderRE matches FIX SenderCompID.
var fixSenderRE = regexp.MustCompile(
	`(?i)(?:49=|SenderCompID["'\s:=]+)([A-Z0-9_\-\.]{2,32})`)

// fixTargetRE matches FIX TargetCompID.
var fixTargetRE = regexp.MustCompile(
	`(?i)(?:56=|TargetCompID["'\s:=]+)([A-Z0-9_\-\.]{2,32})`)

// timestampRE matches `YYYY-MM-DD HH:MM[:SS]`.
var timestampRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`)

// settlementEventRE matches a settlement entry.
var settlementEventRE = regexp.MustCompile(
	`(?i)(?:settlement[_\- ]?id|liquidacion[_\- ]?id|settle[_\- ]?entry|trade[_\- ]?settle|venta[_\- ]?neta|compra[_\- ]?neta)`)

// settlementFailRE matches a failed settlement event.
var settlementFailRE = regexp.MustCompile(
	`(?i)(?:settlement[_\- ]?fail|settle[_\- ]?fail|fail[_\- ]?to[_\- ]?deliver|fail[_\- ]?to[_\- ]?receive|liquidacion[_\- ]?fallida|FTR|FTD|failed[_\- ]?settle)`)

// affirmationEventRE matches an affirmation entry.
var affirmationEventRE = regexp.MustCompile(
	`(?i)(?:afirmacion|afirmaci[oó]n|affirmation|bilateral[_\- ]?confirm|confirm[_\- ]?bilateral|confirmed[_\- ]?bilateral)`)

// repoEntryRE matches a REPO row.
var repoEntryRE = regexp.MustCompile(
	`(?i)(?:repo[_\- ]?id|caucion[_\- ]?id|repo[_\- ]?entry|caucion[_\- ]?entry|repo_book|caucion_book)`)

// repoTenorRE captures a REPO tenor in days.
var repoTenorRE = regexp.MustCompile(
	`(?i)(?:tenor[_\- ]?days?|plazo[_\- ]?dias?|repo[_\- ]?tenor|days[_\- ]?to[_\- ]?maturity)"?\s*[:=]\s*"?(\d{1,4})`)

// leliqEntryRE matches a BCRA Leliq settlement entry.
var leliqEntryRE = regexp.MustCompile(
	`(?i)(?:leliq[_\- ]?id|leliq[_\- ]?entry|leliq[_\- ]?settle|bcra[_\- ]?leliq|leliqusd)`)

// fxForwardRE matches an FX-forward entry.
var fxForwardRE = regexp.MustCompile(
	`(?i)(?:fx[_\- ]?forward|forward[_\- ]?fx|usd_ars_fwd|fwd[_\- ]?usd[_\- ]?ars|forward[_\- ]?usd|forward[_\- ]?ars|moneda[_\- ]?dual)`)

// symbolEntryRE matches a JSON/XML/INI symbol entry or FIX
// tag `55=AL30` (the `=` is part of the tag, so this form
// has a separate alternative branch).
var symbolEntryRE = regexp.MustCompile(
	`(?i)(?:\b55=|"?(?:symbol|simbolo|s[ií]mbolo|ticker|especie|instrumento)"?\s*[:=]\s*"?)([A-Za-z0-9_\-\./]{2,32})`)

// notionalRE matches a notional / settlement amount.
var notionalRE = regexp.MustCompile(
	`(?i)(?:notional|importe|monto|valor|amount|settlement[_\- ]?amount|liquidacion[_\- ]?amount)"?\s*[:=]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit|counterparty[_\- ]?cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// clienteCuitXMLRE matches `<cliente_cuit>…</cliente_cuit>`.
var clienteCuitXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:cliente[_\-]?cuit|cuit[_\-]?cliente|titular[_\-]?cuit|cuit|counterparty[_\-]?cuit)\s*>(\d{2}-?\d{8}-?\d)`)

// ParseMAEclearCredentials parses an api_key / config body.
func ParseMAEclearCredentials(body []byte) MAEClearFields {
	var out MAEClearFields
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

// ParseMAEclearSettlementBook parses a settlement-book file.
func ParseMAEclearSettlementBook(body []byte) MAEClearFields {
	var out MAEClearFields
	if len(body) == 0 {
		return out
	}
	out.SettlementCount = int64(len(settlementEventRE.FindAllIndex(body, -1)))
	out.SettlementFailCount = int64(len(settlementFailRE.FindAllIndex(body, -1)))
	out.SovereignOTCCount = countSovereignSymbols(body)
	out.LeliqSettlementCount = countLeliqSymbols(body)
	out.FXForwardCount = int64(len(fxForwardRE.FindAllIndex(body, -1)))
	out.TotalVolumeCents = sumNotionalCents(body)
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

// ParseMAEclearAffirmationLog parses an affirmation log.
func ParseMAEclearAffirmationLog(body []byte) MAEClearFields {
	var out MAEClearFields
	if len(body) == 0 {
		return out
	}
	out.AffirmationCount = int64(len(affirmationEventRE.FindAllIndex(body, -1)))
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseMAEclearRepoBook parses a REPO bilateral book. A repo
// book may be CSV-row-per-entry (with one notional + one
// tenor per row) or JSON/XML named entries. The CSV form
// requires column-aware parsing; the named form falls back
// to per-entry regex marker counts.
func ParseMAEclearRepoBook(body []byte) MAEClearFields {
	if csv := parseRepoCSV(body); csv.RepoCount > 0 {
		return csv
	}
	var out MAEClearFields
	if len(body) == 0 {
		return out
	}
	out.RepoCount = int64(len(repoEntryRE.FindAllIndex(body, -1)))
	for _, m := range repoTenorRE.FindAllSubmatch(body, -1) {
		days, err := strconv.ParseInt(string(m[1]), 10, 64)
		if err == nil && days > out.RepoMaxTenorDays {
			out.RepoMaxTenorDays = days
		}
	}
	out.TotalVolumeCents = sumNotionalCents(body)
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// parseRepoCSV detects + parses CSV column-row form using
// header indices for tenor / notional / counterparty.
func parseRepoCSV(body []byte) MAEClearFields {
	var out MAEClearFields
	if len(body) == 0 {
		return out
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	if !scanner.Scan() {
		return out
	}
	headerLine := scanner.Text()
	delim := inferCSVDelim(headerLine)
	headers := strings.Split(headerLine, delim)
	if len(headers) < 2 {
		return out
	}
	tenorIdx, notionalIdx := -1, -1
	for i, h := range headers {
		hl := strings.ToLower(strings.TrimSpace(h))
		switch hl {
		case "tenor_days", "tenor-days", "plazo_dias", "plazo-dias",
			"tenor", "plazo", "days_to_maturity", "dtm":
			tenorIdx = i
		case "notional", "monto", "importe", "amount",
			"valor", "settlement_amount":
			notionalIdx = i
		}
	}
	if tenorIdx < 0 && notionalIdx < 0 {
		return out
	}
	for scanner.Scan() {
		line := scanner.Text()
		cols := strings.Split(line, delim)
		if len(cols) < 2 {
			continue
		}
		out.RepoCount++
		if tenorIdx >= 0 && tenorIdx < len(cols) {
			if days, err := strconv.ParseInt(strings.TrimSpace(cols[tenorIdx]), 10, 64); err == nil {
				if days > out.RepoMaxTenorDays {
					out.RepoMaxTenorDays = days
				}
			}
		}
		if notionalIdx >= 0 && notionalIdx < len(cols) {
			out.TotalVolumeCents += decimalToCents(cols[notionalIdx])
		}
	}
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// inferCSVDelim picks the most-likely CSV delimiter from a
// header line.
func inferCSVDelim(headerLine string) string {
	counts := map[string]int{
		",":  strings.Count(headerLine, ","),
		";":  strings.Count(headerLine, ";"),
		"\t": strings.Count(headerLine, "\t"),
		"|":  strings.Count(headerLine, "|"),
	}
	best := ","
	bestN := 0
	for d, n := range counts {
		if n > bestN {
			best = d
			bestN = n
		}
	}
	return best
}

// ParseMAEclearLeliqLog parses a BCRA Leliq settlement log.
func ParseMAEclearLeliqLog(body []byte) MAEClearFields {
	var out MAEClearFields
	if len(body) == 0 {
		return out
	}
	out.LeliqSettlementCount = int64(len(leliqEntryRE.FindAllIndex(body, -1)))
	if out.LeliqSettlementCount == 0 {
		out.LeliqSettlementCount = countLeliqSymbols(body)
	}
	out.TotalVolumeCents = sumNotionalCents(body)
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	return out
}

// ParseMAEclearDropCopy parses a FIX drop-copy log.
func ParseMAEclearDropCopy(body []byte) MAEClearFields {
	var out MAEClearFields
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
	out.SettlementCount = int64(len(settlementEventRE.FindAllIndex(body, -1)))
	out.SettlementFailCount = int64(len(settlementFailRE.FindAllIndex(body, -1)))
	out.SovereignOTCCount = countSovereignSymbols(body)
	out.LeliqSettlementCount = countLeliqSymbols(body)
	out.FXForwardCount = int64(len(fxForwardRE.FindAllIndex(body, -1)))
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
	return out
}

// ParseMAEclearSessionLog parses a terminal session log.
func ParseMAEclearSessionLog(body []byte) MAEClearFields {
	var out MAEClearFields
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

// countSovereignSymbols returns the count of distinct
// sovereign-bond tickers in body.
func countSovereignSymbols(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range symbolEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if IsSovereignBondTicker(s) {
			seen[s] = struct{}{}
		}
	}
	return int64(len(seen))
}

// countLeliqSymbols returns the count of distinct Leliq /
// LELIQ-USD / NOCOM tickers in body.
func countLeliqSymbols(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range symbolEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if IsLeliqTicker(s) {
			seen[s] = struct{}{}
		}
	}
	return int64(len(seen))
}

// sumNotionalCents sums all notional rows in body.
func sumNotionalCents(body []byte) int64 {
	var total int64
	for _, m := range notionalRE.FindAllSubmatch(body, -1) {
		if c := decimalToCents(string(m[1])); c > 0 {
			total += c
		}
	}
	return total
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
