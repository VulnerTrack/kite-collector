package winargprismaweb

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// PrismaWebFields captures scalar fields the audit pipeline
// needs from a PrismaWeb artifact.
type PrismaWebFields struct {
	MemberID               string
	ClienteCuitRaw         string
	FIXSenderCompID        string
	FIXTargetCompID        string
	SessionFirstSeen       string
	SessionLastSeen        string
	SettlementCount        int64
	SettlementFailCount    int64
	MarginCallCount        int64
	OptionsExerciseCount   int64
	CEDEARSettlementCount  int64
	FCICashflowCount       int64
	CollateralCents        int64
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

// settlementEventRE matches a settlement entry.
var settlementEventRE = regexp.MustCompile(
	`(?i)(?:settlement[_\- ]?id|liquidacion[_\- ]?id|liquidaci[oó]n[_\- ]?id|settle[_\- ]?entry|trade[_\- ]?settle|t\+1|t\+2)`)

// settlementFailRE matches a failed settlement event.
var settlementFailRE = regexp.MustCompile(
	`(?i)(?:settlement[_\- ]?fail|settle[_\- ]?fail|fail[_\- ]?to[_\- ]?deliver|fail[_\- ]?to[_\- ]?receive|liquidacion[_\- ]?fallida|FTR|FTD|failed[_\- ]?settle|t\+1[_\- ]?fail)`)

// marginCallRE matches a margin-call event.
var marginCallRE = regexp.MustCompile(
	`(?i)(?:margin[_\- ]?call|llamada[_\- ]?margen|call[_\- ]?margen|margin[_\- ]?notice|margin[_\- ]?event)`)

// optionsExerciseRE matches an options exercise / assignment.
var optionsExerciseRE = regexp.MustCompile(
	`(?i)(?:ejercicio[_\- ]?opcion|ejercicio[_\- ]?opci[oó]n|options?[_\- ]?exercise|options?[_\- ]?assignment|asignacion[_\- ]?opcion|exer[_\- ]?notice)`)

// fciCashflowRE matches an FCI cashflow event.
var fciCashflowRE = regexp.MustCompile(
	`(?i)(?:fci[_\- ]?cashflow|fci[_\- ]?flujo|suscripcion[_\- ]?fci|rescate[_\- ]?fci|fci[_\- ]?subscription|fci[_\- ]?redemption|fci[_\- ]?primary)`)

// symbolEntryRE matches a JSON/XML/INI symbol entry or FIX
// tag `55=AAPL` (the `=` is part of the tag, so this form
// has a separate alternative branch).
var symbolEntryRE = regexp.MustCompile(
	`(?i)(?:\b55=|"?(?:symbol|simbolo|s[ií]mbolo|ticker|especie|instrumento)"?\s*[:=]\s*"?)([A-Za-z0-9_\-\./]{2,32})`)

// notionalRE matches a notional / settlement amount.
var notionalRE = regexp.MustCompile(
	`(?i)(?:notional|importe|monto|valor|amount|settlement[_\- ]?amount|liquidacion[_\- ]?amount|garantias|collateral[_\- ]?amount|margin[_\- ]?amount)"?\s*[:=]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// collateralRE matches a garantías / collateral amount.
var collateralRE = regexp.MustCompile(
	`(?i)(?:garantias|garant[íi]as|collateral|collateral[_\- ]?amount|margen[_\- ]?inicial|initial[_\- ]?margin|garantia[_\- ]?total)"?\s*[:=]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit|counterparty[_\- ]?cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// clienteCuitXMLRE matches `<cliente_cuit>…</cliente_cuit>`.
var clienteCuitXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:cliente[_\-]?cuit|cuit[_\-]?cliente|titular[_\-]?cuit|cuit|counterparty[_\-]?cuit)\s*>(\d{2}-?\d{8}-?\d)`)

// ParsePrismaWebCredentials parses an api_key / config body.
func ParsePrismaWebCredentials(body []byte) PrismaWebFields {
	var out PrismaWebFields
	if len(body) == 0 {
		return out
	}
	if passwordXMLRE.Match(body) || passwordRE.Match(body) {
		out.HasPassword = true
	}
	out.MemberID = MemberIDFromText(string(body))
	out.ClienteCuitRaw = cuitFromBody(body)
	return out
}

// ParsePrismaWebDailySettlement parses a daily settlement file.
func ParsePrismaWebDailySettlement(body []byte) PrismaWebFields {
	var out PrismaWebFields
	if len(body) == 0 {
		return out
	}
	out.SettlementCount = int64(len(settlementEventRE.FindAllIndex(body, -1)))
	out.SettlementFailCount = int64(len(settlementFailRE.FindAllIndex(body, -1)))
	out.CEDEARSettlementCount = countCEDEARSymbols(body)
	out.TotalVolumeCents = sumNotionalCents(body)
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	out.MemberID = MemberIDFromText(string(body))
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParsePrismaWebCollateral parses a garantías / collateral file.
func ParsePrismaWebCollateral(body []byte) PrismaWebFields {
	var out PrismaWebFields
	if len(body) == 0 {
		return out
	}
	for _, m := range collateralRE.FindAllSubmatch(body, -1) {
		out.CollateralCents += decimalToCents(string(m[1]))
	}
	if out.CollateralCents == 0 {
		// Fallback to generic notional sum.
		out.CollateralCents = sumNotionalCents(body)
	}
	out.MemberID = MemberIDFromText(string(body))
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParsePrismaWebMarginCalls parses a margin-call file.
func ParsePrismaWebMarginCalls(body []byte) PrismaWebFields {
	var out PrismaWebFields
	if len(body) == 0 {
		return out
	}
	out.MarginCallCount = int64(len(marginCallRE.FindAllIndex(body, -1)))
	out.TotalVolumeCents = sumNotionalCents(body)
	out.MemberID = MemberIDFromText(string(body))
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	return out
}

// ParsePrismaWebOptionsExercise parses an options-exercise file.
func ParsePrismaWebOptionsExercise(body []byte) PrismaWebFields {
	var out PrismaWebFields
	if len(body) == 0 {
		return out
	}
	out.OptionsExerciseCount = int64(len(optionsExerciseRE.FindAllIndex(body, -1)))
	out.TotalVolumeCents = sumNotionalCents(body)
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	out.MemberID = MemberIDFromText(string(body))
	return out
}

// ParsePrismaWebFCICashflow parses an FCI cash-flow file.
func ParsePrismaWebFCICashflow(body []byte) PrismaWebFields {
	var out PrismaWebFields
	if len(body) == 0 {
		return out
	}
	out.FCICashflowCount = int64(len(fciCashflowRE.FindAllIndex(body, -1)))
	out.TotalVolumeCents = sumNotionalCents(body)
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	out.MemberID = MemberIDFromText(string(body))
	return out
}

// ParsePrismaWebFIXDropCopy parses a FIX drop-copy log.
func ParsePrismaWebFIXDropCopy(body []byte) PrismaWebFields {
	var out PrismaWebFields
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
	out.CEDEARSettlementCount = countCEDEARSymbols(body)
	out.OptionsExerciseCount = int64(len(optionsExerciseRE.FindAllIndex(body, -1)))
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
	return out
}

// ParsePrismaWebMemberPosition parses a member-position file.
func ParsePrismaWebMemberPosition(body []byte) PrismaWebFields {
	var out PrismaWebFields
	if len(body) == 0 {
		return out
	}
	out.TotalVolumeCents = sumNotionalCents(body)
	out.CEDEARSettlementCount = countCEDEARSymbols(body)
	out.MemberID = MemberIDFromText(string(body))
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	out.DistinctCounterparties = DistinctCounterpartiesInBody(body)
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

// countCEDEARSymbols returns the count of distinct CEDEAR
// ticker stems in body.
func countCEDEARSymbols(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range symbolEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if IsCEDEARTicker(s) {
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
