package winargtesoro

import (
	"regexp"
	"strconv"
	"strings"
)

// TesoroFields captures scalar fields the audit pipeline needs.
type TesoroFields struct {
	InstrumentClass       InstrumentClass
	PlacementMethod       PlacementMethod
	DealerCuitRaw         string
	AuctionID             string
	BidCount              int64
	AllocationCount       int64
	DealerCount           int64
	LargestBidNotionalARS int64
	TotalOfferedARS       int64
	TotalAllocatedARS     int64
	HasPassword           bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|tesoro[_\-]?password|mecon[_\-]?password|api[_\-]?token|api[_\-]?key|api[_\-]?secret)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|tesoro[_\-]?password|mecon[_\-]?password|bearer[_\-]?token)\b"?\s*[:=]\s*["'][^"']{1,}["']`,
)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|tesoro[_\-]?password|mecon[_\-]?password)\s*>([^<]{1,})<\s*/`,
)

// instrumentRE matches an instrument-class marker in body.
var instrumentRE = regexp.MustCompile(
	`(?i)"?(?:instrument[_\- ]?class|instrument|instrumento|titulo|especie)"?\s*[:=>]\s*"?(lecap|lecer|lede|lemin|bonte|boncer|bonad|al30|al35|al38|al41|gd29|gd30|gd35|gd38|gd41|gd46|parp|dica|dicy|tx26|tx28|ty27|bopreal)"?`,
)

// placementMethodRE matches a placement-method field.
var placementMethodRE = regexp.MustCompile(
	`(?i)"?(?:placement[_\- ]?method|metodo[_\- ]?colocacion|colocacion[_\- ]?tipo)"?\s*[:=>]\s*"?(competitive[_\- ]?auction|competitiva|non[_\- ]?competitive|no[_\- ]?competitiva|syndicated|sindicada|private[_\- ]?placement|privada|swap|canje|buyback|recompra)"?`,
)

// dealerCuitKeyRE matches `dealer_cuit: NN-NNNNNNNN-N`.
var dealerCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:dealer[_\- ]?cuit|primary[_\- ]?dealer[_\- ]?cuit|creador[_\- ]?mercado[_\- ]?cuit|alyc[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// auctionIDRE matches an auction-ID field.
var auctionIDRE = regexp.MustCompile(
	`(?i)"?(?:auction[_\- ]?id|licitacion[_\- ]?id|subasta[_\- ]?id|auction[_\- ]?number)"?\s*[:=>]\s*"?([A-Z0-9\-]{3,32})"?`,
)

// bidCountRE matches a total bid count.
var bidCountRE = regexp.MustCompile(
	`(?i)"?(?:bid[_\- ]?count|ofertas[_\- ]?count|total[_\- ]?bids)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// allocationCountRE matches a total allocation count.
var allocationCountRE = regexp.MustCompile(
	`(?i)"?(?:allocation[_\- ]?count|asignaciones[_\- ]?count|allocations[_\- ]?total)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// dealerCountRE matches a dealer count.
var dealerCountRE = regexp.MustCompile(
	`(?i)"?(?:dealer[_\- ]?count|creadores[_\- ]?count|dealers[_\- ]?total|primary[_\- ]?dealer[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// largestBidNotionalRE matches the largest bid notional in ARS.
var largestBidNotionalRE = regexp.MustCompile(
	`(?i)"?(?:largest[_\- ]?bid[_\- ]?notional[_\- ]?ars|max[_\- ]?bid[_\- ]?ars|biggest[_\- ]?bid[_\- ]?ars)"?\s*[:=>]\s*"?(\d{1,15})`,
)

// totalOfferedRE matches the total offered amount in ARS.
var totalOfferedRE = regexp.MustCompile(
	`(?i)"?(?:total[_\- ]?offered[_\- ]?ars|ofertado[_\- ]?total[_\- ]?ars|monto[_\- ]?ofertado[_\- ]?ars)"?\s*[:=>]\s*"?(\d{1,15})`,
)

// totalAllocatedRE matches the total allocated amount in ARS.
var totalAllocatedRE = regexp.MustCompile(
	`(?i)"?(?:total[_\- ]?allocated[_\- ]?ars|adjudicado[_\- ]?total[_\- ]?ars|monto[_\- ]?adjudicado[_\- ]?ars)"?\s*[:=>]\s*"?(\d{1,15})`,
)

// ParseTesoro parses any Tesoro artifact body (shared parser).
func ParseTesoro(body []byte) TesoroFields {
	var out TesoroFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := instrumentRE.FindSubmatch(body); len(m) > 1 {
		out.InstrumentClass = detectInstrument(string(m[1]))
	}
	if m := placementMethodRE.FindSubmatch(body); len(m) > 1 {
		out.PlacementMethod = detectPlacementMethod(string(m[1]))
	}
	if c := dealerCuitFromBody(body); c != "" {
		out.DealerCuitRaw = c
	}
	if m := auctionIDRE.FindSubmatch(body); len(m) > 1 {
		out.AuctionID = string(m[1])
	}
	if m := bidCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.BidCount = v
		}
	}
	if m := allocationCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.AllocationCount = v
		}
	}
	if m := dealerCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.DealerCount = v
		}
	}
	if m := largestBidNotionalRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.LargestBidNotionalARS = v
		}
	}
	if m := totalOfferedRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.TotalOfferedARS = v
		}
	}
	if m := totalAllocatedRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.TotalAllocatedARS = v
		}
	}
	return out
}

// dealerCuitFromBody returns the first dealer CUIT match.
func dealerCuitFromBody(body []byte) string {
	if m := dealerCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectInstrument normalizes an instrument-class string to the
// pinned enum.
func detectInstrument(s string) InstrumentClass {
	t := strings.ToLower(strings.TrimSpace(s))
	if c := InstrumentClass(t); isInstrumentEnum(c) {
		return c
	}
	return InstUnknown
}

// isInstrumentEnum verifies the value is one of the pinned
// instrument-class enum constants (excluding the catch-all
// sentinels).
func isInstrumentEnum(c InstrumentClass) bool {
	switch c {
	case InstLECAP, InstLECER, InstLEDE, InstLEMIN,
		InstBONTE, InstBONCER, InstBONAD,
		InstAL30, InstAL35, InstAL38, InstAL41,
		InstGD29, InstGD30, InstGD35, InstGD38, InstGD41, InstGD46,
		InstPARP, InstDICA, InstDICY,
		InstTX26, InstTX28, InstTY27,
		InstBOPREAL:
		return true
	case InstCustom, InstNone, InstUnknown:
		return false
	}
	return false
}

// detectPlacementMethod normalizes a placement-method string.
func detectPlacementMethod(s string) PlacementMethod {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "non") || strings.Contains(t, "no_") ||
		strings.Contains(t, "no-") || strings.Contains(t, "no "):
		return MethodNonCompetitive
	case strings.Contains(t, "competitive") || strings.Contains(t, "competitiva"):
		return MethodCompetitiveAuction
	case strings.Contains(t, "syndicated") || strings.Contains(t, "sindicada"):
		return MethodSyndicated
	case strings.Contains(t, "private") || strings.Contains(t, "privada"):
		return MethodPrivatePlacement
	case strings.Contains(t, "swap") || strings.Contains(t, "canje"):
		return MethodSwap
	case strings.Contains(t, "buyback") || strings.Contains(t, "recompra"):
		return MethodBuyback
	}
	return MethodUnknown
}
