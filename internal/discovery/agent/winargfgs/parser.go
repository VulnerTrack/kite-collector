package winargfgs

import (
	"regexp"
	"strconv"
	"strings"
)

// FGSFields captures scalar fields the audit pipeline needs from
// an FGS artifact.
type FGSFields struct {
	FGSSeriesCode               string
	AuctionID                   string
	ActaID                      string
	ClienteCuitRaw              string
	TrabajadorCuilRaw           string
	AuctionWindow               AuctionWindow
	PortfolioInstrumentsCount   int64
	LICFaceValueARSMillions     int64
	EquityHoldingCount          int64
	SovBondHoldingCount         int64
	PanelLiderHoldingCount      int64
	AuctionBidAmountARSMillions int64
	SIPAPensionerCount          int64
	HasPassword                 bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|fgs[_\-]?password|anses[_\-]?password|portal[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|fgs[_\-]?password|anses[_\-]?password|portal[_\-]?password)\b"?\s*[:=]\s*["'][^"']{1,}["']`,
)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|fgs[_\-]?password|anses[_\-]?password)\s*>([^<]{1,})<\s*/`,
)

// fgsSeriesCodeRE matches a LIC series identifier. LICs are
// labeled by issue date / series (e.g. `LIC2024-001`).
var fgsSeriesCodeRE = regexp.MustCompile(
	`(?i)"?(?:lic[_\- ]?series|series[_\- ]?lic|fgs[_\- ]?series|nro[_\- ]?lic)"?\s*[:=>]\s*"?([A-Z0-9\-]{4,32})"?`,
)

// auctionIDRE matches a primary-market auction identifier.
var auctionIDRE = regexp.MustCompile(
	`(?i)"?(?:auction[_\- ]?id|subasta[_\- ]?id|licitacion[_\- ]?id|nro[_\- ]?subasta|nro[_\- ]?licitacion)"?\s*[:=>]\s*"?([A-Z0-9\-]{4,32})"?`,
)

// actaIDRE matches a board / committee minutes identifier.
var actaIDRE = regexp.MustCompile(
	`(?i)"?(?:acta[_\- ]?id|nro[_\- ]?acta|acta[_\- ]?nro|acta[_\- ]?numero)"?\s*[:=>]\s*"?([A-Z0-9\-]{1,16})"?`,
)

// instrumentRowRE matches `<Instrumento>` / `<Tenencia>` in
// cartera XMLs.
var instrumentRowRE = regexp.MustCompile(
	`(?i)<(?:fgs:|cartera:)?(?:Instrumento|Tenencia|Position|Holding)\b`,
)

// instrumentRowJSONRE matches a JSON position-array row.
var instrumentRowJSONRE = regexp.MustCompile(
	`(?im)^\s*\{[^}]*"?(?:especie|symbol|ticker|instrumento)"?\s*[:=]\s*"?[A-Z][A-Z0-9.\-]{1,12}`,
)

// licFaceValueRE matches LIC face value in ARS millions or
// in absolute ARS. LICs are large-denomination instruments.
var licFaceValueRE = regexp.MustCompile(
	`(?i)"?(?:lic[_\- ]?face[_\- ]?value|valor[_\- ]?nominal[_\- ]?lic|lic[_\- ]?vn|face[_\- ]?value)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`,
)

// auctionBidAmountRE matches an auction bid amount in ARS.
var auctionBidAmountRE = regexp.MustCompile(
	`(?i)"?(?:bid[_\- ]?amount|monto[_\- ]?subasta|oferta[_\- ]?monto|amount[_\- ]?ofrecido)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`,
)

// auctionWindowRE matches the auction window / venue identifier.
var auctionWindowRE = regexp.MustCompile(
	`(?i)"?(?:auction[_\- ]?window|ventana[_\- ]?subasta|window|venue|organismo)"?\s*[:=>]\s*"?([A-Za-z\-_]{4,40})`,
)

// sipaPensionerCountRE matches a count of SIPA pensioners in
// a pension roster.
var sipaPensionerCountRE = regexp.MustCompile(
	`(?i)"?(?:sipa[_\- ]?pensioner[_\- ]?count|pensionados[_\- ]?count|cantidad[_\- ]?pensionados|count[_\- ]?pensioners)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// sipaCSVRowRE matches a per-pensioner CSV row.
var sipaCSVRowRE = regexp.MustCompile(
	`(?im)^\d+,\d{2}-?\d{8}-?\d,`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit|emisora[_\- ]?cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// trabajadorCuilKeyRE matches `trabajador_cuil: NN-NNNNNNNN-N`.
var trabajadorCuilKeyRE = regexp.MustCompile(
	`(?i)"?(?:trabajador[_\- ]?cuil|cuil[_\- ]?trabajador|pensioner[_\- ]?cuil|pensionado[_\- ]?cuil|cuil)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// symbolEntryRE matches a per-symbol entry in cartera /
// auction / acta bodies.
var symbolEntryRE = regexp.MustCompile(
	`(?im)(?:"?(?:especie|symbol|sym|ticker|instrumento)"?\s*[:=]\s*"?|<(?:especie|symbol|instrumento)[^>]*>)([A-Z][A-Z0-9_\-\./]{0,11})`,
)

// ParseCartera parses an FGS cartera XML / XLSX body.
func ParseCartera(body []byte) FGSFields {
	out := parseCommon(body)
	out.PortfolioInstrumentsCount = int64(len(instrumentRowRE.FindAllIndex(body, -1)))
	if out.PortfolioInstrumentsCount == 0 {
		out.PortfolioInstrumentsCount = int64(len(instrumentRowJSONRE.FindAllIndex(body, -1)))
	}
	eq, sov, panel := classifyPositions(body)
	out.EquityHoldingCount = eq
	out.SovBondHoldingCount = sov
	out.PanelLiderHoldingCount = panel
	return out
}

// ParseLICRecord parses an LIC subscription / holding body.
func ParseLICRecord(body []byte) FGSFields {
	out := parseCommon(body)
	if m := fgsSeriesCodeRE.FindSubmatch(body); len(m) > 1 {
		out.FGSSeriesCode = string(m[1])
	}
	if v, ok := sumARSMillions(body, licFaceValueRE); ok {
		out.LICFaceValueARSMillions = v
	}
	return out
}

// ParseDirectorioActa parses a board minutes body.
func ParseDirectorioActa(body []byte) FGSFields {
	out := parseCommon(body)
	if m := actaIDRE.FindSubmatch(body); len(m) > 1 {
		out.ActaID = string(m[1])
	}
	_, _, panel := classifyPositions(body)
	out.PanelLiderHoldingCount = panel
	return out
}

// ParseComiteActa parses a committee minutes body.
func ParseComiteActa(body []byte) FGSFields {
	return ParseDirectorioActa(body)
}

// ParseLineamientosDoc parses an investment policy body.
func ParseLineamientosDoc(body []byte) FGSFields {
	return parseCommon(body)
}

// ParsePrimaryAuctionBid parses an auction bid pre-result body.
func ParsePrimaryAuctionBid(body []byte) FGSFields {
	out := parseCommon(body)
	if m := auctionIDRE.FindSubmatch(body); len(m) > 1 {
		out.AuctionID = string(m[1])
	}
	if v, ok := sumARSMillions(body, auctionBidAmountRE); ok {
		out.AuctionBidAmountARSMillions = v
	}
	out.AuctionWindow = detectAuctionWindow(body)
	return out
}

// ParsePrimaryAuctionResult parses an auction result body.
func ParsePrimaryAuctionResult(body []byte) FGSFields {
	out := parseCommon(body)
	if m := auctionIDRE.FindSubmatch(body); len(m) > 1 {
		out.AuctionID = string(m[1])
	}
	out.AuctionWindow = detectAuctionWindow(body)
	return out
}

// ParseCustodiaRecord parses a CVSA custody record body.
func ParseCustodiaRecord(body []byte) FGSFields {
	return parseCommon(body)
}

// ParseVotingRecord parses an asamblea voting record body.
func ParseVotingRecord(body []byte) FGSFields {
	out := parseCommon(body)
	_, _, panel := classifyPositions(body)
	out.PanelLiderHoldingCount = panel
	return out
}

// ParseSIPAPensionRecord parses a SIPA pensioner roster body.
func ParseSIPAPensionRecord(body []byte) FGSFields {
	out := parseCommon(body)
	if m := sipaPensionerCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.SIPAPensionerCount = v
		}
	}
	if out.SIPAPensionerCount == 0 {
		out.SIPAPensionerCount = int64(len(sipaCSVRowRE.FindAllIndex(body, -1)))
	}
	if m := trabajadorCuilKeyRE.FindSubmatch(body); len(m) > 1 {
		out.TrabajadorCuilRaw = string(m[1])
	}
	return out
}

// ParseFilingReceipt parses an FGS filing receipt body.
func ParseFilingReceipt(body []byte) FGSFields {
	return parseCommon(body)
}

// ParseConfig parses a generic FGS-tool config body.
func ParseConfig(body []byte) FGSFields {
	return parseCommon(body)
}

// parseCommon extracts the cross-cutting fields.
func parseCommon(body []byte) FGSFields {
	var out FGSFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	if c := cuilFromBody(body); c != "" {
		out.TrabajadorCuilRaw = c
	}
	return out
}

// cuitFromBody returns the first cliente CUIT match.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// cuilFromBody returns the first trabajador CUIL match.
func cuilFromBody(body []byte) string {
	if m := trabajadorCuilKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectAuctionWindow sniffs body for the auction venue.
func detectAuctionWindow(body []byte) AuctionWindow {
	s := strings.ToLower(string(body))
	if m := auctionWindowRE.FindSubmatch(body); len(m) > 1 {
		w := strings.ToLower(string(m[1]))
		switch {
		case strings.Contains(w, "bcra"):
			return WindowBCRAPrimary
		case strings.Contains(w, "minecon") ||
			strings.Contains(w, "ministerio_economia") ||
			strings.Contains(w, "ministerio-economia"):
			return WindowMineconPrimary
		case strings.Contains(w, "anses_lic") ||
			strings.Contains(w, "anses-lic"):
			return WindowANSESLIC
		case strings.Contains(w, "tesoro_corto") ||
			strings.Contains(w, "tesoro-corto"):
			return WindowTesoroCortoPlazo
		case strings.Contains(w, "tesoro_largo") ||
			strings.Contains(w, "tesoro-largo"):
			return WindowTesoroLargoPlazo
		case strings.Contains(w, "on_corporate") ||
			strings.Contains(w, "on-corporate") ||
			strings.Contains(w, "on corporate"):
			return WindowONCorporate
		}
	}
	switch {
	case strings.Contains(s, "bcra"):
		return WindowBCRAPrimary
	case strings.Contains(s, "minecon"):
		return WindowMineconPrimary
	case strings.Contains(s, "anses lic") ||
		strings.Contains(s, "anses_lic"):
		return WindowANSESLIC
	case strings.Contains(s, "tesoro corto") ||
		strings.Contains(s, "tesoro_corto"):
		return WindowTesoroCortoPlazo
	case strings.Contains(s, "tesoro largo") ||
		strings.Contains(s, "tesoro_largo"):
		return WindowTesoroLargoPlazo
	case strings.Contains(s, "[auction]"):
		return WindowCustom
	}
	return WindowUnknown
}

// sumARSMillions totals ARS amounts (returns millions). AR
// locale uses both `.` and `,` as separators.
func sumARSMillions(body []byte, re *regexp.Regexp) (int64, bool) {
	var sum int64
	found := false
	for _, m := range re.FindAllSubmatch(body, -1) {
		if len(m) <= 1 {
			continue
		}
		raw := strings.ReplaceAll(string(m[1]), ".", "")
		raw = strings.ReplaceAll(raw, ",", "")
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			sum += v
			found = true
		}
	}
	return sum / 1_000_000, found
}

// classifyPositions returns counts of (equity, sov bond, panel-
// líder) holdings.
func classifyPositions(body []byte) (eq, sov, panel int64) {
	eqSet := map[string]struct{}{}
	sovSet := map[string]struct{}{}
	panelSet := map[string]struct{}{}
	for _, m := range symbolEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" {
			continue
		}
		if IsPanelLiderStem(s) {
			eqSet[s] = struct{}{}
			panelSet[s] = struct{}{}
		}
		if IsARSovereignBondStem(s) {
			sovSet[s] = struct{}{}
		}
	}
	return int64(len(eqSet)), int64(len(sovSet)), int64(len(panelSet))
}
