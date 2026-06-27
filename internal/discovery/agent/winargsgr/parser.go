package winargsgr

import (
	"regexp"
	"strconv"
	"strings"
)

// SGRFields captures scalar fields the audit pipeline needs.
type SGRFields struct {
	SGRShop                  SGRShop
	CounterGuaranteeType     CounterGuaranteeType
	GuaranteeStatus          GuaranteeStatus
	InstrumentType           InstrumentType
	SGRCuitRaw               string
	SMECuitRaw               string
	PymeCount                int64
	ActiveGuaranteeCount     int64
	RiskFundSizeARS          int64
	GuaranteesOutstandingARS int64
	ApalancamientoRatioPct   int64
	HasPassword              bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|sgr[_\-]?password|garantizar[_\-]?password|api[_\-]?token|api[_\-]?key|api[_\-]?secret)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|sgr[_\-]?password|garantizar[_\-]?password|bearer[_\-]?token)\b"?\s*[:=]\s*["'][^"']{1,}["']`)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|sgr[_\-]?password|garantizar[_\-]?password)\s*>([^<]{1,})<\s*/`)

// sgrShopRE matches an SGR-shop marker in body.
var sgrShopRE = regexp.MustCompile(
	`(?i)\b(garantizar sustentable|garantizar-sustentable|garantizar|acindar pymes|acindar-pymes|aval federal|aval-federal|vinculos sgr|vinculos-sgr|affidavit sgr|don mario|don-mario|confiable sgr|avaluar sgr|crecer sgr|fogaba|fondo garantia buenos aires)\b`)

// counterGuaranteeRE matches a counter-guarantee type field.
var counterGuaranteeRE = regexp.MustCompile(
	`(?i)"?(?:counter[_\- ]?guarantee[_\- ]?type|contragarantia[_\- ]?tipo|tipo[_\- ]?contragarantia)"?\s*[:=>]\s*"?(pledge|prenda|mortgage|hipoteca|third[_\- ]?party[_\- ]?fianza|fianza|term[_\- ]?deposit|plazo[_\- ]?fijo|securities|titulos)"?`)

// guaranteeStatusRE matches a guarantee-status field.
var guaranteeStatusRE = regexp.MustCompile(
	`(?i)"?(?:guarantee[_\- ]?status|estado[_\- ]?garantia|status)"?\s*[:=>]\s*"?(vigente|active|ejecutada|executed|recuperada|recovered|prescripta|lapsed|anulada|cancelled)"?`)

// instrumentTypeRE matches an instrument-type field.
var instrumentTypeRE = regexp.MustCompile(
	`(?i)"?(?:instrument[_\- ]?type|instrumento|tipo[_\- ]?instrumento)"?\s*[:=>]\s*"?(cpd|cheque[_\- ]?pago[_\- ]?diferido|onpyme|on[_\- ]?pyme|pagare[_\- ]?bursatil|fideicomiso[_\- ]?pyme|prestamo[_\- ]?bancario)"?`)

// sgrCuitKeyRE matches `sgr_cuit: NN-NNNNNNNN-N`.
var sgrCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:sgr[_\- ]?cuit|entidad[_\- ]?sgr[_\- ]?cuit|sgr[_\- ]?entidad[_\- ]?cuit|cuit[_\- ]?sgr)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// smeCuitKeyRE matches SME-beneficiary CUIT field.
var smeCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:sme[_\- ]?cuit|pyme[_\- ]?cuit|beneficiary[_\- ]?cuit|beneficiario[_\- ]?cuit|cuit[_\- ]?pyme)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// pymeCountRE matches the SME-beneficiary count.
var pymeCountRE = regexp.MustCompile(
	`(?i)"?(?:pyme[_\- ]?count|pymes[_\- ]?total|sme[_\- ]?count|beneficiarios[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`)

// activeGuaranteeCountRE matches active-guarantee count.
var activeGuaranteeCountRE = regexp.MustCompile(
	`(?i)"?(?:active[_\- ]?guarantee[_\- ]?count|garantias[_\- ]?vigentes|guarantees[_\- ]?active)"?\s*[:=>]\s*"?(\d{1,12})`)

// riskFundSizeRE matches Fondo-de-Riesgo size in ARS.
var riskFundSizeRE = regexp.MustCompile(
	`(?i)"?(?:risk[_\- ]?fund[_\- ]?size[_\- ]?ars|fondo[_\- ]?riesgo[_\- ]?ars|fondo[_\- ]?riesgo[_\- ]?monto)"?\s*[:=>]\s*"?(\d{1,15})`)

// guaranteesOutstandingRE matches outstanding guarantees in ARS.
var guaranteesOutstandingRE = regexp.MustCompile(
	`(?i)"?(?:guarantees[_\- ]?outstanding[_\- ]?ars|garantias[_\- ]?outstanding[_\- ]?ars|garantias[_\- ]?vigentes[_\- ]?ars)"?\s*[:=>]\s*"?(\d{1,15})`)

// apalancamientoRE matches apalancamiento ratio (percentage).
var apalancamientoRE = regexp.MustCompile(
	`(?i)"?(?:apalancamiento[_\- ]?ratio[_\- ]?pct|apalancamiento[_\- ]?ratio|leverage[_\- ]?ratio[_\- ]?pct|leverage[_\- ]?ratio)"?\s*[:=>]\s*"?(\d{1,7})`)

// ParseSGR parses any SGR artifact body (shared parser).
func ParseSGR(body []byte) SGRFields {
	var out SGRFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := sgrShopRE.FindSubmatch(body); len(m) > 1 {
		out.SGRShop = detectSGRShop(string(m[1]))
	}
	if m := counterGuaranteeRE.FindSubmatch(body); len(m) > 1 {
		out.CounterGuaranteeType = detectCounterGuarantee(string(m[1]))
	}
	if m := guaranteeStatusRE.FindSubmatch(body); len(m) > 1 {
		out.GuaranteeStatus = detectGuaranteeStatus(string(m[1]))
	}
	if m := instrumentTypeRE.FindSubmatch(body); len(m) > 1 {
		out.InstrumentType = detectInstrumentType(string(m[1]))
	}
	if c := sgrCuitFromBody(body); c != "" {
		out.SGRCuitRaw = c
	}
	if c := smeCuitFromBody(body); c != "" {
		out.SMECuitRaw = c
	}
	if m := pymeCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.PymeCount = v
		}
	}
	if m := activeGuaranteeCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.ActiveGuaranteeCount = v
		}
	}
	if m := riskFundSizeRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.RiskFundSizeARS = v
		}
	}
	if m := guaranteesOutstandingRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.GuaranteesOutstandingARS = v
		}
	}
	if m := apalancamientoRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.ApalancamientoRatioPct = v
		}
	}
	return out
}

// sgrCuitFromBody returns the first SGR-entity CUIT match.
func sgrCuitFromBody(body []byte) string {
	if m := sgrCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// smeCuitFromBody returns the first SME-beneficiary CUIT match.
func smeCuitFromBody(body []byte) string {
	if m := smeCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectSGRShop normalizes an SGR-shop string.
func detectSGRShop(s string) SGRShop {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "garantizar sustentable") ||
		strings.Contains(t, "garantizar-sustentable"):
		return ShopGarantizarSustentable
	case strings.Contains(t, "garantizar"):
		return ShopGarantizar
	case strings.Contains(t, "acindar"):
		return ShopAcindarPymes
	case strings.Contains(t, "aval federal") || strings.Contains(t, "aval-federal"):
		return ShopAvalFederal
	case strings.Contains(t, "vinculos"):
		return ShopVinculos
	case strings.Contains(t, "affidavit"):
		return ShopAffidavit
	case strings.Contains(t, "don mario") || strings.Contains(t, "don-mario"):
		return ShopDonMario
	case strings.Contains(t, "confiable"):
		return ShopConfiable
	case strings.Contains(t, "avaluar"):
		return ShopAvaluar
	case strings.Contains(t, "crecer"):
		return ShopCrecer
	case strings.Contains(t, "fogaba") ||
		strings.Contains(t, "fondo garantia buenos aires"):
		return ShopFondoGarantiaBuenosAires
	}
	return ShopUnknown
}

// detectCounterGuarantee normalizes a counter-guarantee string.
func detectCounterGuarantee(s string) CounterGuaranteeType {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "pledge") || strings.Contains(t, "prenda"):
		return CGPledge
	case strings.Contains(t, "mortgage") || strings.Contains(t, "hipoteca"):
		return CGMortgage
	case strings.Contains(t, "fianza"):
		return CGThirdPartyFianza
	case strings.Contains(t, "term") || strings.Contains(t, "plazo"):
		return CGTermDeposit
	case strings.Contains(t, "securities") || strings.Contains(t, "titulos"):
		return CGSecurities
	}
	return CGUnknown
}

// detectGuaranteeStatus normalizes a guarantee-status string.
func detectGuaranteeStatus(s string) GuaranteeStatus {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "vigente") || strings.Contains(t, "active"):
		return StatusVigente
	case strings.Contains(t, "ejecutada") || strings.Contains(t, "executed"):
		return StatusEjecutada
	case strings.Contains(t, "recuperada") || strings.Contains(t, "recovered"):
		return StatusRecuperada
	case strings.Contains(t, "prescripta") || strings.Contains(t, "lapsed"):
		return StatusPrescripta
	case strings.Contains(t, "anulada") || strings.Contains(t, "cancelled"):
		return StatusAnulada
	}
	return StatusUnknown
}

// detectInstrumentType normalizes an instrument-type string.
func detectInstrumentType(s string) InstrumentType {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "cpd") || strings.Contains(t, "cheque"):
		return InstCPD
	case strings.Contains(t, "onpyme") || strings.Contains(t, "on pyme") ||
		strings.Contains(t, "on-pyme") || strings.Contains(t, "on_pyme"):
		return InstONPyme
	case strings.Contains(t, "pagare"):
		return InstPagareBursatil
	case strings.Contains(t, "fideicomiso"):
		return InstFideicomisoPyme
	case strings.Contains(t, "prestamo") || strings.Contains(t, "bancario"):
		return InstPrestamoBanc
	}
	return InstUnknown
}
