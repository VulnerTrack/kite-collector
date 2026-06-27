package winargpsp

import (
	"regexp"
	"strconv"
	"strings"
)

// PSPFields captures scalar fields the audit pipeline needs.
type PSPFields struct {
	PSPNetwork       PSPNetwork
	SettlementRail   SettlementRail
	TransactionType  TransactionType
	PSPCuitRaw       string
	MerchantCuitRaw  string
	CustomerCVURaw   string
	BatchID          string
	TransactionCount int64
	CustomerCount    int64
	MerchantCount    int64
	BatchValueARS    int64
	ChargebackCount  int64
	HasPassword      bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|psp[_\-]?password|merchant[_\-]?password|api[_\-]?token|api[_\-]?key|api[_\-]?secret)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|psp[_\-]?password|merchant[_\-]?password|bearer[_\-]?token)\b"?\s*[:=]\s*["'][^"']{1,}["']`)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|psp[_\-]?password|merchant[_\-]?password)\s*>([^<]{1,})<\s*/`)

// pspNetworkRE matches a PSP-network marker in body. The
// `ualá` variant accommodates the AR-Spanish accent. The
// trailing `\b` is omitted because Go RE2 `\b` is ASCII-only
// and would fail to match between `á` and a non-letter.
var pspNetworkRE = regexp.MustCompile(
	`(?i)\b(banelco|link|prisma|mercado[_\- ]?pago|ualá|uala|modo|naranja[_\- ]?x|personal[_\- ]?pay|cuenta[_\- ]?dni[_\- ]?bapro|cuenta[_\- ]?dni|brubank|lemon|nubi|belo)`)

// settlementRailRE matches a settlement-rail field.
var settlementRailRE = regexp.MustCompile(
	`(?i)"?(?:settlement[_\- ]?rail|rail|liquidacion[_\- ]?rail|sistema[_\- ]?pago)"?\s*[:=>]\s*"?(compe|mep|coelsa|debin|transfer[_\- ]?3[_\- ]?0|transferencias[_\- ]?3[_\- ]?0|pix[_\- ]?ar)"?`)

// transactionTypeRE matches a transaction-type field.
var transactionTypeRE = regexp.MustCompile(
	`(?i)"?(?:transaction[_\- ]?type|tx[_\- ]?type|tipo[_\- ]?transaccion)"?\s*[:=>]\s*"?(p2p|p2m|m2p|b2b|payroll|nomina|vep[_\- ]?afip|tax[_\- ]?collection|impuestos|utility[_\- ]?payment|servicios|subscription|suscripcion)"?`)

// pspCuitKeyRE matches PSP CUIT field.
var pspCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:psp[_\- ]?cuit|cuit[_\- ]?psp|entidad[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// merchantCuitKeyRE matches merchant CUIT field.
var merchantCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:merchant[_\- ]?cuit|comercio[_\- ]?cuit|cuit[_\- ]?comercio|cuit[_\- ]?merchant)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// customerCVURE matches customer CVU/CBU (22 digits).
var customerCVURE = regexp.MustCompile(
	`(?i)"?(?:customer[_\- ]?cvu|cliente[_\- ]?cvu|cvu|cbu)"?\s*[:=>]\s*"?(\d{22})"?`)

// batchIDRE matches a batch identifier.
var batchIDRE = regexp.MustCompile(
	`(?i)"?(?:batch[_\- ]?id|lote[_\- ]?id|lote)"?\s*[:=>]\s*"?([A-Z0-9][A-Z0-9\-\._]{3,64})"?`)

// transactionCountRE matches a transaction count.
var transactionCountRE = regexp.MustCompile(
	`(?i)"?(?:transaction[_\- ]?count|tx[_\- ]?count|transacciones[_\- ]?total|operaciones[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`)

// customerCountRE matches a customer count.
var customerCountRE = regexp.MustCompile(
	`(?i)"?(?:customer[_\- ]?count|clientes[_\- ]?count|unique[_\- ]?customers|usuarios[_\- ]?unicos)"?\s*[:=>]\s*"?(\d{1,12})`)

// merchantCountRE matches a merchant count.
var merchantCountRE = regexp.MustCompile(
	`(?i)"?(?:merchant[_\- ]?count|comercios[_\- ]?count|merchants[_\- ]?total)"?\s*[:=>]\s*"?(\d{1,12})`)

// batchValueRE matches batch aggregate value in ARS.
var batchValueRE = regexp.MustCompile(
	`(?i)"?(?:batch[_\- ]?value[_\- ]?ars|monto[_\- ]?lote[_\- ]?ars|valor[_\- ]?batch[_\- ]?ars|importe[_\- ]?ars)"?\s*[:=>]\s*"?(\d{1,15})`)

// chargebackCountRE matches chargeback count.
var chargebackCountRE = regexp.MustCompile(
	`(?i)"?(?:chargeback[_\- ]?count|contracargos[_\- ]?count|cb[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`)

// ParsePSP parses any PSP artifact body (shared parser).
func ParsePSP(body []byte) PSPFields {
	var out PSPFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := pspNetworkRE.FindSubmatch(body); len(m) > 1 {
		out.PSPNetwork = detectPSPNetwork(string(m[1]))
	}
	if m := settlementRailRE.FindSubmatch(body); len(m) > 1 {
		out.SettlementRail = detectSettlementRail(string(m[1]))
	}
	if m := transactionTypeRE.FindSubmatch(body); len(m) > 1 {
		out.TransactionType = detectTransactionType(string(m[1]))
	}
	if c := pspCuitFromBody(body); c != "" {
		out.PSPCuitRaw = c
	}
	if c := merchantCuitFromBody(body); c != "" {
		out.MerchantCuitRaw = c
	}
	if m := customerCVURE.FindSubmatch(body); len(m) > 1 {
		out.CustomerCVURaw = string(m[1])
	}
	if m := batchIDRE.FindSubmatch(body); len(m) > 1 {
		out.BatchID = string(m[1])
	}
	if m := transactionCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.TransactionCount = v
		}
	}
	if m := customerCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.CustomerCount = v
		}
	}
	if m := merchantCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.MerchantCount = v
		}
	}
	if m := batchValueRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.BatchValueARS = v
		}
	}
	if m := chargebackCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.ChargebackCount = v
		}
	}
	return out
}

// pspCuitFromBody returns the first PSP CUIT match.
func pspCuitFromBody(body []byte) string {
	if m := pspCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// merchantCuitFromBody returns the first merchant CUIT match.
func merchantCuitFromBody(body []byte) string {
	if m := merchantCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectPSPNetwork normalizes a PSP-network string.
func detectPSPNetwork(s string) PSPNetwork {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "banelco"):
		return NetworkBanelco
	case t == "link":
		return NetworkLink
	case strings.Contains(t, "prisma"):
		return NetworkPrisma
	case strings.Contains(t, "mercado") && strings.Contains(t, "pago"):
		return NetworkMercadoPago
	case strings.Contains(t, "uala") || strings.Contains(t, "ualá"):
		return NetworkUala
	case strings.Contains(t, "modo"):
		return NetworkModo
	case strings.Contains(t, "naranja"):
		return NetworkNaranjaX
	case strings.Contains(t, "personal") && strings.Contains(t, "pay"):
		return NetworkPersonalPay
	case strings.Contains(t, "cuenta") && strings.Contains(t, "dni"):
		return NetworkCuentaDNIBAPRO
	case strings.Contains(t, "brubank"):
		return NetworkBrubank
	case strings.Contains(t, "lemon"):
		return NetworkLemon
	case strings.Contains(t, "nubi"):
		return NetworkNubi
	case strings.Contains(t, "belo"):
		return NetworkBelo
	}
	return NetworkUnknown
}

// detectSettlementRail normalizes a settlement-rail string.
func detectSettlementRail(s string) SettlementRail {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "compe"):
		return RailCompe
	case strings.Contains(t, "mep"):
		return RailMEP
	case strings.Contains(t, "coelsa"):
		return RailCOELSA
	case strings.Contains(t, "debin"):
		return RailDEBIN
	case strings.Contains(t, "transfer") || strings.Contains(t, "transferencias"):
		return RailTransfer30
	case strings.Contains(t, "pix"):
		return RailPIXAR
	}
	return RailUnknown
}

// detectTransactionType normalizes a transaction-type string.
func detectTransactionType(s string) TransactionType {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case t == "p2p":
		return TxP2P
	case t == "p2m":
		return TxP2M
	case t == "m2p":
		return TxM2P
	case t == "b2b":
		return TxB2B
	case strings.Contains(t, "payroll") || strings.Contains(t, "nomina"):
		return TxPayroll
	case strings.Contains(t, "vep") || strings.Contains(t, "afip"):
		return TxVEPAFIP
	case strings.Contains(t, "tax") || strings.Contains(t, "impuesto"):
		return TxTaxCollection
	case strings.Contains(t, "utility") || strings.Contains(t, "servicio"):
		return TxUtilityPayment
	case strings.Contains(t, "subscription") || strings.Contains(t, "suscripcion"):
		return TxSubscription
	}
	return TxUnknown
}
