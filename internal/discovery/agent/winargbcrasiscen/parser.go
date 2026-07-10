package winargbcrasiscen

import (
	"bufio"
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

// SISCENFields captures scalar fields the audit pipeline needs
// from a SISCEN artifact.
type SISCENFields struct {
	EntityCode                  string
	Username                    string
	PortalToken                 string
	ClienteCuitRaw              string
	TradeRecordCount            int64
	DistinctISINsCount          int64
	DistinctClientesCount       int64
	DistinctCounterpartiesCount int64
	HighValueTradeCount         int64
	RejectionRecordCount        int64
	SovBondRecordCount          int64
	CorpONRecordCount           int64
	EquityRecordCount           int64
	FCIRecordCount              int64
	RepoRecordCount             int64
	ForwardRecordCount          int64
	SwapRecordCount             int64
	HasPassword                 bool
	HasPortalToken              bool
	HasForeignResident          bool
	HasConcentratedCP           bool
}

// passwordRE matches a password row in siscen_config.xml /
// portal token file (INI / JSON / key=value form).
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|bcra[_\-]?password|siscen[_\-]?password|portal[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|bcra[_\-]?password|siscen[_\-]?password|portal[_\-]?password|portal[_\-]?secret|bcra[_\-]?secret)\s*=\s*["'][^"']{1,}["']`,
)

// passwordXMLRE matches XML-form `<bcra_password>...</bcra_password>`.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<(?:[\w_-]*[_\-])?(?:password|passwd|clave|secret)[\w_-]*>\s*([^<\s]{1,})\s*<`,
)

// portalTokenRE matches a BCRA SISCEN portal bearer token
// (INI / JSON / key=value form).
var portalTokenRE = regexp.MustCompile(
	`(?i)("|')?(?:bcra[_\-]?(?:portal[_\-]?)?token|siscen[_\-]?token|portal[_\-]?token|portal[_\-]?bearer|access[_\-]?token|bearer)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`,
)

// portalTokenXMLRE matches XML-form
// `<bcra_portal_token>...</bcra_portal_token>`.
var portalTokenXMLRE = regexp.MustCompile(
	`(?i)<(?:[\w_-]*[_\-])?(?:token|bearer)[\w_-]*>\s*([A-Za-z0-9_\-\.\+/=]{16,})\s*<`,
)

// usernameRE matches BCRA SISCEN portal login (INI form).
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:bcra[_\-]?username|siscen[_\-]?username|portal[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// usernameXMLRE matches XML-form `<bcra_username>...</bcra_username>`.
var usernameXMLRE = regexp.MustCompile(
	`(?i)<(?:[\w_-]*[_\-])?(?:username|user|login|email)[\w_-]*>\s*([A-Za-z0-9_.@\-]{3,80})\s*<`,
)

// entityCodeRE matches a BCRA entity code (3-5 digit entity
// number assigned by BCRA — every supervised entity has one;
// INI form).
var entityCodeRE = regexp.MustCompile(
	`(?i)"?(?:entidad[_\- ]?codigo|entidad[_\- ]?id|entity[_\- ]?code|codigo[_\- ]?entidad|bcra[_\- ]?id)"?\s*[:=]\s*"?(\d{3,5})`,
)

// entityCodeXMLRE matches XML-form `<entidad_codigo>...</entidad_codigo>`.
var entityCodeXMLRE = regexp.MustCompile(
	`(?i)<(?:entidad[_\-]?codigo|entidad[_\-]?id|entity[_\-]?code|codigo[_\-]?entidad|bcra[_\-]?id)>\s*(\d{3,5})\s*<`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N` in
// INI / JSON / XML form. The trailing separator class
// `[:=>]` covers `cliente_cuit:`, `cliente_cuit=`, and
// `<cliente_cuit>` opening tag.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// cuitScanRE matches any 11-digit CUIT bounded by word edges
// — used for distinct cliente CUIT counts in SISCEN reports.
var cuitScanRE = regexp.MustCompile(`\b(\d{2})-?(\d{8})-?(\d)\b`)

// isinRE matches a 12-char ISIN (2 letters + 9 alphanumerics +
// 1 check digit). Used for distinct ISIN counts.
var isinRE = regexp.MustCompile(`\b([A-Z]{2}[A-Z0-9]{9}\d)\b`)

// rejectionLineRE matches a typical BCRA validation rejection
// line. SISCEN error logs use codes like `ERR-001`, `RC-1234`,
// or `RECHAZO: ...`.
var rejectionLineRE = regexp.MustCompile(
	`(?im)^.*(?:ERR-\d{3,}|RC-\d{3,}|RECHAZO\s*:|REJECTED\s*:|RECHAZADO\s*:|INVALIDO\s*:|INVALID\s*:|VALIDATION\s+ERROR)`,
)

// tradeRowRE detects a trade-detail row (record-type `02`).
// SISCEN fixed-width layouts use leading record-type codes:
// `01` (header), `02` (trade), `99` (trailer). We count `02`
// rows as the trade-record total.
var tradeRowRE = regexp.MustCompile(
	`(?im)^\s*0?2[ |;]?`,
)

// repoMarkerRE detects repo / caución markers in SISCEN rows.
var repoMarkerRE = regexp.MustCompile(
	`(?i)\b(?:CAUCION|CAUCIÓN|REPO|REPORTO|PASE|PASE[_\- ]?BURSATIL)\b`,
)

// forwardMarkerRE detects forward operation markers.
var forwardMarkerRE = regexp.MustCompile(
	`(?i)\b(?:FORWARD|FWD|OPERACION[_\- ]?A[_\- ]?TERMINO|A[_\- ]?TERMINO|FUTURO)\b`,
)

// swapMarkerRE detects swap operation markers.
var swapMarkerRE = regexp.MustCompile(
	`(?i)\b(?:SWAP|PERMUTA|INTERCAMBIO[_\- ]?VALORES)\b`,
)

// fciMarkerRE detects FCI subscription / redemption markers.
var fciMarkerRE = regexp.MustCompile(
	`(?i)\b(?:FCI|CUOTAPARTE|CUOTA[_\- ]?PARTE|SUSCRIPCION|RESCATE)\b`,
)

// corpONMarkerRE detects corporate ON markers.
var corpONMarkerRE = regexp.MustCompile(
	`(?i)\b(?:OBLIGACION[_\- ]?NEGOCIABLE|OBL[_\- ]?NEG|ON\b|CORP[_\- ]?BOND)`,
)

// tradeAmountUSDRE matches `monto_usd` / `usd_amount` columns
// for high-value-trade detection.
var tradeAmountUSDRE = regexp.MustCompile(
	`(?i)(?:monto[_\- ]?usd|usd[_\- ]?amount|importe[_\- ]?usd|monto[_\- ]?dolares)\s*[:=]\s*"?(\d+(?:[.,]\d+)?)`,
)

// foreignResidentRE detects markers indicating non-AR resident
// CUIT (CUITs starting with 55 are reserved for foreign).
var foreignResidentRE = regexp.MustCompile(
	`(?:^|\D)55-?\d{8}-?\d(?:\D|$)`,
)

// ParseSISCENConfig parses siscen_config.xml / portal cfg.
// Supports both INI / JSON / key=value form AND XML-tag form
// because BCRA ships both kinds of config exemplars.
func ParseSISCENConfig(body []byte) SISCENFields {
	var out SISCENFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := portalTokenRE.FindSubmatch(body); len(m) > 3 {
		out.PortalToken = string(m[3])
		out.HasPortalToken = true
	} else if m := portalTokenXMLRE.FindSubmatch(body); len(m) > 1 {
		out.PortalToken = string(m[1])
		out.HasPortalToken = true
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	} else if m := usernameXMLRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if m := entityCodeRE.FindSubmatch(body); len(m) > 1 {
		out.EntityCode = string(m[1])
	} else if m := entityCodeXMLRE.FindSubmatch(body); len(m) > 1 {
		out.EntityCode = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseSISCENCredentials parses a credentials body.
func ParseSISCENCredentials(body []byte) SISCENFields {
	return ParseSISCENConfig(body)
}

// ParseSISCENPortalToken parses a portal-token file. The body
// IS the token (or contains it).
func ParseSISCENPortalToken(body []byte) SISCENFields {
	var out SISCENFields
	if len(body) == 0 {
		return out
	}
	if m := portalTokenRE.FindSubmatch(body); len(m) > 3 {
		out.PortalToken = string(m[3])
		out.HasPortalToken = true
		return out
	}
	// Some portals store the raw token as the file body.
	tok := strings.TrimSpace(string(body))
	if len(tok) >= 16 && len(tok) <= 4096 {
		out.PortalToken = tok
		out.HasPortalToken = true
	}
	return out
}

// ParseSISCENReport parses a fixed-width / CSV SISCEN report.
func ParseSISCENReport(body []byte) SISCENFields {
	var out SISCENFields
	if len(body) == 0 {
		return out
	}
	out.TradeRecordCount = int64(len(tradeRowRE.FindAllIndex(body, -1)))
	out.RepoRecordCount = int64(len(repoMarkerRE.FindAllIndex(body, -1)))
	out.ForwardRecordCount = int64(len(forwardMarkerRE.FindAllIndex(body, -1)))
	out.SwapRecordCount = int64(len(swapMarkerRE.FindAllIndex(body, -1)))
	out.FCIRecordCount = int64(len(fciMarkerRE.FindAllIndex(body, -1)))
	out.CorpONRecordCount = int64(len(corpONMarkerRE.FindAllIndex(body, -1)))
	out.SovBondRecordCount, out.EquityRecordCount,
		out.DistinctISINsCount = classifySecuritiesRecords(body)
	out.DistinctClientesCount, out.HighValueTradeCount,
		out.HasForeignResident = scanClienteAndAmounts(body)
	if m := entityCodeRE.FindSubmatch(body); len(m) > 1 {
		out.EntityCode = string(m[1])
	} else if m := entityCodeXMLRE.FindSubmatch(body); len(m) > 1 {
		out.EntityCode = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	out.HasConcentratedCP = false
	return out
}

// ParseSISCENTemplate parses an entity template (.tpl). Same
// shape as report but typically without filled-in data.
func ParseSISCENTemplate(body []byte) SISCENFields {
	out := ParseSISCENConfig(body)
	if m := entityCodeRE.FindSubmatch(body); len(m) > 1 {
		out.EntityCode = string(m[1])
	}
	return out
}

// ParseSISCENRejectionLog parses BCRA validation error log.
func ParseSISCENRejectionLog(body []byte) SISCENFields {
	var out SISCENFields
	if len(body) == 0 {
		return out
	}
	out.RejectionRecordCount = int64(len(rejectionLineRE.FindAllIndex(body, -1)))
	if m := entityCodeRE.FindSubmatch(body); len(m) > 1 {
		out.EntityCode = string(m[1])
	}
	out.DistinctClientesCount, _, out.HasForeignResident = scanClienteAndAmounts(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseSISCENSourceDump parses an upstream-system dump that
// feeds SISCEN. Same scan as report.
func ParseSISCENSourceDump(body []byte) SISCENFields {
	return ParseSISCENReport(body)
}

// ParseSISCENArchive parses a historical archive. Same scan.
func ParseSISCENArchive(body []byte) SISCENFields {
	return ParseSISCENReport(body)
}

// cuitFromBody returns a cliente CUIT match (per-row form).
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// classifySecuritiesRecords scans the body for AR sovereign-
// bond stems, BYMA equity stems, and ISINs. Returns
// (sovBondCount, equityCount, isinCount).
func classifySecuritiesRecords(body []byte) (sov, eq, isins int64) {
	sovSet := map[string]struct{}{}
	eqSet := map[string]struct{}{}
	isinSet := map[string]struct{}{}
	// Sweep ALL caps tokens 3-8 chars long; classify each.
	tokenRE := regexp.MustCompile(`\b([A-Z][A-Z0-9.\-]{2,7})\b`)
	for _, m := range tokenRE.FindAllSubmatch(body, -1) {
		s := string(m[1])
		switch {
		case IsARSovBondStem(s):
			sovSet[s] = struct{}{}
		case IsBYMAEquityTicker(s):
			eqSet[s] = struct{}{}
		}
	}
	for _, m := range isinRE.FindAllSubmatch(body, -1) {
		isinSet[string(m[1])] = struct{}{}
	}
	return int64(len(sovSet)), int64(len(eqSet)), int64(len(isinSet))
}

// scanClienteAndAmounts walks the body counting distinct CUITs
// (cliente roster size), high-value trades (USD > 1 M), and
// flagging any non-AR (55-prefix) CUIT presence.
func scanClienteAndAmounts(body []byte) (distinctClientes, highVal int64, foreign bool) {
	cuitSet := map[string]struct{}{}
	for _, m := range cuitScanRE.FindAllSubmatch(body, -1) {
		prefix := string(m[1])
		if !IsValidCuitEntityPrefix(prefix) {
			continue
		}
		key := prefix + string(m[2]) + string(m[3])
		cuitSet[key] = struct{}{}
	}
	if foreignResidentRE.Match(body) {
		foreign = true
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		for _, m := range tradeAmountUSDRE.FindAllSubmatch(line, -1) {
			raw := strings.ReplaceAll(strings.ReplaceAll(
				string(m[1]), ".", "",
			), ",", ".")
			v, err := strconv.ParseFloat(raw, 64)
			if err != nil {
				continue
			}
			if v*100 >= float64(HighValueTradeUSDCents) {
				highVal++
			}
		}
	}
	return int64(len(cuitSet)), highVal, foreign
}
