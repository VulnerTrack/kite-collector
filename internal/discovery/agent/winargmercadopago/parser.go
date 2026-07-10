package winargmercadopago

import (
	"regexp"
	"strconv"
	"strings"
)

// MPFields captures scalar fields the audit pipeline needs
// from a MercadoPago artifact.
type MPFields struct {
	AccessToken             string
	RefreshToken            string
	WebhookSecret           string
	Username                string
	MPUserID                string
	MPAppID                 string
	ClienteCuitRaw          string
	ClienteDNI              string
	BalanceUSDCents         int64
	RendimientosRecordCount int64
	InversionesRecordCount  int64
	AuditEventCount         int64
	PIISignalCount          int64
	HasPassword             bool
	HasAccessToken          bool
	HasRefreshToken         bool
	HasSDKCredentials       bool
	HasWebhookSecret        bool
	HasAutoinvest           bool
}

// passwordRE matches a password row.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|mp[_\-]?password|client[_\-]?secret|app[_\-]?secret|MP_CLIENT_SECRET)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|mp[_\-]?password|mp[_\-]?secret|client[_\-]?secret|app[_\-]?secret)\s*=\s*["'][^"']{1,}["']`,
)

// accessTokenRE matches a MercadoPago OAuth2 `access_token`.
// MP tokens follow patterns like `APP_USR-<id>-...-<id>` or
// `TEST-<id>-...` (test mode) — 30+ chars typically.
var accessTokenRE = regexp.MustCompile(
	`(?i)("|')?(?:mp[_\-]?access[_\-]?token|access[_\-]?token|MP_ACCESS_TOKEN|access_token|APP_USR|TEST[\-])("|')?\s*[:=]\s*"?(APP_USR[\-_][A-Za-z0-9_\-\.]{20,}|TEST[\-_][A-Za-z0-9_\-\.]{20,}|[A-Za-z0-9_\-\.]{32,})`,
)

// refreshTokenRE matches a MercadoPago OAuth2 refresh token.
var refreshTokenRE = regexp.MustCompile(
	`(?i)("|')?(?:mp[_\-]?refresh[_\-]?token|refresh[_\-]?token|MP_REFRESH_TOKEN|refresh_token|TG-)("|')?\s*[:=]\s*"?(TG-[A-Za-z0-9_\-\.]{20,}|[A-Za-z0-9_\-\.]{32,})`,
)

// clientIDRE matches a MercadoPago application client_id.
// MP client_ids are 16+ digit numerics (sometimes with dashes).
var clientIDRE = regexp.MustCompile(
	`(?i)"?(?:mp[_\-]?client[_\-]?id|client[_\-]?id|MP_CLIENT_ID|app[_\-]?id)"?\s*[:=]\s*"?(\d{10,32})`,
)

// userIDRE matches a MercadoPago user_id.
var userIDRE = regexp.MustCompile(
	`(?i)"?(?:mp[_\-]?user[_\-]?id|user[_\-]?id|MP_USER_ID)"?\s*[:=]\s*"?(\d{6,16})`,
)

// usernameRE matches MP login.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:mp[_\-]?username|mp[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// webhookSecretRE matches a webhook signing key.
var webhookSecretRE = regexp.MustCompile(
	`(?i)("|')?(?:webhook[_\-]?secret|webhook[_\-]?signing[_\-]?key|MP_WEBHOOK_SECRET|x-?signature|notification[_\-]?secret)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`,
)

// autoinvestRE detects marketplace Rendimientos auto-invest
// armed state. The optional `"?` after each key handles
// JSON-form `"auto_invest": true` as well as INI/.env form
// `auto_invest=true`.
var autoinvestRE = regexp.MustCompile(
	`(?i)(?:auto[_\- ]?invest"?\s*[:=]\s*(?:true|1|on|yes|enabled)|rendimientos[_\- ]?auto[_\- ]?fund"?\s*[:=]\s*(?:true|1|on|yes)|marketplace[_\- ]?auto[_\- ]?invest"?\s*=\s*(?:true|1|on|yes)|investment_strategy"?\s*[:=]\s*"?(?:auto|automatic|enabled))`,
)

// rendimientosRowRE matches a per-row Rendimientos / FCI entry.
// Heuristic: rows containing `cuotaparte` or `mercado_fondo` or
// `money_market` plus numeric values.
var rendimientosRowRE = regexp.MustCompile(
	`(?i)(?:cuotaparte|cuota[_\- ]?parte|mercado[_\- ]?fondo|mercadofondo|money[_\- ]?market|rendimiento|fondo[_\- ]?comun)`,
)

// inversionesRowRE matches a per-row equity / bond entry.
var inversionesRowRE = regexp.MustCompile(
	`(?i)(?:accion|equity|bond|bono|cedear|holding|posicion|posición|stock)`,
)

// auditEventRE matches per-event lines in audit log.
var auditEventRE = regexp.MustCompile(
	`(?i)(?:audit[_\- ]?event|operation[_\- ]?id|event[_\- ]?id|^\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}|\baction\b\s*[:=])`,
)

// balanceUSDRE matches `balance_usd=` / `usd_amount` fields.
var balanceUSDRE = regexp.MustCompile(
	`(?i)(?:balance[_\- ]?usd|usd[_\- ]?amount|importe[_\- ]?usd|saldo[_\- ]?usd|monto[_\- ]?dolares)\s*[:=]\s*"?(\d+(?:[.,]\d+)?)`,
)

// clienteDNIRE matches an AR DNI (`dni: 12345678`).
var clienteDNIRE = regexp.MustCompile(
	`(?i)\b(?:dni|documento|nro_documento|numero_documento)\s*[:=]\s*"?(\d{7,8})`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// nameRE matches a `name` / `nombre` field — used for PII
// bundle detection.
var nameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:name|nombre|first_name|last_name|apellido)"?\s*[:=]\s*"?[A-Za-zÁÉÍÓÚáéíóúÑñ]{2,40}`,
)

// ParseMPConfig parses a generic MP cfg / .env body.
func ParseMPConfig(body []byte) MPFields {
	var out MPFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := accessTokenRE.FindSubmatch(body); len(m) > 3 {
		out.AccessToken = string(m[3])
		out.HasAccessToken = true
	}
	if m := refreshTokenRE.FindSubmatch(body); len(m) > 3 {
		out.RefreshToken = string(m[3])
		out.HasRefreshToken = true
	}
	if m := webhookSecretRE.FindSubmatch(body); len(m) > 3 {
		out.WebhookSecret = string(m[3])
		out.HasWebhookSecret = true
	}
	if m := clientIDRE.FindSubmatch(body); len(m) > 1 {
		out.MPAppID = string(m[1])
		out.HasSDKCredentials = true
	}
	if m := userIDRE.FindSubmatch(body); len(m) > 1 {
		out.MPUserID = string(m[1])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	if m := clienteDNIRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteDNI = string(m[1])
	}
	out.PIISignalCount = piiBundleSignalCount(body, out.ClienteCuitRaw,
		out.ClienteDNI)
	return out
}

// ParseMPCredentials parses a credentials .env / token file.
func ParseMPCredentials(body []byte) MPFields {
	return ParseMPConfig(body)
}

// ParseMPSDKScript parses a Python / JS SDK script body.
func ParseMPSDKScript(body []byte) MPFields {
	out := ParseMPConfig(body)
	// .py / .js scripts that import mercadopago AND embed
	// a token are SDK-credential carriers.
	if (strings.Contains(strings.ToLower(string(body)),
		"import mercadopago") ||
		strings.Contains(strings.ToLower(string(body)),
			"require('mercadopago'")) &&
		(out.HasAccessToken || out.HasRefreshToken) {
		out.HasSDKCredentials = true
	}
	return out
}

// ParseMPWebhookConfig parses a webhook cfg body.
func ParseMPWebhookConfig(body []byte) MPFields {
	out := ParseMPConfig(body)
	// Webhook configs that contain a signing key are
	// always tagged.
	if m := webhookSecretRE.FindSubmatch(body); len(m) > 3 {
		out.WebhookSecret = string(m[3])
		out.HasWebhookSecret = true
	}
	return out
}

// ParseMPRendimientosExport parses a Rendimientos CSV / JSON
// export body.
func ParseMPRendimientosExport(body []byte) MPFields {
	var out MPFields
	if len(body) == 0 {
		return out
	}
	out.RendimientosRecordCount = int64(len(
		rendimientosRowRE.FindAllIndex(body, -1),
	))
	out.BalanceUSDCents = sumUSDBalances(body)
	if m := userIDRE.FindSubmatch(body); len(m) > 1 {
		out.MPUserID = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	if m := clienteDNIRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteDNI = string(m[1])
	}
	out.PIISignalCount = piiBundleSignalCount(body, out.ClienteCuitRaw,
		out.ClienteDNI)
	return out
}

// ParseMPInversionesExport parses an Inversiones equity / bond
// export body.
func ParseMPInversionesExport(body []byte) MPFields {
	var out MPFields
	if len(body) == 0 {
		return out
	}
	out.InversionesRecordCount = int64(len(
		inversionesRowRE.FindAllIndex(body, -1),
	))
	out.BalanceUSDCents = sumUSDBalances(body)
	if m := userIDRE.FindSubmatch(body); len(m) > 1 {
		out.MPUserID = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	if m := clienteDNIRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteDNI = string(m[1])
	}
	out.PIISignalCount = piiBundleSignalCount(body, out.ClienteCuitRaw,
		out.ClienteDNI)
	return out
}

// ParseMPTradeLog parses a trade-operations log.
func ParseMPTradeLog(body []byte) MPFields {
	out := ParseMPInversionesExport(body)
	return out
}

// ParseMPMarketplaceConfig parses a Marketplace auto-invest
// cfg body — flags armed state.
func ParseMPMarketplaceConfig(body []byte) MPFields {
	out := ParseMPConfig(body)
	if autoinvestRE.Match(body) {
		out.HasAutoinvest = true
	}
	return out
}

// ParseMPAuditLog parses an MP audit operations log body.
func ParseMPAuditLog(body []byte) MPFields {
	var out MPFields
	if len(body) == 0 {
		return out
	}
	out.AuditEventCount = int64(len(auditEventRE.FindAllIndex(body, -1)))
	if m := userIDRE.FindSubmatch(body); len(m) > 1 {
		out.MPUserID = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	if m := clienteDNIRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteDNI = string(m[1])
	}
	out.PIISignalCount = piiBundleSignalCount(body, out.ClienteCuitRaw,
		out.ClienteDNI)
	return out
}

// cuitFromBody returns a cliente CUIT match.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// piiBundleSignalCount counts how many distinct PII signals
// the body carries: CUIT, DNI, name. Returns 0..3.
func piiBundleSignalCount(body []byte, cuit, dni string) int64 {
	var n int64
	if cuit != "" {
		n++
	}
	if dni != "" {
		n++
	}
	if nameRE.Match(body) {
		n++
	}
	return n
}

// sumUSDBalances sums all `balance_usd=` numeric fields in
// the body and returns the total in cents.
func sumUSDBalances(body []byte) int64 {
	var total float64
	for _, m := range balanceUSDRE.FindAllSubmatch(body, -1) {
		raw := strings.ReplaceAll(strings.ReplaceAll(
			string(m[1]), ".", "",
		), ",", ".")
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			continue
		}
		total += v
	}
	return int64(total * 100)
}
