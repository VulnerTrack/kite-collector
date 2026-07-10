package winarglemoncash

import (
	"regexp"
	"strconv"
	"strings"
)

// LemonFields captures scalar fields the audit pipeline needs
// from a Lemon Cash artifact.
type LemonFields struct {
	AccessToken           string
	RefreshToken          string
	WebhookSecret         string
	Username              string
	LemonUserID           string
	LemonAppID            string
	ClienteCuitRaw        string
	ClienteDNI            string
	CryptoBalanceUSDCents int64
	TradeRecordCount      int64
	CardTxCount           int64
	EarnPositionCount     int64
	DistinctAssetsCount   int64
	PIISignalCount        int64
	HasPassword           bool
	HasAccessToken        bool
	HasRefreshToken       bool
	HasSDKCredentials     bool
	HasWebhookSecret      bool
	HasUSDTARSArbitrage   bool
	HasKYCMarkers         bool
}

// passwordRE matches a password row in .env / config.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|lemon[_\-]?password|client[_\-]?secret|app[_\-]?secret|LEMON_CLIENT_SECRET)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|lemon[_\-]?password|lemon[_\-]?secret|client[_\-]?secret|app[_\-]?secret)\s*=\s*["'][^"']{1,}["']`,
)

// accessTokenRE matches a Lemon OAuth2 access token.
var accessTokenRE = regexp.MustCompile(
	`(?i)("|')?(?:lemon[_\-]?access[_\-]?token|access[_\-]?token|LEMON_ACCESS_TOKEN|access_token|bearer)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{24,})`,
)

// refreshTokenRE matches a Lemon OAuth2 refresh token.
var refreshTokenRE = regexp.MustCompile(
	`(?i)("|')?(?:lemon[_\-]?refresh[_\-]?token|refresh[_\-]?token|LEMON_REFRESH_TOKEN|refresh_token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{24,})`,
)

// clientIDRE matches a Lemon application client_id.
var clientIDRE = regexp.MustCompile(
	`(?i)"?(?:lemon[_\-]?client[_\-]?id|client[_\-]?id|LEMON_CLIENT_ID|app[_\-]?id)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{8,64})`,
)

// userIDRE matches a Lemon user_id.
var userIDRE = regexp.MustCompile(
	`(?i)"?(?:lemon[_\-]?user[_\-]?id|user[_\-]?id|LEMON_USER_ID)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{6,32})`,
)

// usernameRE matches Lemon login.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:lemon[_\-]?username|lemon[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// webhookSecretRE matches a webhook signing key.
var webhookSecretRE = regexp.MustCompile(
	`(?i)("|')?(?:webhook[_\-]?secret|webhook[_\-]?signing[_\-]?key|LEMON_WEBHOOK_SECRET|x-?signature|notification[_\-]?secret)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`,
)

// usdtArsArbitrageRE detects USDT/ARS arbitrage logic — common
// surfaces:
//
//  1. Brecha-cambiaria calculation (`brecha`, `dolar_blue`,
//     `dolar_mep`, `dolar_oficial`).
//  2. USDT/ARS pair references.
//  3. Cross-venue price snapshots (Binance + Lemon).
var usdtArsArbitrageRE = regexp.MustCompile(
	`(?i)(?:brecha[_\- ]?cambiaria|dolar[_\- ]?(?:blue|mep|ccl|tarjeta|oficial)|usdt[_\- ]?ars|usdc[_\- ]?ars|arbitrage|arbitraje|cross[_\- ]?venue[_\- ]?price)`,
)

// kycMarkerRE detects KYC dump markers — KYC payloads
// typically carry `selfie`, `dni_front`, `dni_back`, AML
// screening, or PEP flag.
var kycMarkerRE = regexp.MustCompile(
	`(?i)(?:selfie[_\- ]?(?:ref|url|s3|file)|dni[_\- ]?(?:front|back|image)|aml[_\- ]?screen|pep[_\- ]?(?:flag|check)|kyc[_\- ]?(?:level|tier|approved|status)|liveness[_\- ]?(?:score|check))`,
)

// tradeRowRE matches a per-trade row in trade-log. We accept
// CSV-style `,t-\d+,` row IDs in addition to keyword markers
// because Lemon trade-log exports often elide the `trade_id`
// header keyword on data rows.
var tradeRowRE = regexp.MustCompile(
	`(?i)(?:trade[_\- ]?id|swap[_\- ]?id|buy[_\- ]?id|sell[_\- ]?id|,t-\d+,|,swap-\d+,|^\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}|OrderFilled|FillEvent)`,
)

// cardTxRowRE matches a per-row crypto-card transaction.
var cardTxRowRE = regexp.MustCompile(
	`(?i)(?:card[_\- ]?tx[_\- ]?id|merchant[_\- ]?id|merchant[_\- ]?name|mcc[_\- ]?code|authorization[_\- ]?id|settlement[_\- ]?id|card[_\- ]?transaction)`,
)

// earnRowRE matches a per-row Lemon Earn yield-position entry.
var earnRowRE = regexp.MustCompile(
	`(?i)(?:earn[_\- ]?position|yield[_\- ]?apy|apy|stake[_\- ]?id|reward[_\- ]?id|yield[_\- ]?balance)`,
)

// assetEntryRE matches a per-asset balance line — used for
// distinct-asset and balance sums.
var assetEntryRE = regexp.MustCompile(
	`(?i)(?:asset|currency|coin|ticker|symbol)\s*[:=]\s*"?([A-Za-z0-9_\-/]{2,20})`,
)

// balanceUSDRE matches `balance_usd=` / `usd_amount` fields.
// The `"?` after the key handles JSON-form `"balance_usd":
// 5000` in addition to INI / .env form.
var balanceUSDRE = regexp.MustCompile(
	`(?i)(?:balance[_\- ]?usd|usd[_\- ]?amount|importe[_\- ]?usd|saldo[_\- ]?usd|monto[_\- ]?dolares)"?\s*[:=]\s*"?(\d+(?:[.,]\d+)?)`,
)

// clienteDNIRE matches an AR DNI (`dni: 12345678`) — the `"?`
// after the key handles JSON-form `"dni": "12345678"`.
var clienteDNIRE = regexp.MustCompile(
	`(?i)\b(?:dni|documento|nro_documento|numero_documento)"?\s*[:=]\s*"?(\d{7,8})`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// nameRE matches a `name` / `nombre` field — used for PII
// bundle detection.
var nameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:name|nombre|first_name|last_name|apellido|full_name)"?\s*[:=]\s*"?[A-Za-zÁÉÍÓÚáéíóúÑñ]{2,40}`,
)

// ParseLemonConfig parses a generic Lemon cfg / .env body.
func ParseLemonConfig(body []byte) LemonFields {
	var out LemonFields
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
		out.LemonAppID = string(m[1])
		out.HasSDKCredentials = true
	}
	if m := userIDRE.FindSubmatch(body); len(m) > 1 {
		out.LemonUserID = string(m[1])
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

// ParseLemonCredentials parses a credentials body.
func ParseLemonCredentials(body []byte) LemonFields {
	return ParseLemonConfig(body)
}

// ParseLemonSDKScript parses a Python / JS SDK script body.
func ParseLemonSDKScript(body []byte) LemonFields {
	out := ParseLemonConfig(body)
	if (strings.Contains(strings.ToLower(string(body)),
		"import lemon") ||
		strings.Contains(strings.ToLower(string(body)),
			"require('lemon")) &&
		(out.HasAccessToken || out.HasRefreshToken) {
		out.HasSDKCredentials = true
	}
	if usdtArsArbitrageRE.Match(body) {
		out.HasUSDTARSArbitrage = true
	}
	return out
}

// ParseLemonTradeLog parses a wallet trade-log body.
func ParseLemonTradeLog(body []byte) LemonFields {
	var out LemonFields
	if len(body) == 0 {
		return out
	}
	out.TradeRecordCount = int64(len(tradeRowRE.FindAllIndex(body, -1)))
	out.CryptoBalanceUSDCents = sumUSDBalances(body)
	out.DistinctAssetsCount = countDistinctAssets(body)
	if m := userIDRE.FindSubmatch(body); len(m) > 1 {
		out.LemonUserID = string(m[1])
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

// ParseLemonEarnPositions parses a Lemon Earn yield-positions
// body.
func ParseLemonEarnPositions(body []byte) LemonFields {
	var out LemonFields
	if len(body) == 0 {
		return out
	}
	out.EarnPositionCount = int64(len(earnRowRE.FindAllIndex(body, -1)))
	out.CryptoBalanceUSDCents = sumUSDBalances(body)
	out.DistinctAssetsCount = countDistinctAssets(body)
	if m := userIDRE.FindSubmatch(body); len(m) > 1 {
		out.LemonUserID = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	out.PIISignalCount = piiBundleSignalCount(body, out.ClienteCuitRaw,
		out.ClienteDNI)
	return out
}

// ParseLemonKYCDump parses a KYC PII dump body.
func ParseLemonKYCDump(body []byte) LemonFields {
	var out LemonFields
	if len(body) == 0 {
		return out
	}
	if kycMarkerRE.Match(body) {
		out.HasKYCMarkers = true
	}
	if m := userIDRE.FindSubmatch(body); len(m) > 1 {
		out.LemonUserID = string(m[1])
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

// ParseLemonCardTransactions parses a crypto-card spend body.
func ParseLemonCardTransactions(body []byte) LemonFields {
	var out LemonFields
	if len(body) == 0 {
		return out
	}
	out.CardTxCount = int64(len(cardTxRowRE.FindAllIndex(body, -1)))
	out.CryptoBalanceUSDCents = sumUSDBalances(body)
	if m := userIDRE.FindSubmatch(body); len(m) > 1 {
		out.LemonUserID = string(m[1])
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

// ParseLemonArbitrageScript parses an arbitrage strategy.
func ParseLemonArbitrageScript(body []byte) LemonFields {
	out := ParseLemonSDKScript(body)
	out.HasUSDTARSArbitrage = true
	return out
}

// ParseLemonMarketplaceConfig parses a merchant marketplace cfg.
func ParseLemonMarketplaceConfig(body []byte) LemonFields {
	out := ParseLemonConfig(body)
	if m := webhookSecretRE.FindSubmatch(body); len(m) > 3 {
		out.WebhookSecret = string(m[3])
		out.HasWebhookSecret = true
	}
	return out
}

// ParseLemonWebhookConfig parses a webhook cfg body.
func ParseLemonWebhookConfig(body []byte) LemonFields {
	out := ParseLemonConfig(body)
	if m := webhookSecretRE.FindSubmatch(body); len(m) > 3 {
		out.WebhookSecret = string(m[3])
		out.HasWebhookSecret = true
	}
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

// sumUSDBalances sums all `balance_usd=` numeric fields.
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

// countDistinctAssets counts unique asset/currency tokens.
func countDistinctAssets(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range assetEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
	}
	return int64(len(seen))
}
