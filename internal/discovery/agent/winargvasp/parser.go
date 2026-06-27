package winargvasp

import (
	"regexp"
	"strconv"
	"strings"
)

// VASPFields captures scalar fields the audit pipeline needs.
type VASPFields struct {
	VASPFirm               VASPFirm
	Blockchain             Blockchain
	TokenClass             TokenClass
	TravelRuleStatus       TravelRuleStatus
	VASPCuitRaw            string
	WalletAddressRaw       string
	CounterpartyVASPRaw    string
	WalletCount            int64
	CustomerCount          int64
	HotWalletBalanceUSD    int64
	ColdWalletBalanceUSD   int64
	SanctionsHitCount      int64
	RedemptionAmountUSD    int64
	HasPassword            bool
	HasSeedPhraseIndicator bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|vasp[_\-]?password|wallet[_\-]?password|api[_\-]?token|api[_\-]?key|api[_\-]?secret|private[_\-]?key)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|vasp[_\-]?password|wallet[_\-]?password|bearer[_\-]?token|private[_\-]?key)\b"?\s*[:=]\s*["'][^"']{1,}["']`)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|vasp[_\-]?password|wallet[_\-]?password|private[_\-]?key)\s*>([^<]{1,})<\s*/`)

// seedPhraseRE matches BIP-39 seed phrase indicators.
var seedPhraseRE = regexp.MustCompile(
	`(?i)"?\b(?:seed[_\- ]?phrase|mnemonic|recovery[_\- ]?phrase|bip[_\- ]?39|backup[_\- ]?phrase|frase[_\- ]?semilla)\b"?\s*[:=]`)

// vaspFirmRE matches a VASP firm marker in body.
var vaspFirmRE = regexp.MustCompile(
	`(?i)\b(lemon[_\- ]?cash|lemoncash|belo|bitso[_\- ]?ar|bitso|ripio|buenbit|bitnovo[_\- ]?ar|bitnovo|satoshitango|decrypto|bitex|letsbit|buda[_\- ]?ar)\b`)

// blockchainRE matches a blockchain field.
var blockchainRE = regexp.MustCompile(
	`(?i)"?(?:blockchain|chain|network|red)"?\s*[:=>]\s*"?(bitcoin|btc|ethereum|eth|tron|trx|solana|sol|polygon|matic|arbitrum|arb|optimism|op|base|bsc|bnb|avalanche|avax|bitcoin[_\- ]?cash|bch|litecoin|ltc|ripple|xrp)"?`)

// tokenClassRE matches a token-class field.
var tokenClassRE = regexp.MustCompile(
	`(?i)"?(?:token[_\- ]?class|token[_\- ]?type|asset[_\- ]?class)"?\s*[:=>]\s*"?(btc[_\- ]?native|erc[_\- ]?20[_\- ]?stablecoin|erc[_\- ]?20[_\- ]?utility|trc[_\- ]?20[_\- ]?stablecoin|sol[_\- ]?spl[_\- ]?stablecoin|nft[_\- ]?erc[_\- ]?721|nft[_\- ]?erc[_\- ]?1155|native[_\- ]?coin|wrapped[_\- ]?coin)"?`)

// travelRuleStatusRE matches Travel-Rule status field.
var travelRuleStatusRE = regexp.MustCompile(
	`(?i)"?(?:travel[_\- ]?rule[_\- ]?status|travel[_\- ]?rule|ivms101[_\- ]?status)"?\s*[:=>]\s*"?(compliant|cumple|pending|pendiente|non[_\- ]?compliant|no[_\- ]?cumple|self[_\- ]?hosted|auto[_\- ]?custodia|below[_\- ]?threshold|debajo[_\- ]?umbral)"?`)

// vaspCuitKeyRE matches VASP CUIT field.
var vaspCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:vasp[_\- ]?cuit|psav[_\- ]?cuit|exchange[_\- ]?cuit|cuit[_\- ]?vasp|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// walletAddrRE matches a wallet address by chain pattern.
// We accept BTC (legacy/SegWit/Taproot) + ETH-style 0x +
// TRON T-prefix + Solana base58 (>= 32 chars).
var walletAddrRE = regexp.MustCompile(
	`(?i)"?(?:wallet[_\- ]?address|address|addr|wallet|to[_\- ]?address|from[_\- ]?address|destination)"?\s*[:=>]\s*"?(0x[a-f0-9]{40}|bc1[a-z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|T[a-km-zA-HJ-NP-Z1-9]{33}|[1-9A-HJ-NP-Za-km-z]{32,44})"?`)

// counterpartyVASPRE matches counterparty VASP identifier in
// Travel Rule IVMS101 messaging.
var counterpartyVASPRE = regexp.MustCompile(
	`(?i)"?(?:counterparty[_\- ]?vasp|beneficiary[_\- ]?vasp|originating[_\- ]?vasp|counterparty[_\- ]?id|to[_\- ]?vasp)"?\s*[:=>]\s*"?([A-Z0-9][A-Z0-9\-\._]{3,64})"?`)

// walletCountRE matches a customer-wallet count.
var walletCountRE = regexp.MustCompile(
	`(?i)"?(?:wallet[_\- ]?count|wallets[_\- ]?total|customer[_\- ]?wallets[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`)

// customerCountRE matches a customer count.
var customerCountRE = regexp.MustCompile(
	`(?i)"?(?:customer[_\- ]?count|clientes[_\- ]?count|kyc[_\- ]?customers[_\- ]?count|usuarios[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`)

// hotWalletBalanceRE matches hot-wallet USD balance.
var hotWalletBalanceRE = regexp.MustCompile(
	`(?i)"?(?:hot[_\- ]?wallet[_\- ]?balance[_\- ]?usd|hot[_\- ]?balance[_\- ]?usd|saldo[_\- ]?caliente[_\- ]?usd)"?\s*[:=>]\s*"?(\d{1,15})`)

// coldWalletBalanceRE matches cold-wallet USD balance.
var coldWalletBalanceRE = regexp.MustCompile(
	`(?i)"?(?:cold[_\- ]?wallet[_\- ]?balance[_\- ]?usd|cold[_\- ]?balance[_\- ]?usd|saldo[_\- ]?frio[_\- ]?usd)"?\s*[:=>]\s*"?(\d{1,15})`)

// sanctionsHitCountRE matches sanctions-hit count.
var sanctionsHitCountRE = regexp.MustCompile(
	`(?i)"?(?:sanctions[_\- ]?hit[_\- ]?count|ofac[_\- ]?hit[_\- ]?count|sanctions[_\- ]?match[_\- ]?count|hits[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`)

// redemptionAmountRE matches redemption amount in USD.
var redemptionAmountRE = regexp.MustCompile(
	`(?i)"?(?:redemption[_\- ]?amount[_\- ]?usd|redemption[_\- ]?usd|redeem[_\- ]?usd|monto[_\- ]?redemption[_\- ]?usd)"?\s*[:=>]\s*"?(\d{1,15})`)

// ParseVASP parses any VASP artifact body (shared parser).
func ParseVASP(body []byte) VASPFields {
	var out VASPFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if seedPhraseRE.Match(body) {
		out.HasSeedPhraseIndicator = true
	}
	if m := vaspFirmRE.FindSubmatch(body); len(m) > 1 {
		out.VASPFirm = detectVASPFirm(string(m[1]))
	}
	if m := blockchainRE.FindSubmatch(body); len(m) > 1 {
		out.Blockchain = detectBlockchain(string(m[1]))
	}
	if m := tokenClassRE.FindSubmatch(body); len(m) > 1 {
		out.TokenClass = detectTokenClass(string(m[1]))
	}
	if m := travelRuleStatusRE.FindSubmatch(body); len(m) > 1 {
		out.TravelRuleStatus = detectTravelRuleStatus(string(m[1]))
	}
	if c := vaspCuitFromBody(body); c != "" {
		out.VASPCuitRaw = c
	}
	if m := walletAddrRE.FindSubmatch(body); len(m) > 1 {
		out.WalletAddressRaw = string(m[1])
	}
	if m := counterpartyVASPRE.FindSubmatch(body); len(m) > 1 {
		out.CounterpartyVASPRaw = string(m[1])
	}
	if m := walletCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.WalletCount = v
		}
	}
	if m := customerCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.CustomerCount = v
		}
	}
	if m := hotWalletBalanceRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.HotWalletBalanceUSD = v
		}
	}
	if m := coldWalletBalanceRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.ColdWalletBalanceUSD = v
		}
	}
	if m := sanctionsHitCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.SanctionsHitCount = v
		}
	}
	if m := redemptionAmountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.RedemptionAmountUSD = v
		}
	}
	return out
}

// vaspCuitFromBody returns the first VASP CUIT match.
func vaspCuitFromBody(body []byte) string {
	if m := vaspCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectVASPFirm normalizes a VASP-firm string.
func detectVASPFirm(s string) VASPFirm {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "lemon"):
		return FirmLemonCash
	case t == "belo":
		return FirmBelo
	case strings.Contains(t, "bitso"):
		return FirmBitsoAR
	case strings.Contains(t, "ripio"):
		return FirmRipio
	case strings.Contains(t, "buenbit"):
		return FirmBuenbit
	case strings.Contains(t, "bitnovo"):
		return FirmBitnovoAR
	case strings.Contains(t, "satoshitango"):
		return FirmSatoshiTango
	case strings.Contains(t, "decrypto"):
		return FirmDecrypto
	case strings.Contains(t, "bitex"):
		return FirmBitex
	case strings.Contains(t, "letsbit"):
		return FirmLetsbit
	case strings.Contains(t, "buda"):
		return FirmBudaAR
	}
	return FirmUnknown
}

// detectBlockchain normalizes a blockchain string.
func detectBlockchain(s string) Blockchain {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "bitcoin") && strings.Contains(t, "cash") ||
		t == "bch":
		return ChainBitcoinCash
	case strings.Contains(t, "bitcoin") || t == "btc":
		return ChainBitcoin
	case strings.Contains(t, "ethereum") || t == "eth":
		return ChainEthereum
	case strings.Contains(t, "tron") || t == "trx":
		return ChainTron
	case strings.Contains(t, "solana") || t == "sol":
		return ChainSolana
	case strings.Contains(t, "polygon") || t == "matic":
		return ChainPolygon
	case strings.Contains(t, "arbitrum") || t == "arb":
		return ChainArbitrum
	case strings.Contains(t, "optimism") || t == "op":
		return ChainOptimism
	case t == "base":
		return ChainBase
	case t == "bsc" || t == "bnb":
		return ChainBSC
	case strings.Contains(t, "avalanche") || t == "avax":
		return ChainAvalanche
	case strings.Contains(t, "litecoin") || t == "ltc":
		return ChainLitecoin
	case strings.Contains(t, "ripple") || t == "xrp":
		return ChainRipple
	}
	return ChainUnknown
}

// detectTokenClass normalizes a token-class string.
func detectTokenClass(s string) TokenClass {
	t := strings.ToLower(strings.TrimSpace(s))
	t = strings.ReplaceAll(t, "_", "-")
	t = strings.ReplaceAll(t, " ", "-")
	switch {
	case strings.Contains(t, "btc") && strings.Contains(t, "native"):
		return TokenBTCNative
	case strings.Contains(t, "trc-20") || strings.Contains(t, "trc20"):
		return TokenTRC20Stablecoin
	case strings.Contains(t, "sol") && strings.Contains(t, "spl"):
		return TokenSOLSPLStablecoin
	case strings.Contains(t, "erc-20") || strings.Contains(t, "erc20"):
		if strings.Contains(t, "stable") {
			return TokenERC20Stablecoin
		}
		return TokenERC20Utility
	case strings.Contains(t, "nft") && strings.Contains(t, "721"):
		return TokenNFTERC721
	case strings.Contains(t, "nft") && strings.Contains(t, "1155"):
		return TokenNFTERC1155
	case strings.Contains(t, "wrapped"):
		return TokenWrappedCoin
	case strings.Contains(t, "native"):
		return TokenNativeCoin
	}
	return TokenUnknown
}

// detectTravelRuleStatus normalizes a Travel-Rule-status string.
func detectTravelRuleStatus(s string) TravelRuleStatus {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "non") || strings.Contains(t, "no_") ||
		strings.Contains(t, "no-") || strings.Contains(t, "no cumple"):
		return TRNonCompliant
	case strings.Contains(t, "compliant") || strings.Contains(t, "cumple"):
		return TRCompliant
	case strings.Contains(t, "pending") || strings.Contains(t, "pendiente"):
		return TRPending
	case strings.Contains(t, "self") || strings.Contains(t, "auto"):
		return TRSelfHosted
	case strings.Contains(t, "below") || strings.Contains(t, "debajo"):
		return TRBelowThreshold
	}
	return TRUnknown
}
