package winargcrypto

import (
	"bufio"
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// CryptoFields captures scalar fields the audit pipeline
// needs from a crypto-PSAV artifact.
type CryptoFields struct {
	APIKey              string
	ClienteCuitRaw      string
	SessionFirstSeen    string
	SessionLastSeen     string
	Period              string
	TradeCount          int64
	OTCP2PCount         int64
	StablecoinCents     int64
	MaxTradeCents       int64
	DistinctPairCount   int64
	HasAPIKey           bool
	HasAPISecret        bool
	HasWalletSeedMarker bool
	HasStrategyImport   bool
	HasAfipMarker       bool
}

// apiKeyRE matches an `api_key` row in JSON/INI/YAML body.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(api[_-]?key)("|')?\s*[:=]\s*("|')?([A-Za-z0-9_\-]{16,})`,
)

// apiSecretRE matches an `api_secret`/`secret_key` row.
var apiSecretRE = regexp.MustCompile(
	`(?i)("|')?(api[_-]?secret|secret[_-]?key|client[_-]?secret)("|')?\s*[:=]\s*("|')?([A-Za-z0-9_\-\+/=]{16,})`,
)

// otcMarkerRE detects OTC P2P trade markers in a log body.
var otcMarkerRE = regexp.MustCompile(
	`(?i)(?:\botc\b|\bp2p\b|peer[\s_-]*to[\s_-]*peer|seller_id|buyer_id|advertisement_id)`,
)

// stablecoinAmountRE matches `USDT_amount=NN.NN` / `usdc_value=NN`.
// The captured numeric value is bounded so trailing CSV fields
// (commas with 3-digit fee, etc.) don't get pulled in.
var stablecoinAmountRE = regexp.MustCompile(
	`(?i)(?:USDT|USDC|DAI|BUSD)[\s_-]*(?:amount|value|ars|notional|total)\s*[:=]\s*([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`,
)

// notionalRE matches a generic notional row. Same bounded
// numeric capture as stablecoinAmountRE.
var notionalRE = regexp.MustCompile(
	`(?i)(?:notional|amount|total|valor|importe|monto)\s*[:=]\s*([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`,
)

// pairRE matches a ticker pair like `BTC/ARS`, `USDT-ARS`.
var pairRE = regexp.MustCompile(
	`\b([A-Z]{3,8})[/_\-]([A-Z]{3,8})\b`,
)

// timestampMinRE matches a timestamp at line start.
var timestampMinRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`,
)

// strategyImportRE detects ccxt / python-binance / pybitso /
// pybinance imports in .py / .ipynb bodies.
var strategyImportRE = regexp.MustCompile(
	`(?im)^\s*(?:from\s+ccxt|import\s+ccxt|from\s+python_binance|import\s+python_binance|from\s+binance|import\s+binance|from\s+pybitso|import\s+pybitso)`,
)

// afipMarkerRE detects AFIP-marker tokens (BIENES PERSONALES,
// RG 5193, RG 5527) that indicate the trader is reporting to
// AFIP.
var afipMarkerRE = regexp.MustCompile(
	`(?i)(?:bienes[\s_-]*personales|rg[\s_-]*5193|rg[\s_-]*5527|afip[\s_-]*cripto|declaraci[oó]n[\s_-]*jurada)`,
)

// clienteCuitKeyRE matches a labeled cliente CUIT.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// bip39MarkerRE detects the canonical 12 / 24-word BIP39
// seed-phrase shape by counting common BIP39-wordlist words
// near each other in a body. We don't extract the words;
// we only flag presence.
//
// The check uses the most frequent BIP39 stems (a-prefix:
// abandon, ability, able, about, above, ...). If 6+ of these
// stems appear within a 200-char window, we flag.
var bip39CommonStems = []string{
	"abandon", "ability", "able", "about", "above",
	"absent", "absorb", "abstract", "absurd", "abuse",
	"access", "accident", "account", "accuse", "achieve",
	"acid", "acoustic", "acquire", "across", "act",
	"action", "actor", "actress", "actual", "adapt",
	"add", "addict", "address", "adjust", "admit",
	"adult", "advance", "advice", "aerobic", "affair",
	"afford", "afraid", "again", "age", "agent",
	"agree", "ahead", "aim", "air", "airport",
	"aisle", "alarm", "album", "alcohol", "alert",
	"alien", "all", "alley", "allow", "almost",
}

// ParseCryptoCredentials parses an API-key / credentials.json
// body. Captures api_key / api_secret + hash.
func ParseCryptoCredentials(body []byte) CryptoFields {
	var out CryptoFields
	if len(body) == 0 {
		return out
	}
	if m := apiKeyRE.FindSubmatch(body); m != nil {
		out.HasAPIKey = true
		if len(m) > 5 {
			out.APIKey = string(m[5])
		}
	}
	if apiSecretRE.Match(body) {
		out.HasAPISecret = true
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	if out.ClienteCuitRaw == "" {
		if m := cuitRE.FindSubmatch(body); m != nil {
			out.ClienteCuitRaw = string(m[1]) + string(m[2]) + string(m[3])
		}
	}
	return out
}

// ParseCryptoOTCLog parses an OTC P2P trade log body.
//
// Counts P2P operation entries, captures first/last
// timestamp, max-trade amount.
func ParseCryptoOTCLog(body []byte) CryptoFields {
	var out CryptoFields
	if len(body) == 0 {
		return out
	}
	out.OTCP2PCount = int64(len(otcMarkerRE.FindAllIndex(body, -1)))
	stamps := timestampMinRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	for _, m := range notionalRE.FindAllSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		cents := decimalToCents(string(m[1]))
		if cents > out.MaxTradeCents {
			out.MaxTradeCents = cents
		}
	}
	if afipMarkerRE.Match(body) {
		out.HasAfipMarker = true
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseCryptoStablecoinLog parses a USDT/USDC pair trading
// log. Counts stablecoin volume, max-trade.
func ParseCryptoStablecoinLog(body []byte) CryptoFields {
	var out CryptoFields
	if len(body) == 0 {
		return out
	}
	for _, m := range stablecoinAmountRE.FindAllSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		cents := decimalToCents(string(m[1]))
		if cents > 0 {
			out.StablecoinCents += cents
			if cents > out.MaxTradeCents {
				out.MaxTradeCents = cents
			}
		}
	}
	// Fall back to generic notional if no stablecoin-prefixed
	// amounts were found.
	if out.StablecoinCents == 0 {
		for _, m := range notionalRE.FindAllSubmatch(body, -1) {
			cents := decimalToCents(string(m[1]))
			if cents > 0 {
				out.StablecoinCents += cents
				if cents > out.MaxTradeCents {
					out.MaxTradeCents = cents
				}
			}
		}
	}
	pairs := map[string]struct{}{}
	for _, m := range pairRE.FindAllSubmatch(body, -1) {
		if len(m) < 3 {
			continue
		}
		left := strings.ToUpper(string(m[1]))
		right := strings.ToUpper(string(m[2]))
		if IsStablecoinPair(left) || IsStablecoinPair(right) {
			pairs[left+"/"+right] = struct{}{}
		}
	}
	out.DistinctPairCount = int64(len(pairs))
	// Trade count = total notional matches.
	out.TradeCount = int64(len(notionalRE.FindAllIndex(body, -1)))
	if afipMarkerRE.Match(body) {
		out.HasAfipMarker = true
	}
	stamps := timestampMinRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	return out
}

// ParseCryptoAccountExport parses a generic account-export CSV
// or XLSX-derived body. Captures trade count + per-row max.
func ParseCryptoAccountExport(body []byte) CryptoFields {
	var out CryptoFields
	if len(body) == 0 {
		return out
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' || line[0] == ';' {
			continue
		}
		out.TradeCount++
		if m := notionalRE.FindSubmatch(line); m != nil {
			cents := decimalToCents(string(m[1]))
			if cents > out.MaxTradeCents {
				out.MaxTradeCents = cents
			}
		}
	}
	// Subtract the header row (first non-empty line counted).
	if out.TradeCount > 0 {
		out.TradeCount--
	}
	if afipMarkerRE.Match(body) {
		out.HasAfipMarker = true
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	return out
}

// ParseCryptoWalletSeed scans for BIP39 stems clustered in a
// short window. Returns presence-only — the raw words are
// NEVER captured. Returns true (in CryptoFields.Has...) only
// when ≥ 6 distinct common stems appear in a 200-char window.
func ParseCryptoWalletSeed(body []byte) CryptoFields {
	var out CryptoFields
	if len(body) == 0 {
		return out
	}
	out.HasWalletSeedMarker = HasBIP39ClusterMarker(body)
	return out
}

// HasBIP39ClusterMarker reports whether the body has a
// cluster of common BIP39 stems within a 200-byte window.
// Implementation is intentionally conservative — we count
// distinct stems and gate on a strict threshold to avoid
// false positives in dictionary / wordlist files.
//
// Small bodies (< 200 bytes) are scanned as a single window
// so that a tight 12-word phrase still trips the detector.
func HasBIP39ClusterMarker(body []byte) bool {
	if len(body) < 30 {
		return false
	}
	lower := bytes.ToLower(body)
	const window = 200
	const minDistinctStems = 6
	scan := func(slice []byte) bool {
		seen := map[string]struct{}{}
		for _, stem := range bip39CommonStems {
			if bytes.Contains(slice, []byte(stem)) {
				seen[stem] = struct{}{}
				if len(seen) >= minDistinctStems {
					return true
				}
			}
		}
		return false
	}
	if len(lower) <= window {
		return scan(lower)
	}
	for i := 0; i+window <= len(lower); i += 100 {
		if scan(lower[i : i+window]) {
			return true
		}
	}
	return scan(lower[len(lower)-window:])
}

// ParseCryptoStrategy parses a .py / .ipynb body and detects
// ccxt / python-binance / pybitso imports.
func ParseCryptoStrategy(body []byte) CryptoFields {
	var out CryptoFields
	if len(body) == 0 {
		return out
	}
	if strategyImportRE.Match(body) {
		out.HasStrategyImport = true
	}
	return out
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
