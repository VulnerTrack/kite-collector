package winargbloomberg

import (
	"regexp"
	"strings"
)

// BloombergFields captures scalar fields the audit pipeline
// needs from a Bloomberg artifact.
type BloombergFields struct {
	SessionToken        string
	LicenseID           string
	Username            string
	ClienteCuitRaw      string
	DistinctUsers       int64
	DistinctARTickers   int64
	DistinctTickers     int64
	HasPassword         bool
	HasBLPAPIImport     bool
	HasExcelBLPFormula  bool
	HasArgentineMarkers bool
}

// passwordRE matches a password row (line-anchored INI/JSON).
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|BLPPassword|bbg[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|bbg_secret)\s*=\s*["'][^"']{1,}["']`,
)

// sessionTokenRE matches a Bloomberg session token / cookie.
var sessionTokenRE = regexp.MustCompile(
	`(?i)("|')?(?:bbg[_-]?session[_-]?token|blp[_-]?session|session[_-]?id|bloomberg[_-]?token|bbg[_-]?auth)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{20,})`,
)

// licenseIDRE matches a Bloomberg license / subscription ID.
var licenseIDRE = regexp.MustCompile(
	`(?i)("|')?(?:license[_\- ]?id|licenseId|sub[_\- ]?id|account[_\- ]?id|UUID|customer[_\- ]?id)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-]{8,})`,
)

// usernameRE matches Bloomberg username.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:BLPUsername|bbg[_\-]?username|terminal[_\-]?user|username|user|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// blpapiImportRE detects BLPAPI SDK import in Python/Java/C#.
var blpapiImportRE = regexp.MustCompile(
	`(?im)^\s*(?:from\s+blpapi|import\s+blpapi|using\s+Bloomberglp\.Blpapi|import\s+com\.bloomberglp\.blpapi)`,
)

// excelBLPRE detects Excel BLP add-in formula usage.
var excelBLPRE = regexp.MustCompile(
	`(?i)(?:=BDP\s*\(|=BDH\s*\(|=BDS\s*\(|=BLP\s*\(|=BCURVE\s*\(|=BLPAddin)`,
)

// tickerEntryRE matches a JSON/INI/Excel ticker entry.
var tickerEntryRE = regexp.MustCompile(
	`(?i)"?(?:ticker|symbol|security|secid|bbg[_\-]?id)"?\s*[:=]\s*"?([A-Za-z0-9_\-\./\s]{3,32}(?:Equity|Govt|Corp|Index|Comdty|Curncy|AR|US|LN))`,
)

// arTickerKeyRE matches a bare AR ticker in Bloomberg syntax.
var arTickerKeyRE = regexp.MustCompile(
	`(?i)(?:GGAL|YPFD|PAMP|BMA|BBAR|EDN|SUPV|TXAR|COME|TRAN|MIRG|ALUA|TGSU2|TGNO4|AL30|GD30|AL35|GD35|AL41|GD41|AY24|AE38|BOPREAL|BPY26|TX26|TX28|TC25|TC27|LECAP|BONCER|BONTE|YPCUO|YPF)\s+(?:AR|Govt|Corp|Equity|Index)`,
)

// userLoginRE matches a per-user login event line in bbg.log.
var userLoginRE = regexp.MustCompile(
	`(?im)(?:^|\s)(?:login[_\- ]?user|logged[_\- ]?in[_\- ]?as|user[_\- ]?id|session[_\- ]?user)\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,40})"?`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseBloombergConfig parses a BBG terminal / Anywhere config.
func ParseBloombergConfig(body []byte) BloombergFields {
	var out BloombergFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := sessionTokenRE.FindSubmatch(body); len(m) > 3 {
		out.SessionToken = string(m[3])
	}
	if m := licenseIDRE.FindSubmatch(body); len(m) > 3 {
		out.LicenseID = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	out.DistinctTickers, out.DistinctARTickers = countTickers(body)
	if out.DistinctARTickers > 0 {
		out.HasArgentineMarkers = true
	}
	return out
}

// ParseBloombergCredentials parses a Bloomberg credentials body.
func ParseBloombergCredentials(body []byte) BloombergFields {
	return ParseBloombergConfig(body)
}

// ParseBloombergLicense parses a Bloomberg.lic file.
func ParseBloombergLicense(body []byte) BloombergFields {
	var out BloombergFields
	if len(body) == 0 {
		return out
	}
	if m := licenseIDRE.FindSubmatch(body); len(m) > 3 {
		out.LicenseID = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	return out
}

// ParseBloombergSessionLog parses a bbg.log terminal session log.
func ParseBloombergSessionLog(body []byte) BloombergFields {
	var out BloombergFields
	if len(body) == 0 {
		return out
	}
	out.DistinctUsers = countDistinctUsers(body)
	if m := sessionTokenRE.FindSubmatch(body); len(m) > 3 {
		out.SessionToken = string(m[3])
	}
	out.DistinctTickers, out.DistinctARTickers = countTickers(body)
	if out.DistinctARTickers > 0 {
		out.HasArgentineMarkers = true
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseBloombergBPipeConfig parses a B-Pipe managed-feed config.
func ParseBloombergBPipeConfig(body []byte) BloombergFields {
	out := ParseBloombergConfig(body)
	return out
}

// ParseBloombergAIMConfig parses a Bloomberg AIM portfolio config.
func ParseBloombergAIMConfig(body []byte) BloombergFields {
	out := ParseBloombergConfig(body)
	return out
}

// ParseBloombergBLPAPIScript parses a BLPAPI SDK script.
func ParseBloombergBLPAPIScript(body []byte) BloombergFields {
	var out BloombergFields
	if len(body) == 0 {
		return out
	}
	if blpapiImportRE.Match(body) {
		out.HasBLPAPIImport = true
	}
	if passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := sessionTokenRE.FindSubmatch(body); len(m) > 3 {
		out.SessionToken = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	out.DistinctTickers, out.DistinctARTickers = countTickers(body)
	if out.DistinctARTickers > 0 {
		out.HasArgentineMarkers = true
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseBloombergExcelAddin parses an Excel workbook with BLP
// add-in formulas. The body is the unzipped sharedStrings.xml
// or the raw xlsm (we treat as text since xlsm is OOXML zip;
// pattern detection works on the formula text inside).
func ParseBloombergExcelAddin(body []byte) BloombergFields {
	var out BloombergFields
	if len(body) == 0 {
		return out
	}
	if excelBLPRE.Match(body) {
		out.HasExcelBLPFormula = true
	}
	out.DistinctTickers, out.DistinctARTickers = countTickers(body)
	if out.DistinctARTickers > 0 {
		out.HasArgentineMarkers = true
	}
	return out
}

// ParseBloombergVaultCache parses a local Bloomberg Vault cache.
func ParseBloombergVaultCache(body []byte) BloombergFields {
	var out BloombergFields
	if len(body) == 0 {
		return out
	}
	out.DistinctTickers, out.DistinctARTickers = countTickers(body)
	if out.DistinctARTickers > 0 {
		out.HasArgentineMarkers = true
	}
	return out
}

// ParseBloombergAnywhereCert parses a Bloomberg Anywhere mobile
// cert file. Mostly presence-only.
func ParseBloombergAnywhereCert(body []byte) BloombergFields {
	var out BloombergFields
	if len(body) == 0 {
		return out
	}
	if m := licenseIDRE.FindSubmatch(body); len(m) > 3 {
		out.LicenseID = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
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

// countTickers returns (distinctTickers, distinctARTickers).
// AR tickers are matched by `arTickerKeyRE` regardless of
// whether they also appear via `tickerEntryRE`.
func countTickers(body []byte) (int64, int64) {
	all := map[string]struct{}{}
	ar := map[string]struct{}{}
	for _, m := range tickerEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" {
			continue
		}
		all[s] = struct{}{}
		if IsArgentineBloombergTicker(s) {
			ar[s] = struct{}{}
		}
	}
	for _, m := range arTickerKeyRE.FindAll(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m)))
		if s == "" {
			continue
		}
		all[s] = struct{}{}
		ar[s] = struct{}{}
	}
	return int64(len(all)), int64(len(ar))
}

// countDistinctUsers returns the number of distinct user IDs
// observed in a session log.
func countDistinctUsers(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range userLoginRE.FindAllSubmatch(body, -1) {
		u := strings.ToLower(strings.TrimSpace(string(m[1])))
		if u != "" {
			seen[u] = struct{}{}
		}
	}
	return int64(len(seen))
}
