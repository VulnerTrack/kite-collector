package winargrefinitiv

import (
	"regexp"
	"strings"
)

// RefinitivFields captures scalar fields the audit pipeline
// needs from a Refinitiv artifact.
type RefinitivFields struct {
	SessionToken           string
	LicenseID              string
	Username               string
	ClienteCuitRaw         string
	DistinctUsers          int64
	DistinctARTickers      int64
	DistinctTickers        int64
	HasPassword            bool
	HasPythonSDKImport     bool
	HasExcelTRFormula      bool
	HasWorldCheckMarker    bool
	HasDatastreamMarker    bool
	HasMachineReadableNews bool
	HasLSEGRebrandMarker   bool
	HasArgentineMarkers    bool
}

// passwordRE matches a password row.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|eikon[_\-]?password|refinitiv[_\-]?password)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|app_key|eikon_secret)\s*=\s*["'][^"']{1,}["']`,
)

// sessionTokenRE matches a Refinitiv session token.
var sessionTokenRE = regexp.MustCompile(
	`(?i)("|')?(?:eikon[_\-]?token|refinitiv[_\-]?token|lseg[_\-]?token|app[_\-]?key|session[_\-]?id|session[_\-]?token|access[_\-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{20,})`,
)

// licenseIDRE matches a Refinitiv license / subscription ID.
var licenseIDRE = regexp.MustCompile(
	`(?i)("|')?(?:license[_\- ]?id|licenseId|user[_\- ]?id|customer[_\- ]?id|UUID|subscription[_\- ]?id)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-]{8,})`,
)

// usernameRE matches Refinitiv username.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:eikon[_\-]?username|refinitiv[_\-]?username|lseg[_\-]?username|username|user|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`,
)

// pythonSDKImportRE detects refinitiv-data / eikon Python SDK.
var pythonSDKImportRE = regexp.MustCompile(
	`(?im)^\s*(?:from\s+refinitiv|import\s+refinitiv|from\s+lseg|import\s+lseg|import\s+eikon|from\s+eikon)`,
)

// excelTRRE detects Excel Eikon =TR()/=RData()/=AdfinX formulas.
var excelTRRE = regexp.MustCompile(
	`(?i)(?:=TR\s*\(|=RData\s*\(|=RHistory\s*\(|=AdfinX\s*\(|=ATR\s*\(|=Headlines\s*\()`,
)

// worldCheckRE detects World-Check screening markers.
var worldCheckRE = regexp.MustCompile(
	`(?i)(?:world[_\- ]?check|wc[_\- ]?screening|aml[_\- ]?screening|pep[_\- ]?screening|sanctions[_\- ]?screening|wco[_\- ]?check)`,
)

// datastreamRE detects Datastream subscription markers.
var datastreamRE = regexp.MustCompile(
	`(?i)(?:datastream|dws[_\- ]?cfg|dsws|dsfetch|RHistory|tick[_\- ]?history|refinitiv[_\- ]?historical)`,
)

// mrnRE detects Reuters / Refinitiv machine-readable news.
var mrnRE = regexp.MustCompile(
	`(?i)(?:reuters[_\- ]?nrt|reuters[_\- ]?mrn|news[_\- ]?machine[_\- ]?readable|mrn[_\- ]?feed|news[_\- ]?analytics|reuters[_\- ]?elektron)`,
)

// lsegRebrandRE detects LSEG Workspace 2024+ rebrand markers.
var lsegRebrandRE = regexp.MustCompile(
	`(?i)(?:lseg[_\- ]?workspace|workspace[_\- ]?2024|lseg[_\- ]?rebrand|refinitiv[_\- ]?lseg|lseg[_\- ]?migration)`,
)

// tickerEntryRE matches a JSON/INI/Excel ticker / RIC entry.
var tickerEntryRE = regexp.MustCompile(
	`(?i)"?(?:ticker|symbol|ric|instrument|reuters[_\- ]?id)"?\s*[:=]\s*"?([A-Za-z0-9_\-\./=]{3,32})`,
)

// arTickerKeyRE matches a bare AR ticker in Refinitiv RIC.
var arTickerKeyRE = regexp.MustCompile(
	`(?i)\b(?:GGAL|YPFD|PAMP|BMA|BBAR|EDN|SUPV|TXAR|COME|TRAN|MIRG|ALUA|TGSU2|TGNO4)\.BA\b|\bAR(?:AL30|GD30|AL35|GD35|AL41|GD41|AY24|AE38|BOPREAL|BPY26|TX26|TX28|TC25|LECAP|BONCER|BONTE)=`,
)

// userLoginRE matches a per-user login event line.
var userLoginRE = regexp.MustCompile(
	`(?im)(?:^|\s)(?:login[_\- ]?user|logged[_\- ]?in[_\- ]?as|user[_\- ]?id|session[_\- ]?user|eikon[_\- ]?user)\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,40})"?`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseRefinitivConfig parses an Eikon / Workspace config.
func ParseRefinitivConfig(body []byte) RefinitivFields {
	var out RefinitivFields
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
	out.DistinctTickers, out.DistinctARTickers = countTickers(body)
	if out.DistinctARTickers > 0 {
		out.HasArgentineMarkers = true
	}
	if mrnRE.Match(body) {
		out.HasMachineReadableNews = true
	}
	if lsegRebrandRE.Match(body) {
		out.HasLSEGRebrandMarker = true
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseRefinitivCredentials parses a credentials body.
func ParseRefinitivCredentials(body []byte) RefinitivFields {
	return ParseRefinitivConfig(body)
}

// ParseRefinitivLicense parses an Eikon.lic body.
func ParseRefinitivLicense(body []byte) RefinitivFields {
	var out RefinitivFields
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

// ParseRefinitivSessionLog parses an eikon.log session log.
func ParseRefinitivSessionLog(body []byte) RefinitivFields {
	var out RefinitivFields
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
	if mrnRE.Match(body) {
		out.HasMachineReadableNews = true
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseLSEGWorkspaceConfig parses a 2024+ LSEG Workspace cfg.
func ParseLSEGWorkspaceConfig(body []byte) RefinitivFields {
	out := ParseRefinitivConfig(body)
	out.HasLSEGRebrandMarker = true
	return out
}

// ParseDatastreamConfig parses a Datastream config body.
func ParseDatastreamConfig(body []byte) RefinitivFields {
	out := ParseRefinitivConfig(body)
	out.HasDatastreamMarker = true
	if !out.HasDatastreamMarker {
		out.HasDatastreamMarker = datastreamRE.Match(body)
	}
	return out
}

// ParseWorldCheckConfig parses a World-Check config body.
func ParseWorldCheckConfig(body []byte) RefinitivFields {
	out := ParseRefinitivConfig(body)
	out.HasWorldCheckMarker = true
	if !out.HasWorldCheckMarker {
		out.HasWorldCheckMarker = worldCheckRE.Match(body)
	}
	return out
}

// ParseRefinitivPythonSDK parses a refinitiv-data Python script.
func ParseRefinitivPythonSDK(body []byte) RefinitivFields {
	var out RefinitivFields
	if len(body) == 0 {
		return out
	}
	if pythonSDKImportRE.Match(body) {
		out.HasPythonSDKImport = true
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
	if mrnRE.Match(body) {
		out.HasMachineReadableNews = true
	}
	if datastreamRE.Match(body) {
		out.HasDatastreamMarker = true
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

// ParseRefinitivExcelAddin parses an Excel workbook with
// Eikon add-in formulas.
func ParseRefinitivExcelAddin(body []byte) RefinitivFields {
	var out RefinitivFields
	if len(body) == 0 {
		return out
	}
	if excelTRRE.Match(body) {
		out.HasExcelTRFormula = true
	}
	out.DistinctTickers, out.DistinctARTickers = countTickers(body)
	if out.DistinctARTickers > 0 {
		out.HasArgentineMarkers = true
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
// AR tickers matched by `arTickerKeyRE` regardless of whether
// they also appear via `tickerEntryRE`.
func countTickers(body []byte) (int64, int64) {
	all := map[string]struct{}{}
	ar := map[string]struct{}{}
	for _, m := range tickerEntryRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" {
			continue
		}
		all[s] = struct{}{}
		if IsArgentineRefinitivTicker(s) {
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
