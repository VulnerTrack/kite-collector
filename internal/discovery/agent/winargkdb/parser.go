package winargkdb

import (
	"regexp"
	"strings"
)

// KDBFields captures scalar fields the audit pipeline needs
// from a KDB+/Q artifact.
type KDBFields struct {
	APIKey              string
	Username            string
	ClienteCuitRaw      string
	LicenseClass        LicenseClass
	KDBNodeRole         KDBNodeRole
	DistinctTablesCount int64
	RPCHandlerCount     int64
	AutoloadChainDepth  int64
	TplogRecordCount    int64
	HasPassword         bool
	HasSubscriberConfig bool
	HasMATbaRofexTable  bool
	HasCMEFuturesTable  bool
	HasUSEquityTable    bool
	HasCryptoData       bool
}

// passwordRE matches a password row in .q script / .qrc.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|kdb[_\-]?password|q[_\-]?password)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line / Q-form
// `pwd:"..."`.
var passwordInlineRE = regexp.MustCompile(
	`(?i)\b(?:password|passwd|api_key|api_secret|kdb[_\-]?password|kdb[_\-]?secret|q[_\-]?password|pwd)\s*[:=]\s*["'][^"']{1,}["']`)

// apiKeyRE matches a KDB+ / external-broker API key embedded in
// a Q feed-handler script.
var apiKeyRE = regexp.MustCompile(
	`(?i)("|')?(?:kdb[_\-]?api[_\-]?key|kdb[_\-]?token|broker[_\-]?token|exchange[_\-]?token|api[_\-]?key|api[_\-]?token|access[_\-]?token)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-\.\+/=]{16,})`)

// usernameRE matches KDB+ / handler login.
var usernameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:kdb[_\-]?username|q[_\-]?username|broker[_\-]?user|username|user|login[_\-]?id|email)"?\s*[:=]\s*"?([A-Za-z0-9_.@\-]{3,80})"?`)

// rpcHandlerRE matches a Q remote-call handler definition.
// `.z.ps` / `.z.po` / `.z.pg` / `.z.ws` are KDB+'s well-known
// hooks for IPC / WebSocket / HTTP / sync RPC; setting any of
// these exposes a remote-code-execution surface.
var rpcHandlerRE = regexp.MustCompile(
	`(?i)(?:\.z\.p[so]\s*:|\.z\.pg\s*:|\.z\.ws\s*:|\.z\.ph\s*:|\.z\.pp\s*:|\.z\.pi\s*:|\.z\.zd\s*:)`)

// subscriberRE detects feed-handler / tickerplant config
// markers.
var subscriberRE = regexp.MustCompile(
	`(?i)(?:tickerplant|feed[_\- ]?handler|subscribe\b|\.u\.sub|\.tp\.|upd\s*:|tp[_\- ]?cfg|sub[_\- ]?fn)`)

// licenseRE detects KX commercial license body (.lic file
// content). KX licenses start with version markers + hex
// fingerprint, but the safest heuristic is to look for
// `kdb+` and `KX Systems` strings in the body.
var licenseRE = regexp.MustCompile(
	`(?i)(?:kdb\+|kx[_\- ]?systems|KXSYS|k4[_\.]lic|kc[_\.]lic|expir(?:y|es)[_\- ]?date|seat[_\- ]?count|cpu[_\- ]?count)`)

// licensePersonalRE detects personal-edition (free) license
// markers — kdb+pe.
var licensePersonalRE = regexp.MustCompile(
	`(?i)(?:kdb\+pe|personal[_\- ]?edition|32[_\- ]?bit[_\- ]?edition|non[_\- ]?commercial)`)

// licenseEvalRE detects evaluation / trial license markers.
var licenseEvalRE = regexp.MustCompile(
	`(?i)(?:evaluation|trial|temporary|30[_\- ]?day|90[_\- ]?day)`)

// tableNameRE matches a Q `.<table>:` table-definition line,
// e.g. `trades:([]ts:`timestamp$();sym:`symbol$();price:`float$())`.
var tableNameRE = regexp.MustCompile(
	`(?m)^\s*([a-zA-Z][a-zA-Z0-9_]{0,30})\s*:\s*\(\s*\[\s*\]`)

// symbolKeywordRE matches symbol-literal mentions inside Q
// scripts — typically backtick + symbol, e.g. `DLR, `ES.
var symbolKeywordRE = regexp.MustCompile(
	"`([A-Z][A-Z0-9.\\-/]{1,16})\\b")

// autoloadRE detects `\l <script>` (load) directives in .qrc /
// startup chains.
var autoloadRE = regexp.MustCompile(
	`(?m)^\s*\\l\s+\S+`)

// tplogRecordRE detects per-record markers in a tplog file.
var tplogRecordRE = regexp.MustCompile(
	`(?i)(?:upd\s*\[|upd\(\s*` + "`" + `[a-z0-9_]+|\bupd\b\s*,)`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// nodeRoleRE detects which KDB+ node role a script implements,
// based on conventional naming + content markers.
var nodeRoleRE = regexp.MustCompile(
	`(?i)(?:tickerplant|feed[_\- ]?handler|\.u\.tick|\bRDB\b|real[_\- ]?time[_\- ]?database|\bHDB\b|historical[_\- ]?database|gateway|\.gw\.|client[_\- ]?proc)`)

// ParseKDBConfig parses a generic KDB+ / .qrc cfg body.
func ParseKDBConfig(body []byte) KDBFields {
	var out KDBFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	if m := usernameRE.FindSubmatch(body); len(m) > 1 {
		out.Username = string(m[1])
	}
	out.AutoloadChainDepth = int64(len(autoloadRE.FindAllIndex(body, -1)))
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseKDBCredentials parses a credentials body.
func ParseKDBCredentials(body []byte) KDBFields {
	return ParseKDBConfig(body)
}

// ParseKDBQScript parses a .q script body.
func ParseKDBQScript(body []byte) KDBFields {
	var out KDBFields
	if len(body) == 0 {
		return out
	}
	if passwordInlineRE.Match(body) {
		out.HasPassword = true
	}
	if m := apiKeyRE.FindSubmatch(body); len(m) > 3 {
		out.APIKey = string(m[3])
	}
	out.RPCHandlerCount = int64(len(rpcHandlerRE.FindAllIndex(body, -1)))
	if subscriberRE.Match(body) {
		out.HasSubscriberConfig = true
	}
	out.KDBNodeRole = detectNodeRole(body)
	out.DistinctTablesCount, out.HasMATbaRofexTable,
		out.HasCMEFuturesTable, out.HasUSEquityTable,
		out.HasCryptoData = classifyKDBTables(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseKDBKScript parses a .k script body.
func ParseKDBKScript(body []byte) KDBFields {
	return ParseKDBQScript(body)
}

// ParseKDBQRCStartup parses a .qrc startup body — counts the
// autoload chain depth.
func ParseKDBQRCStartup(body []byte) KDBFields {
	out := ParseKDBConfig(body)
	out.AutoloadChainDepth = int64(len(autoloadRE.FindAllIndex(body, -1)))
	return out
}

// ParseKDBSubscriberConfig parses a feed-handler / tickerplant
// subscriber config — flags subscriber state + counts RPC
// handlers.
func ParseKDBSubscriberConfig(body []byte) KDBFields {
	out := ParseKDBQScript(body)
	out.HasSubscriberConfig = true
	if out.KDBNodeRole == RoleUnknown {
		out.KDBNodeRole = RoleFeedHandler
	}
	return out
}

// ParseKDBTplog parses a tplog (tick-log) body.
func ParseKDBTplog(body []byte) KDBFields {
	var out KDBFields
	if len(body) == 0 {
		return out
	}
	out.TplogRecordCount = int64(len(tplogRecordRE.FindAllIndex(body, -1)))
	out.DistinctTablesCount, out.HasMATbaRofexTable,
		out.HasCMEFuturesTable, out.HasUSEquityTable,
		out.HasCryptoData = classifyKDBTables(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseKDBLicense parses a KX license (.lic) body and returns
// the license-class fingerprint.
func ParseKDBLicense(body []byte) KDBFields {
	var out KDBFields
	if !licenseRE.Match(body) {
		return out
	}
	switch {
	case licensePersonalRE.Match(body):
		out.LicenseClass = LicensePersonalEdition
	case licenseEvalRE.Match(body):
		out.LicenseClass = LicenseEvaluation
	default:
		out.LicenseClass = LicenseCommercial
	}
	return out
}

// ParseKDBHDBMeta parses HDB meta files (sym, .d, par.txt).
func ParseKDBHDBMeta(body []byte) KDBFields {
	var out KDBFields
	if len(body) == 0 {
		return out
	}
	out.DistinctTablesCount, out.HasMATbaRofexTable,
		out.HasCMEFuturesTable, out.HasUSEquityTable,
		out.HasCryptoData = classifyKDBTables(body)
	return out
}

// cuitFromBody returns a cliente CUIT match.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectNodeRole walks the body for tickerplant / feed-handler
// / RDB / HDB / gateway markers and returns the dominant role.
func detectNodeRole(body []byte) KDBNodeRole {
	matches := nodeRoleRE.FindAll(body, -1)
	if len(matches) == 0 {
		return RoleUnknown
	}
	roles := map[KDBNodeRole]int{}
	for _, m := range matches {
		s := strings.ToLower(string(m))
		switch {
		case strings.Contains(s, "tickerplant") || strings.Contains(s, ".u.tick"):
			roles[RoleTickerplant]++
		case strings.Contains(s, "feed_handler") || strings.Contains(s, "feed-handler"):
			roles[RoleFeedHandler]++
		case strings.Contains(s, "rdb") || strings.Contains(s, "real_time") ||
			strings.Contains(s, "real-time"):
			roles[RoleRDB]++
		case strings.Contains(s, "hdb") || strings.Contains(s, "historical"):
			roles[RoleHDB]++
		case strings.Contains(s, "gateway") || strings.Contains(s, ".gw."):
			roles[RoleGateway]++
		case strings.Contains(s, "client_proc") || strings.Contains(s, "client-proc"):
			roles[RoleClient]++
		}
	}
	if len(roles) >= 2 {
		return RoleMultiRole
	}
	for r := range roles {
		return r
	}
	return RoleUnknown
}

// classifyKDBTables walks the body matching backtick-symbol
// literals (`DLR, `ES, `AAPL) AND table-name definitions; it
// returns (totalDistinct, hasMATba, hasCME, hasUS, hasCrypto).
func classifyKDBTables(body []byte) (total int64, matba, cme, us, crypto bool) {
	seen := map[string]struct{}{}
	for _, m := range tableNameRE.FindAllSubmatch(body, -1) {
		seen[string(m[1])] = struct{}{}
	}
	for _, m := range symbolKeywordRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
		stem := s
		if i := strings.Index(s, "/"); i > 0 {
			stem = s[:i]
		}
		switch {
		case IsMATbaRofexSymbol(stem):
			matba = true
		case IsCryptoSymbol(s) || IsCryptoSymbol(stem):
			crypto = true
		case IsCMEFuturesSymbol(stem):
			cme = true
		case IsUSEquityStem(stem):
			us = true
		}
	}
	return int64(len(seen)), matba, cme, us, crypto
}
