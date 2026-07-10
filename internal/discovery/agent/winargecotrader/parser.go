package winargecotrader

import (
	"bufio"
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

// EcoTraderFields captures scalar fields the audit pipeline
// needs from an Eco Trader / ROFEX TraderPro artifact.
type EcoTraderFields struct {
	Login                string
	Server               string
	BrokerMatricula      string
	ClienteCuitRaw       string
	SessionFirstSeen     string
	SessionLastSeen      string
	DistinctFuturesCount int64
	MaxPositionLots      int64
	DollarFuturesLots    int64
	AgroFuturesLots      int64
	HasPassword          bool
	HasInflation         bool
	HasMTRUSDBridge      bool
	HasAfterHours        bool
	IsDirectFIX          bool
	IsDemoAccount        bool
}

// passwordRE matches a line-anchored credential row in INI /
// XML / JSON configs.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*(?:<\s*)?"?(?:password|clave|pass|passwd)"?\s*(?:[:=>]|>)\s*\S+`,
)

// passwordXMLRE matches `<password>…</password>` on a single
// line (Eco Trader settings.xml).
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|clave)\s*>[^<\n]{1,}<\s*/\s*(?:password|clave)\s*>`,
)

// loginRE matches `<login>NNN</login>` / `login = NNN`.
var loginRE = regexp.MustCompile(
	`(?im)(?:^\s*"?login"?\s*[:=]\s*"?(\d{3,15})"?|<\s*login\s*>(\d{3,15})<\s*/\s*login\s*>)`,
)

// serverRE matches `<server>…</server>` / `server = …`.
var serverRE = regexp.MustCompile(
	`(?im)(?:^\s*"?(?:server|servidor|host|gateway|endpoint|broker_host)"?\s*[:=]\s*"?([A-Za-z0-9_.\-:/]{3,128})"?|<\s*(?:server|servidor|host|gateway)\s*>([A-Za-z0-9_.\-:/]{3,128})<\s*/\s*(?:server|servidor|host|gateway)\s*>)`,
)

// fixSessionRE detects a FIX 4.4 session token in a config.
var fixSessionRE = regexp.MustCompile(
	`(?i)(?:8=FIX\.4\.4|SenderCompID|TargetCompID|BeginString=FIX|fix[_\- ]?session|fix[_\- ]?initiator|FIX\.4\.4|fix44\.cfg)`,
)

// demoAccountRE detects a demo account marker.
var demoAccountRE = regexp.MustCompile(
	`(?i)\b(?:demo|simulator|sandbox|paper[_\- ]?trading|cuenta[_\- ]?demo|account[_\- ]?demo|test[_\- ]?env)\b`,
)

// matriculaINIRE matches matrícula in INI / settings.xml row.
var matriculaINIRE = regexp.MustCompile(
	`(?im)^\s*"?(?:matricula|matr[íi]cula|broker[_\- ]?matricula|rofex[_\- ]?matricula|alyc[_\- ]?matricula)"?\s*[:=]\s*"?(\d{1,5})"?`,
)

// matriculaXMLRE matches `<matricula>NN</matricula>` in XML.
var matriculaXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:matricula|matr[íi]cula|broker_?matricula|rofex_?matricula|alyc_?matricula)\s*>(\d{1,5})<\s*/\s*(?:matricula|matr[íi]cula|broker_?matricula|rofex_?matricula|alyc_?matricula)\s*>`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// clienteCuitXMLRE matches `<cliente_cuit>NN-NNNNNNNN-N</cliente_cuit>`.
var clienteCuitXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:cliente[_\-]?cuit|cuit[_\-]?cliente|titular[_\-]?cuit|cuit)\s*>(\d{2}-?\d{8}-?\d)`,
)

// cuitFromBody runs the key and XML form variants.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	if m := clienteCuitXMLRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// timestampRE matches `YYYY-MM-DD HH:MM[:SS]`.
var timestampRE = regexp.MustCompile(
	`(20\d{2}[\-\/](?:0[1-9]|1[0-2])[\-\/](?:0[1-9]|[12]\d|3[01])\s+\d{1,2}:\d{2}(?::\d{2})?)`,
)

// symbolRowRE matches a watchlist / positions symbol entry
// (INI / JSON form, not line-anchored).
var symbolRowRE = regexp.MustCompile(
	`(?i)"?(?:symbol|simbolo|s[ií]mbolo|ticker|instrument|instrumento|underlying)"?\s*[:=]\s*"?([A-Za-z0-9_\-\./]{2,32})`,
)

// symbolXMLRE matches `<symbol>…</symbol>` in XML watchlist.
var symbolXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:symbol|simbolo|ticker|instrument)\s*>([A-Za-z0-9_\-\./]{2,32})<\s*/\s*(?:symbol|simbolo|ticker|instrument)\s*>`,
)

// lotsRE matches a per-position lot count (INI / JSON form,
// not line-anchored).
var lotsRE = regexp.MustCompile(
	`(?i)"?(?:lots?|lotes?|quantity|cantidad|qty|size)"?\s*[:=]\s*"?(\d{1,7})"?`,
)

// concertacionRE detects session concertación markers.
var concertacionRE = regexp.MustCompile(
	`(?i)(?:concertaci[oó]n|trade[_\- ]?confirmed|fill|execution[_\- ]?report|execrpt|execution[_\- ]?confirmed|order[_\- ]?filled)`,
)

// ParseEcoTraderConfig parses settings.xml / settings.ini.
func ParseEcoTraderConfig(body []byte) EcoTraderFields {
	var out EcoTraderFields
	if len(body) == 0 {
		return out
	}
	if passwordXMLRE.Match(body) || passwordRE.Match(body) {
		out.HasPassword = true
	}
	if m := loginRE.FindSubmatch(body); len(m) > 2 {
		if len(m[1]) > 0 {
			out.Login = string(m[1])
		} else if len(m[2]) > 0 {
			out.Login = string(m[2])
		}
	}
	if m := serverRE.FindSubmatch(body); len(m) > 2 {
		if len(m[1]) > 0 {
			out.Server = string(m[1])
		} else if len(m[2]) > 0 {
			out.Server = string(m[2])
		}
	}
	if fixSessionRE.Match(body) {
		out.IsDirectFIX = true
	}
	if demoAccountRE.Match(body) {
		out.IsDemoAccount = true
	}
	out.BrokerMatricula = matriculaFromBody(body)
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// ParseEcoTraderSessionLog parses a session_<dt>.log.
func ParseEcoTraderSessionLog(body []byte) EcoTraderFields {
	var out EcoTraderFields
	if len(body) == 0 {
		return out
	}
	stamps := timestampRE.FindAllSubmatch(body, -1)
	if len(stamps) > 0 {
		out.SessionFirstSeen = string(stamps[0][1])
		out.SessionLastSeen = string(stamps[len(stamps)-1][1])
	}
	if out.SessionFirstSeen != "" && IsAfterHoursStamp(out.SessionFirstSeen) {
		out.HasAfterHours = true
	}
	if !out.HasAfterHours && out.SessionLastSeen != "" &&
		IsAfterHoursStamp(out.SessionLastSeen) {
		out.HasAfterHours = true
	}
	for _, m := range timestampRE.FindAllSubmatch(body, -1) {
		if IsAfterHoursStamp(string(m[1])) {
			out.HasAfterHours = true
			break
		}
	}
	if concertacionRE.Match(body) && len(stamps) > 0 {
		// presence-only; keeps schema slim.
		_ = stamps
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteCuitRaw = string(m[1])
	}
	if fixSessionRE.Match(body) {
		out.IsDirectFIX = true
	}
	out.BrokerMatricula = matriculaFromBody(body)
	return out
}

// ParseEcoTraderPositions parses a positions_cache.json.
func ParseEcoTraderPositions(body []byte) EcoTraderFields {
	var out EcoTraderFields
	if len(body) == 0 {
		return out
	}
	symbols := collectSymbols(body)
	out.DistinctFuturesCount = int64(len(symbols))
	lots := collectLots(body)
	for _, n := range lots {
		if n > out.MaxPositionLots {
			out.MaxPositionLots = n
		}
	}
	out.DollarFuturesLots, out.AgroFuturesLots = sumFuturesLots(body)
	if hasInflationSymbol(symbols) {
		out.HasInflation = true
	}
	if hasMTRUSDSymbol(symbols) {
		out.HasMTRUSDBridge = true
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		out.ClienteCuitRaw = string(m[1])
	}
	out.BrokerMatricula = matriculaFromBody(body)
	return out
}

// ParseEcoTraderWatchlist parses a watchlist artifact.
func ParseEcoTraderWatchlist(body []byte) EcoTraderFields {
	var out EcoTraderFields
	if len(body) == 0 {
		return out
	}
	symbols := collectSymbols(body)
	out.DistinctFuturesCount = int64(len(symbols))
	if hasInflationSymbol(symbols) {
		out.HasInflation = true
	}
	if hasMTRUSDSymbol(symbols) {
		out.HasMTRUSDBridge = true
	}
	if hasDollarFuturesSymbol(symbols) {
		out.DollarFuturesLots = 1
	}
	if hasAgroFuturesSymbol(symbols) {
		out.AgroFuturesLots = 1
	}
	return out
}

// matriculaFromBody runs the INI and XML regex variants.
func matriculaFromBody(body []byte) string {
	if m := matriculaINIRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	if m := matriculaXMLRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// collectSymbols scans line-anchored and XML-tag symbol rows.
func collectSymbols(body []byte) []string {
	seen := map[string]struct{}{}
	for _, m := range symbolRowRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	for _, m := range symbolXMLRE.FindAllSubmatch(body, -1) {
		s := strings.ToUpper(strings.TrimSpace(string(m[1])))
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// collectLots scans line-anchored lot rows.
func collectLots(body []byte) []int64 {
	var out []int64
	for _, m := range lotsRE.FindAllSubmatch(body, -1) {
		n, err := strconv.ParseInt(string(m[1]), 10, 64)
		if err == nil && n > 0 {
			out = append(out, n)
		}
	}
	return out
}

// sumFuturesLots scans body line-by-line for `symbol+lots`
// co-occurrences (positions_cache.json shape). A given line
// may carry both a symbol and a lot count (JSON inline form),
// or they may straddle adjacent lines (INI / XML form).
func sumFuturesLots(body []byte) (int64, int64) {
	var dollar, agro int64
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	var pendingSym string
	for scanner.Scan() {
		line := scanner.Bytes()
		sym := ""
		if m := symbolRowRE.FindSubmatch(line); len(m) > 1 {
			sym = strings.ToUpper(strings.TrimSpace(string(m[1])))
		} else if m := symbolXMLRE.FindSubmatch(line); len(m) > 1 {
			sym = strings.ToUpper(strings.TrimSpace(string(m[1])))
		}
		if sym != "" {
			pendingSym = sym
		}
		if m := lotsRE.FindSubmatch(line); len(m) > 1 {
			n, err := strconv.ParseInt(string(m[1]), 10, 64)
			if err != nil || n <= 0 {
				continue
			}
			if pendingSym == "" {
				continue
			}
			if IsDollarFutures(pendingSym) {
				dollar += n
			}
			if IsAgroFutures(pendingSym) {
				agro += n
			}
			pendingSym = ""
		}
	}
	return dollar, agro
}

// hasInflationSymbol reports CER / UVA membership in a set.
func hasInflationSymbol(syms []string) bool {
	for _, s := range syms {
		if IsInflationFutures(s) {
			return true
		}
	}
	return false
}

// hasMTRUSDSymbol reports MTR-USD membership in a set.
func hasMTRUSDSymbol(syms []string) bool {
	for _, s := range syms {
		if IsMTRUSDBridge(s) {
			return true
		}
	}
	return false
}

// hasDollarFuturesSymbol reports dollar-futures membership.
func hasDollarFuturesSymbol(syms []string) bool {
	for _, s := range syms {
		if IsDollarFutures(s) {
			return true
		}
	}
	return false
}

// hasAgroFuturesSymbol reports agro-futures membership.
func hasAgroFuturesSymbol(syms []string) bool {
	for _, s := range syms {
		if IsAgroFutures(s) {
			return true
		}
	}
	return false
}
