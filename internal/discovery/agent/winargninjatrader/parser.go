package winargninjatrader

import (
	"bufio"
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

// NTFields captures scalar fields the audit pipeline needs
// from an NT8 artifact.
type NTFields struct {
	AccountLogin         string
	StrategyName         string
	BrokerRoute          BrokerRoute
	InstrumentCount      int64
	OptimizerIterations  int64
	HasReplayDump        bool
	HasDataProviderLogin bool
	HasArgentineFutures  bool
}

// accountLoginRE matches `Login=NNN` / `Account=NNN` rows
// in INI / JSON config.
var accountLoginRE = regexp.MustCompile(
	`(?im)^\s*"?(?:Login|Account|AccountName|AccountID)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{3,32})"?`,
)

// accountLoginXMLRE matches `<Login>NNN</Login>` /
// `<Account>NNN</Account>` in connections.xml.
var accountLoginXMLRE = regexp.MustCompile(
	`(?i)<(?:Login|Account|AccountName|AccountID)>([A-Za-z0-9_\-]{3,32})</`,
)

// strategyNameCSRE matches `public class <name> : Strategy`
// in a NinjaScript .cs file.
var strategyNameCSRE = regexp.MustCompile(
	`(?m)public\s+class\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?:Strategy|Indicator|BarsType|DrawingTool|AddOn)`,
)

// optimizerIterationsRE matches an Optimizer XML
// `<Iterations>NN</Iterations>` row.
var optimizerIterationsRE = regexp.MustCompile(
	`(?i)<\s*(?:iterations|optimizer[_\- ]?iterations|total[_\- ]?iterations)\s*>\s*([0-9]+)\s*<`,
)

// dataProviderLoginRE matches `<Username>`, `<Password>`,
// `<APIKey>` in connections.xml.
var dataProviderLoginRE = regexp.MustCompile(
	`(?i)<\s*(?:Username|Password|APIKey|Login)\s*>\s*[^<]+\s*<`,
)

// replayMarkerRE detects a market-replay file marker
// (NT8 stores replay sessions under db\replay\).
var replayMarkerRE = regexp.MustCompile(
	`(?i)(?:market[_\- ]?replay|replay[_\- ]?session|replay[_\- ]?dump|nt[_\- ]?replay)`,
)

// instrumentCountRE counts instrument entries in the
// instrument DB / connection config.
var instrumentCountRE = regexp.MustCompile(
	`(?i)<\s*(?:Instrument|Symbol|Ticker|MasterInstrument)\s*>`,
)

// ParseNTArtifact parses an NT8 body (XML / CS / log) and
// extracts scalar fields.
func ParseNTArtifact(body []byte) NTFields {
	var out NTFields
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	if m := accountLoginRE.FindSubmatch(body); m != nil {
		out.AccountLogin = string(m[1])
	}
	if out.AccountLogin == "" {
		if m := accountLoginXMLRE.FindSubmatch(body); m != nil {
			out.AccountLogin = string(m[1])
		}
	}
	if m := strategyNameCSRE.FindSubmatch(body); m != nil {
		out.StrategyName = string(m[1])
	}
	if m := optimizerIterationsRE.FindSubmatch(body); m != nil {
		n, _ := strconv.ParseInt(string(m[1]), 10, 64)
		out.OptimizerIterations = n
	}
	out.BrokerRoute = BrokerRouteFromBody(body)
	if dataProviderLoginRE.Match(body) {
		out.HasDataProviderLogin = true
	}
	if replayMarkerRE.Match(body) {
		out.HasReplayDump = true
	}
	out.InstrumentCount = int64(len(instrumentCountRE.FindAllIndex(body, -1)))
	// Argentine futures detection.
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for scanner.Scan() {
		line := scanner.Text()
		for _, sym := range ArgentineFuturesSymbols() {
			if strings.Contains(line, sym) {
				out.HasArgentineFutures = true
				break
			}
		}
		if out.HasArgentineFutures {
			break
		}
	}
	return out
}
