package winargmt

import (
	"bufio"
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// MTFields captures scalar fields the audit pipeline needs
// from an MT artifact (config / source / report).
type MTFields struct {
	BrokerHostname           string
	ServerName               string
	AccountLogin             string
	EAName                   string
	OptimizerInSampleProfit  float64
	OptimizerOutSampleProfit float64
	HasPassword              bool
	HasSignalProvider        bool
}

// passwordIniRE matches `Password=NNN` / `password=NNN` in
// terminal.ini / accounts.ini.
var passwordIniRE = regexp.MustCompile(
	`(?im)^\s*"?(?:Password|Clave|AccountPassword|InvestorPassword)"?\s*[:=]\s*\S+`,
)

// signalProviderRE matches a TradingSignal / SignalsProvider /
// SignalSubscription row indicating a paid signal service.
var signalProviderRE = regexp.MustCompile(
	`(?im)^\s*"?(?:TradingSignal|SignalsProvider|SignalSubscription|Signal_|SignalUser|SignalLogin)"?\s*[:=]\s*\S+`,
)

// accountLoginRE matches `Login=NNNNNN` / `AccountNumber=NNNNNN`.
var accountLoginRE = regexp.MustCompile(
	`(?im)^\s*"?(?:Login|AccountNumber|Account)"?\s*[:=]\s*"?(\d{4,10})"?`,
)

// serverNameRE matches `Server=<name>` / `ServerName=<name>`.
var serverNameRE = regexp.MustCompile(
	`(?im)^\s*"?(?:Server|ServerName|TradeServer)"?\s*[:=]\s*"?([A-Za-z0-9_.\-]{3,80})"?`,
)

// eaNameRE matches `EA=<name>` / `Expert=<name>` in optimize/
// backtest reports.
var eaNameRE = regexp.MustCompile(
	`(?i)("|')?(?:expert|ea|advisor|strategy)("|')?\s*[:=]\s*"?([A-Za-z0-9_\-. ]{2,80})"?`,
)

// optimizerInSampleRE matches `In-Sample Profit: NN.NN`.
var optimizerInSampleRE = regexp.MustCompile(
	`(?i)(?:in[\s_-]?sample[\s_-]?profit|in[\s_-]?sample[\s_-]?net[\s_-]?profit|is[\s_-]?profit)\s*[:=]\s*\$?\s*(-?[0-9]+(?:[.,][0-9]+)?)`,
)

// optimizerOutSampleRE matches `Out-of-Sample Profit: NN.NN`.
var optimizerOutSampleRE = regexp.MustCompile(
	`(?i)(?:out[\s_-]?of[\s_-]?sample[\s_-]?profit|out[\s_-]?sample[\s_-]?profit|oos[\s_-]?profit|forward[\s_-]?profit)\s*[:=]\s*\$?\s*(-?[0-9]+(?:[.,][0-9]+)?)`,
)

// brokerHostExtractRE matches a broker host token in origin.txt
// or servers list line.
var brokerHostExtractRE = regexp.MustCompile(
	`(?i)([A-Za-z0-9][A-Za-z0-9_\-]*\.(?:com|com\.ar|net|org|io)(?:\.[a-z]{2,3})?)`,
)

// ParseMTTerminalConfig parses a terminal.ini / accounts.ini /
// servers.dat-style text body.
//
// Captures: Server=, Login=, Password= presence, signal
// subscription presence, EA name (in [Common] section).
func ParseMTTerminalConfig(body []byte) MTFields {
	var out MTFields
	if len(body) == 0 {
		return out
	}
	if passwordIniRE.Match(body) {
		out.HasPassword = true
	}
	if signalProviderRE.Match(body) {
		out.HasSignalProvider = true
	}
	if m := accountLoginRE.FindSubmatch(body); m != nil {
		out.AccountLogin = string(m[1])
	}
	if m := serverNameRE.FindSubmatch(body); m != nil {
		out.ServerName = string(m[1])
		out.BrokerHostname = string(m[1])
	}
	if out.BrokerHostname == "" {
		// Fall back to first hostname token in the body.
		if m := brokerHostExtractRE.FindSubmatch(body); m != nil {
			out.BrokerHostname = strings.ToLower(string(m[1]))
		}
	}
	if m := eaNameRE.FindSubmatch(body); len(m) > 3 {
		name := strings.TrimSpace(string(m[3]))
		if name != "" && name != "true" && name != "false" {
			out.EAName = name
		}
	}
	return out
}

// ParseMTOrigin parses an origin.txt body. Origin records
// the broker hostname the terminal was installed from.
func ParseMTOrigin(body []byte) MTFields {
	var out MTFields
	if len(body) == 0 {
		return out
	}
	if m := brokerHostExtractRE.FindSubmatch(body); m != nil {
		out.BrokerHostname = strings.ToLower(string(m[1]))
	}
	return out
}

// ParseMTOptimizeReport parses a Strategy Optimizer HTML/CSV
// report and extracts in-sample vs out-of-sample profit.
//
// MT Strategy Optimizer reports both numbers; the OOS dropoff
// percentage is computed from them.
func ParseMTOptimizeReport(body []byte) MTFields {
	var out MTFields
	if len(body) == 0 {
		return out
	}
	if m := optimizerInSampleRE.FindSubmatch(body); m != nil {
		out.OptimizerInSampleProfit = parseFloat(string(m[1]))
	}
	if m := optimizerOutSampleRE.FindSubmatch(body); m != nil {
		out.OptimizerOutSampleProfit = parseFloat(string(m[1]))
	}
	if m := eaNameRE.FindSubmatch(body); len(m) > 3 {
		out.EAName = strings.TrimSpace(string(m[3]))
	}
	return out
}

// OOSDropoffPct computes the out-of-sample profit dropoff as
// a percent of the in-sample profit. Returns 0 if either
// figure is non-positive (an unprofitable in-sample doesn't
// surface as over-fit — the strategy is simply bad).
func OOSDropoffPct(inSample, outSample float64) int {
	if inSample <= 0 {
		return 0
	}
	if outSample >= inSample {
		return 0
	}
	dropoff := (inSample - outSample) / inSample * 100
	if dropoff < 0 {
		return 0
	}
	if dropoff > 100 {
		return 100
	}
	return int(math.Round(dropoff))
}

// ParseMTBacktestReport parses a Strategy Tester HTML/CSV
// report. Same OOS-dropoff calc as optimize report; the
// backtest variant typically has only in-sample.
func ParseMTBacktestReport(body []byte) MTFields {
	return ParseMTOptimizeReport(body)
}

// parseFloat parses a decimal with comma- or dot-separator.
func parseFloat(s string) float64 {
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
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return f
}

// IsMQLSourceImportingDLL reports whether an MQL source body
// declares an `#import "lib.dll"` directive (untrusted DLL
// load — supply-chain risk).
func IsMQLSourceImportingDLL(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	imp := regexp.MustCompile(`(?i)^\s*#\s*import\s+"[^"]+\.dll"`)
	for scanner.Scan() {
		if imp.Match(scanner.Bytes()) {
			return true
		}
	}
	return false
}
