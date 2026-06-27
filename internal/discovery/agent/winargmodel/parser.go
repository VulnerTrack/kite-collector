package winargmodel

import (
	"regexp"
	"strconv"
	"strings"
)

// ModelFields captures scalar fields the audit pipeline needs
// from a quant-model artifact.
type ModelFields struct {
	StrategyID            string
	ModelVersion          string
	ClienteCuitRaw        string
	StrategyClass         StrategyClass
	DataSource            DataSource
	TrainingRecordCount   int64
	FeatureCount          int64
	HyperparamTrialsCount int64
	DrawdownPct           int64
	SharpeX100            int64
	HasPassword           bool
	HasPIIFeatures        bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|quant[_\-]?password|model[_\-]?password|registry[_\-]?password|huggingface[_\-]?password)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|quant[_\-]?password|model[_\-]?password|hf[_\-]?token|huggingface[_\-]?token)\b"?\s*[:=]\s*["'][^"']{1,}["']`)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|quant[_\-]?password|model[_\-]?password)\s*>([^<]{1,})<\s*/`)

// strategyIDRE matches a strategy identifier.
var strategyIDRE = regexp.MustCompile(
	`(?i)"?(?:strategy[_\- ]?id|strat[_\- ]?id|model[_\- ]?id|strategy[_\- ]?name)"?\s*[:=>]\s*"?([A-Za-z0-9\-_.]{3,40})"?`)

// modelVersionRE matches a model-version field.
var modelVersionRE = regexp.MustCompile(
	`(?i)"?(?:model[_\- ]?version|version|v|tag)"?\s*[:=>]\s*"?(v?\d+\.\d+(?:\.\d+)?)"?`)

// strategyClassRE matches a strategy-class field.
var strategyClassRE = regexp.MustCompile(
	`(?i)"?(?:strategy[_\- ]?class|strategy[_\- ]?type|estrategia)"?\s*[:=>]\s*"?([A-Za-z\-_ ]{3,40})`)

// dataSourceRE matches a data-source field.
var dataSourceRE = regexp.MustCompile(
	`(?i)"?(?:data[_\- ]?source|source|datasource)"?\s*[:=>]\s*"?([A-Za-z\-_ ]{3,40})`)

// trainingRecordCountRE matches a training-record count field.
var trainingRecordCountRE = regexp.MustCompile(
	`(?i)"?(?:training[_\- ]?record[_\- ]?count|n[_\- ]?samples|sample[_\- ]?count|record[_\- ]?count|rows)"?\s*[:=>]\s*"?(\d{1,15})`)

// featureCountRE matches a feature-count field.
var featureCountRE = regexp.MustCompile(
	`(?i)"?(?:feature[_\- ]?count|n[_\- ]?features|num[_\- ]?features|columns|features)"?\s*[:=>]\s*"?(\d{1,12})`)

// hyperparamTrialsRE matches an Optuna / Hyperopt trial count.
var hyperparamTrialsRE = regexp.MustCompile(
	`(?i)"?(?:hyperparam[_\- ]?trials|n[_\- ]?trials|trials|optuna[_\- ]?trials|hyperopt[_\- ]?trials)"?\s*[:=>]\s*"?(\d{1,12})`)

// drawdownPctRE matches a drawdown-percent field.
var drawdownPctRE = regexp.MustCompile(
	`(?i)"?(?:max[_\- ]?drawdown[_\- ]?pct|max[_\- ]?dd|drawdown[_\- ]?pct|mdd[_\- ]?pct)"?\s*[:=>]\s*"?(\d{1,3}(?:\.\d+)?)`)

// sharpeRE matches a Sharpe-ratio field.
var sharpeRE = regexp.MustCompile(
	`(?i)"?(?:sharpe|sharpe[_\- ]?ratio|sr)"?\s*[:=>]\s*"?(\-?\d+(?:\.\d+)?)`)

// piiFeatureMarkerRE matches markers indicating PII features
// in the training set.
var piiFeatureMarkerRE = regexp.MustCompile(
	`(?i)\b(?:dni[_\- ]?feature|cuit[_\- ]?feature|email[_\- ]?feature|phone[_\- ]?feature|address[_\- ]?feature|date[_\- ]?of[_\- ]?birth|dob[_\- ]?feature|kyc[_\- ]?feature|cliente[_\- ]?feature|customer[_\- ]?id|client[_\- ]?cuit|client[_\- ]?dni|pii[_\- ]?columns)\b`)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|titular[_\- ]?cuit|cuit[_\- ]?cliente|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseModelWeights parses a model-weights body (text portion).
//
// Model-weights files are typically binary, so we extract only
// what's possible from any embedded metadata header. For ONNX
// the file has a Protocol-Buffers binary header that may
// contain ASCII strings for strategy / version.
func ParseModelWeights(body []byte) ModelFields {
	return parseCommon(body)
}

// ParseTrainingDataset parses a training dataset body (header).
func ParseTrainingDataset(body []byte) ModelFields {
	out := parseCommon(body)
	if m := trainingRecordCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.TrainingRecordCount = v
		}
	}
	if m := featureCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.FeatureCount = v
		}
	}
	if piiFeatureMarkerRE.Match(body) {
		out.HasPIIFeatures = true
	}
	return out
}

// ParseFeatureStore parses a feature-store body.
func ParseFeatureStore(body []byte) ModelFields {
	return ParseTrainingDataset(body)
}

// ParseHyperparamSearch parses a hyperparameter-sweep body.
func ParseHyperparamSearch(body []byte) ModelFields {
	out := parseCommon(body)
	if m := hyperparamTrialsRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.HyperparamTrialsCount = v
		}
	}
	return out
}

// ParseWalkForwardAnalysis parses a WFA body.
func ParseWalkForwardAnalysis(body []byte) ModelFields {
	out := parseCommon(body)
	if m := sharpeRE.FindSubmatch(body); len(m) > 1 {
		out.SharpeX100 = parseSharpeX100(string(m[1]))
	}
	if m := drawdownPctRE.FindSubmatch(body); len(m) > 1 {
		out.DrawdownPct = parseDrawdownPct(string(m[1]))
	}
	return out
}

// ParseOOSTestResult parses an OOS-test body.
func ParseOOSTestResult(body []byte) ModelFields {
	return ParseWalkForwardAnalysis(body)
}

// ParseMonteCarloOutput parses a MC sim body.
func ParseMonteCarloOutput(body []byte) ModelFields {
	out := parseCommon(body)
	if m := drawdownPctRE.FindSubmatch(body); len(m) > 1 {
		out.DrawdownPct = parseDrawdownPct(string(m[1]))
	}
	return out
}

// ParseModelDriftAlert parses a drift alert body.
func ParseModelDriftAlert(body []byte) ModelFields {
	return parseCommon(body)
}

// ParseLiveAttribution parses a live attribution body.
func ParseLiveAttribution(body []byte) ModelFields {
	out := parseCommon(body)
	if m := sharpeRE.FindSubmatch(body); len(m) > 1 {
		out.SharpeX100 = parseSharpeX100(string(m[1]))
	}
	return out
}

// ParseABTestDashboard parses an A/B test HTML body.
func ParseABTestDashboard(body []byte) ModelFields {
	return parseCommon(body)
}

// ParseConfig parses a generic quant-tool config body.
func ParseConfig(body []byte) ModelFields {
	return parseCommon(body)
}

// parseCommon extracts the cross-cutting fields.
func parseCommon(body []byte) ModelFields {
	var out ModelFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := strategyIDRE.FindSubmatch(body); len(m) > 1 {
		out.StrategyID = string(m[1])
	}
	if m := modelVersionRE.FindSubmatch(body); len(m) > 1 {
		out.ModelVersion = string(m[1])
	}
	if m := strategyClassRE.FindSubmatch(body); len(m) > 1 {
		out.StrategyClass = detectStrategyClass(string(m[1]))
	}
	if m := dataSourceRE.FindSubmatch(body); len(m) > 1 {
		out.DataSource = detectDataSource(string(m[1]))
	}
	if c := cuitFromBody(body); c != "" {
		out.ClienteCuitRaw = c
	}
	return out
}

// cuitFromBody returns the first cliente CUIT match.
func cuitFromBody(body []byte) string {
	if m := clienteCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectStrategyClass sniffs the strategy-class string.
func detectStrategyClass(s string) StrategyClass {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "market making") ||
		strings.Contains(t, "market-making"):
		return StrategyMarketMaking
	case strings.Contains(t, "vol arbitrage") ||
		strings.Contains(t, "vol-arbitrage") ||
		strings.Contains(t, "volatility"):
		return StrategyVolArbitrage
	case strings.Contains(t, "arbitrage") ||
		strings.Contains(t, "arbitraje"):
		return StrategyArbitrage
	case strings.Contains(t, "trend") ||
		strings.Contains(t, "tendencia"):
		return StrategyTrendFollowing
	case strings.Contains(t, "mean reversion") ||
		strings.Contains(t, "mean-reversion") ||
		strings.Contains(t, "reversion"):
		return StrategyMeanReversion
	case strings.Contains(t, "factor"):
		return StrategyFactor
	case strings.Contains(t, "hft") ||
		strings.Contains(t, "execution"):
		return StrategyHFTExecution
	case strings.Contains(t, "ml prediction") ||
		strings.Contains(t, "ml-prediction") ||
		strings.Contains(t, "machine learning"):
		return StrategyMLPrediction
	case strings.Contains(t, "sentiment"):
		return StrategySentimentTrading
	case strings.Contains(t, "options pricing") ||
		strings.Contains(t, "options-pricing"):
		return StrategyOptionsPricing
	case strings.Contains(t, "sov bond") ||
		strings.Contains(t, "sov-bond") ||
		strings.Contains(t, "soberano"):
		return StrategySovBond
	case strings.Contains(t, "fci"):
		return StrategyFCIStrategy
	}
	return StrategyUnknown
}

// detectDataSource sniffs the data-source string.
func detectDataSource(s string) DataSource {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "l3") ||
		strings.Contains(t, "order book") ||
		strings.Contains(t, "orderbook"):
		return DataL3OrderBook
	case strings.Contains(t, "l1") ||
		strings.Contains(t, "quote"):
		return DataL1Quote
	case strings.Contains(t, "tick"):
		return DataTickData
	case strings.Contains(t, "news"):
		return DataNewsFeed
	case strings.Contains(t, "fundamentals"):
		return DataFundamentals
	case strings.Contains(t, "alternative"):
		return DataAlternative
	case strings.Contains(t, "social") ||
		strings.Contains(t, "sentiment"):
		return DataSocialSentiment
	case strings.Contains(t, "satellite"):
		return DataSatellite
	case strings.Contains(t, "weather"):
		return DataWeather
	case strings.Contains(t, "credit rating") ||
		strings.Contains(t, "credit-rating") ||
		strings.Contains(t, "rating"):
		return DataCreditRating
	case strings.Contains(t, "kyc") ||
		strings.Contains(t, "client kyc"):
		return DataClientKYC
	case strings.Contains(t, "order flow") ||
		strings.Contains(t, "order-flow"):
		return DataOrderFlow
	}
	return DataUnknown
}

// parseSharpeX100 parses a Sharpe ratio and returns it * 100 as
// an int.
func parseSharpeX100(s string) int64 {
	t := strings.TrimSpace(s)
	neg := false
	if strings.HasPrefix(t, "-") {
		neg = true
		t = t[1:]
	}
	dotIdx := strings.IndexByte(t, '.')
	intPart := t
	fracPart := ""
	if dotIdx >= 0 {
		intPart = t[:dotIdx]
		fracPart = t[dotIdx+1:]
	}
	if len(fracPart) > 2 {
		fracPart = fracPart[:2]
	}
	for len(fracPart) < 2 {
		fracPart += "0"
	}
	combined := intPart + fracPart
	v, err := strconv.ParseInt(combined, 10, 64)
	if err != nil {
		return 0
	}
	if neg {
		v = -v
	}
	return v
}

// parseDrawdownPct parses a drawdown percent and returns it as
// an integer percent.
func parseDrawdownPct(s string) int64 {
	t := strings.TrimSpace(s)
	dotIdx := strings.IndexByte(t, '.')
	if dotIdx >= 0 {
		t = t[:dotIdx]
	}
	v, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
