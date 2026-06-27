// Package winargmodel audits AR quant-strategy ML-model and
// training-data artifact files cached on AR institutional and
// retail-pro quant-desk workstations across Windows, Linux, and
// macOS.
//
// Distinct because the shape is the **ML-strategy IP layer** —
// serialized model weights + training-data corpus + analysis
// reports — distinct from trading platforms (winargninja) and
// Python backtest engines (winargpybacktest / winarglean).
//
// Two unique risk rollups: strategy-IP-exfiltration-risk (model
// weights = serialized trading edge) and training-data-PII-risk
// (training features may include client KYC or insider tick
// data). Plus pickle-RCE-risk for the Python pickle vulnerability
// (CWE-502).
//
// Read-only by intent. (Project guideline 4.2.)
package winargmodel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	MaxRows        = 16384
	MaxFileBytes   = 16 << 20
	RecentlyWindow = 90 * 24 * time.Hour
)

// LargeTrainingRecordThreshold — > 1M training records flags a
// production-scale dataset (CWE-200 blast radius across the
// underlying corpus).
const LargeTrainingRecordThreshold = 1_000_000

// ArtifactKind pinned to host_arg_model.artifact_kind.
type ArtifactKind string

const (
	KindModelWeights        ArtifactKind = "qm-model-weights"
	KindTrainingDataset     ArtifactKind = "qm-training-dataset"
	KindFeatureStore        ArtifactKind = "qm-feature-store"
	KindHyperparamSearch    ArtifactKind = "qm-hyperparam-search"
	KindWalkForwardAnalysis ArtifactKind = "qm-walk-forward-analysis"
	KindOOSTestResult       ArtifactKind = "qm-oos-test-result"
	KindMonteCarloOutput    ArtifactKind = "qm-monte-carlo-output"
	KindModelDriftAlert     ArtifactKind = "qm-model-drift-alert"
	KindLiveAttribution     ArtifactKind = "qm-live-attribution"
	KindABTestDashboard     ArtifactKind = "qm-ab-test-dashboard"
	KindConfig              ArtifactKind = "qm-config"
	KindCredentials         ArtifactKind = "qm-credentials"
	KindInstaller           ArtifactKind = "qm-installer"
	KindOther               ArtifactKind = "other"
	KindUnknown             ArtifactKind = "unknown"
)

// ModelFramework pinned to host_arg_model.model_framework.
type ModelFramework string

const (
	FrameworkScikitLearn ModelFramework = "scikit-learn"
	FrameworkTensorFlow  ModelFramework = "tensorflow"
	FrameworkPyTorch     ModelFramework = "pytorch"
	FrameworkXGBoost     ModelFramework = "xgboost"
	FrameworkLightGBM    ModelFramework = "lightgbm"
	FrameworkCatBoost    ModelFramework = "catboost"
	FrameworkJAX         ModelFramework = "jax"
	FrameworkONNX        ModelFramework = "onnx"
	FrameworkKeras       ModelFramework = "keras"
	FrameworkHuggingFace ModelFramework = "huggingface"
	FrameworkLlamaCpp    ModelFramework = "llama-cpp"
	FrameworkSafetensors ModelFramework = "safetensors"
	FrameworkCustom      ModelFramework = "custom"
	FrameworkNone        ModelFramework = "none"
	FrameworkUnknown     ModelFramework = "unknown"
)

// StrategyClass pinned to host_arg_model.strategy_class.
type StrategyClass string

const (
	StrategyMarketMaking     StrategyClass = "market-making"
	StrategyArbitrage        StrategyClass = "arbitrage"
	StrategyTrendFollowing   StrategyClass = "trend-following"
	StrategyMeanReversion    StrategyClass = "mean-reversion"
	StrategyFactor           StrategyClass = "factor"
	StrategyHFTExecution     StrategyClass = "hft-execution"
	StrategyMLPrediction     StrategyClass = "ml-prediction"
	StrategySentimentTrading StrategyClass = "sentiment-trading"
	StrategyOptionsPricing   StrategyClass = "options-pricing"
	StrategyVolArbitrage     StrategyClass = "vol-arbitrage"
	StrategySovBond          StrategyClass = "sov-bond"
	StrategyFCIStrategy      StrategyClass = "fci-strategy"
	StrategyCustom           StrategyClass = "custom"
	StrategyNone             StrategyClass = "none"
	StrategyUnknown          StrategyClass = "unknown"
)

// DataSource pinned to host_arg_model.data_source.
type DataSource string

const (
	DataTickData        DataSource = "tick-data"
	DataL1Quote         DataSource = "l1-quote"
	DataL3OrderBook     DataSource = "l3-orderbook"
	DataNewsFeed        DataSource = "news-feed"
	DataFundamentals    DataSource = "fundamentals"
	DataAlternative     DataSource = "alternative-data"
	DataSocialSentiment DataSource = "social-sentiment"
	DataSatellite       DataSource = "satellite"
	DataWeather         DataSource = "weather"
	DataCreditRating    DataSource = "credit-rating"
	DataClientKYC       DataSource = "client-kyc"
	DataOrderFlow       DataSource = "order-flow"
	DataCustom          DataSource = "custom"
	DataNone            DataSource = "none"
	DataUnknown         DataSource = "unknown"
)

// Row mirrors host_arg_model column shape.
type Row struct {
	FilePath                     string         `json:"file_path"`
	FileHash                     string         `json:"file_hash"`
	UserProfile                  string         `json:"user_profile,omitempty"`
	ArtifactKind                 ArtifactKind   `json:"artifact_kind"`
	ModelFramework               ModelFramework `json:"model_framework"`
	StrategyClass                StrategyClass  `json:"strategy_class"`
	DataSource                   DataSource     `json:"data_source,omitempty"`
	ReportingPeriod              string         `json:"reporting_period,omitempty"`
	ClienteCuitPrefix            string         `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4           string         `json:"cliente_cuit_suffix4,omitempty"`
	StrategyID                   string         `json:"strategy_id,omitempty"`
	ModelVersion                 string         `json:"model_version,omitempty"`
	TrainingRecordCount          int64          `json:"training_record_count,omitempty"`
	FeatureCount                 int64          `json:"feature_count,omitempty"`
	HyperparamTrialsCount        int64          `json:"hyperparam_trials_count,omitempty"`
	DrawdownPct                  int64          `json:"drawdown_pct,omitempty"`
	SharpeX100                   int64          `json:"sharpe_x100,omitempty"`
	FileOwnerUID                 int            `json:"file_owner_uid,omitempty"`
	FileMode                     int            `json:"file_mode,omitempty"`
	FileSize                     int64          `json:"file_size,omitempty"`
	HasPasswordInConfig          bool           `json:"has_password_in_config"`
	HasModelWeights              bool           `json:"has_model_weights"`
	HasTrainingDataset           bool           `json:"has_training_dataset"`
	HasFeatureStore              bool           `json:"has_feature_store"`
	HasHyperparamSearch          bool           `json:"has_hyperparam_search"`
	HasWalkForwardAnalysis       bool           `json:"has_walk_forward_analysis"`
	HasOOSTestResult             bool           `json:"has_oos_test_result"`
	HasMonteCarloOutput          bool           `json:"has_monte_carlo_output"`
	HasModelDriftAlert           bool           `json:"has_model_drift_alert"`
	HasLiveAttribution           bool           `json:"has_live_attribution"`
	HasABTestDashboard           bool           `json:"has_ab_test_dashboard"`
	HasPickleFormat              bool           `json:"has_pickle_format"`
	HasSafetensorsFormat         bool           `json:"has_safetensors_format"`
	HasONNXFormat                bool           `json:"has_onnx_format"`
	HasLLMQuantWeights           bool           `json:"has_llm_quant_weights"`
	HasClienteCuit               bool           `json:"has_cliente_cuit"`
	HasPIIFeatures               bool           `json:"has_pii_features"`
	IsRecent                     bool           `json:"is_recent"`
	IsWorldReadable              bool           `json:"is_world_readable"`
	IsGroupReadable              bool           `json:"is_group_readable"`
	IsCredentialExposureRisk     bool           `json:"is_credential_exposure_risk"`
	IsStrategyIPExfiltrationRisk bool           `json:"is_strategy_ip_exfiltration_risk"`
	IsTrainingDataPIIRisk        bool           `json:"is_training_data_pii_risk"`
	IsPickleRCERisk              bool           `json:"is_pickle_rce_risk"`
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// HashSecret returns the SHA-256 hex of a normalized secret.
func HashSecret(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated quant-model install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Quant`,
		`C:\QuantDesk`,
		`C:\MLModels`,
		`C:\Program Files\Quant`,
		"/opt/quant",
		"/opt/quant-desk",
	}
}

// DefaultUsersBases is the curated per-OS user-profile bases.
func DefaultUsersBases() []string {
	return []string{
		`C:\Users`,
		"/home",
		"/Users",
	}
}

// UserModelDirs is the curated per-user relative path set.
//
// Quant analysts commonly hold model artifacts under home-root
// directories named `quant`, `models`, `data`, `notebooks`.
func UserModelDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Quant"},
		{"AppData", "Local", "Quant"},
		{".config", "quant"},
		{".quant"},
		{"quant"},
		{"models"},
		{"data"},
		{"notebooks"},
		{"Documents", "Quant"},
		{"Documents", "Models"},
		{"Documents", "ML"},
		{"Library", "Application Support", "Quant"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a quant-
// model artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pkl", ".joblib",
		".pt", ".pth", ".bin",
		".onnx",
		".h5", ".keras", ".pb",
		".ubj", ".lgb", ".cbm",
		".msgpack",
		".gguf", ".safetensors",
		".parquet", ".arrow", ".feather",
		".csv", ".tsv", ".json", ".html",
		".xml", ".cfg", ".ini",
		".log", ".txt",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the quant-model catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".pkl", ".joblib", ".pt", ".pth",
		".onnx", ".h5", ".keras", ".gguf",
		".safetensors", ".ubj", ".lgb", ".cbm",
		".msgpack", ".parquet", ".arrow", ".feather":
		return true
	}
	for _, tok := range []string{
		"model_", "model-",
		"training_data", "training-data",
		"feature_store", "feature-store",
		"hyperparam", "hyperparameter",
		"walk_forward", "walk-forward", "wfa_",
		"oos_test", "oos-test", "oos_",
		"monte_carlo", "monte-carlo", "mc_sim",
		"model_drift", "model-drift", "drift_alert",
		"live_attribution", "live-attribution",
		"ab_test", "a_b_test",
		"strategy_", "strategy-",
		"quant_", "quant-",
		"optuna", "hyperopt",
		"backtest_result", "backtest-result",
		"trading_model", "trading-model",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ArtifactKindFromName classifies a filename heuristically.
func ArtifactKindFromName(name string) ArtifactKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".msi", ".exe", ".pkg", ".dmg":
		if strings.Contains(n, "quant") || strings.Contains(n, "model") {
			return KindInstaller
		}
		return KindOther
	case ".pkl", ".joblib", ".pt", ".pth",
		".onnx", ".h5", ".keras", ".gguf",
		".safetensors", ".ubj", ".lgb", ".cbm",
		".msgpack":
		return KindModelWeights
	case ".parquet", ".arrow", ".feather":
		if strings.Contains(n, "feature_store") ||
			strings.Contains(n, "feature-store") ||
			strings.Contains(n, "features_") {
			return KindFeatureStore
		}
		return KindTrainingDataset
	case ".html":
		if strings.Contains(n, "ab_test") ||
			strings.Contains(n, "a_b_test") {
			return KindABTestDashboard
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "quant") && strings.Contains(n, "config"):
		return KindConfig
	case strings.Contains(n, "hyperparam") ||
		strings.Contains(n, "hyperparameter") ||
		strings.Contains(n, "optuna") ||
		strings.Contains(n, "hyperopt"):
		return KindHyperparamSearch
	case strings.Contains(n, "walk_forward") ||
		strings.Contains(n, "walk-forward") ||
		strings.Contains(n, "wfa_"):
		return KindWalkForwardAnalysis
	case strings.Contains(n, "oos_test") ||
		strings.Contains(n, "oos-test") ||
		strings.Contains(n, "oos_"):
		return KindOOSTestResult
	case strings.Contains(n, "monte_carlo") ||
		strings.Contains(n, "monte-carlo") ||
		strings.Contains(n, "mc_sim"):
		return KindMonteCarloOutput
	case strings.Contains(n, "model_drift") ||
		strings.Contains(n, "model-drift") ||
		strings.Contains(n, "drift_alert"):
		return KindModelDriftAlert
	case strings.Contains(n, "live_attribution") ||
		strings.Contains(n, "live-attribution"):
		return KindLiveAttribution
	case strings.Contains(n, "ab_test") ||
		strings.Contains(n, "a_b_test"):
		return KindABTestDashboard
	case strings.Contains(n, "training_data") ||
		strings.Contains(n, "training-data"):
		return KindTrainingDataset
	case strings.Contains(n, "feature_store") ||
		strings.Contains(n, "feature-store"):
		return KindFeatureStore
	case strings.Contains(n, "model_") ||
		strings.Contains(n, "model-"):
		return KindModelWeights
	}
	return KindOther
}

// FrameworkFromExt detects model framework from extension.
func FrameworkFromExt(name string) ModelFramework {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pkl":
		// Typically scikit-learn joblib.dump
		if strings.Contains(strings.ToLower(name), "torch") {
			return FrameworkPyTorch
		}
		return FrameworkScikitLearn
	case ".joblib":
		return FrameworkScikitLearn
	case ".pt", ".pth":
		return FrameworkPyTorch
	case ".onnx":
		return FrameworkONNX
	case ".h5", ".keras":
		return FrameworkKeras
	case ".gguf":
		return FrameworkLlamaCpp
	case ".safetensors":
		return FrameworkSafetensors
	case ".ubj":
		return FrameworkXGBoost
	case ".lgb":
		return FrameworkLightGBM
	case ".cbm":
		return FrameworkCatBoost
	case ".msgpack":
		return FrameworkJAX
	case ".bin":
		// Often HuggingFace pytorch_model.bin
		if strings.Contains(strings.ToLower(name), "pytorch_model") {
			return FrameworkHuggingFace
		}
		return FrameworkUnknown
	}
	return FrameworkUnknown
}

// IsPickleExt reports whether the extension is a pickle-derived
// format (RCE risk per CWE-502).
func IsPickleExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".pkl" || ext == ".joblib"
}

// IsSafetensorsExt reports whether the extension is safetensors.
func IsSafetensorsExt(name string) bool {
	return strings.ToLower(filepath.Ext(name)) == ".safetensors"
}

// IsONNXExt reports whether the extension is ONNX.
func IsONNXExt(name string) bool {
	return strings.ToLower(filepath.Ext(name)) == ".onnx"
}

// IsLLMQuantExt reports whether the extension is an LLM-quant
// format.
func IsLLMQuantExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".gguf" || ext == ".safetensors"
}

// CuitEntityPrefixes mirrors AFIP collector list.
func CuitEntityPrefixes() []string {
	return []string{"20", "23", "24", "27", "30", "33", "34"}
}

// IsValidCuitEntityPrefix reports prefix membership.
func IsValidCuitEntityPrefix(p string) bool {
	for _, v := range CuitEntityPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuitRE matches 11-digit CUIT bounded by non-digit / edges.
var cuitRE = regexp.MustCompile(`(?:^|\D)(\d{2})-?(\d{8})-?(\d)(?:\D|$)`)

// CuitFingerprint extracts (prefix, suffix4) from text.
func CuitFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidCuitEntityPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// PeriodFromFilename extracts YYYYMM or YYYY from a filename.
func PeriodFromFilename(name string) string {
	if m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name)); m != nil {
		return m[1] + m[2]
	}
	if m := regexp.MustCompile(`(20\d{2})`).
		FindStringSubmatch(filepath.Base(name)); m != nil {
		return m[1]
	}
	return ""
}

// IsCredentialKind reports whether the kind carries PII /
// credential material.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindModelWeights, KindTrainingDataset,
		KindFeatureStore, KindHyperparamSearch,
		KindWalkForwardAnalysis, KindOOSTestResult,
		KindMonteCarloOutput, KindModelDriftAlert,
		KindLiveAttribution, KindABTestDashboard,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// AnnotateSecurity sets derived booleans.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.ClienteCuitPrefix != "" {
		r.HasClienteCuit = true
	}
	switch r.ArtifactKind {
	case KindModelWeights:
		r.HasModelWeights = true
	case KindTrainingDataset:
		r.HasTrainingDataset = true
	case KindFeatureStore:
		r.HasFeatureStore = true
	case KindHyperparamSearch:
		r.HasHyperparamSearch = true
	case KindWalkForwardAnalysis:
		r.HasWalkForwardAnalysis = true
	case KindOOSTestResult:
		r.HasOOSTestResult = true
	case KindMonteCarloOutput:
		r.HasMonteCarloOutput = true
	case KindModelDriftAlert:
		r.HasModelDriftAlert = true
	case KindLiveAttribution:
		r.HasLiveAttribution = true
	case KindABTestDashboard:
		r.HasABTestDashboard = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag.
	}
	if IsPickleExt(r.FilePath) {
		r.HasPickleFormat = true
	}
	if IsSafetensorsExt(r.FilePath) {
		r.HasSafetensorsFormat = true
	}
	if IsONNXExt(r.FilePath) {
		r.HasONNXFormat = true
	}
	if IsLLMQuantExt(r.FilePath) {
		r.HasLLMQuantWeights = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasModelWeights ||
		r.HasTrainingDataset || r.HasFeatureStore ||
		r.HasClienteCuit
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && r.HasModelWeights {
		r.IsStrategyIPExfiltrationRisk = true
	}
	if readable && (r.HasTrainingDataset || r.HasFeatureStore) &&
		(r.HasPIIFeatures || r.HasClienteCuit ||
			r.DataSource == DataClientKYC) {
		r.IsTrainingDataPIIRisk = true
	}
	if readable && r.HasPickleFormat {
		r.IsPickleRCERisk = true
	}
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].ArtifactKind != rs[j].ArtifactKind {
			return rs[i].ArtifactKind < rs[j].ArtifactKind
		}
		return rs[i].ReportingPeriod < rs[j].ReportingPeriod
	})
}
