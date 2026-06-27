package winargmodel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindModelWeights), "qm-model-weights"},
		{string(KindTrainingDataset), "qm-training-dataset"},
		{string(KindHyperparamSearch), "qm-hyperparam-search"},
		{string(KindWalkForwardAnalysis), "qm-walk-forward-analysis"},
		{string(KindModelDriftAlert), "qm-model-drift-alert"},
		{string(FrameworkScikitLearn), "scikit-learn"},
		{string(FrameworkTensorFlow), "tensorflow"},
		{string(FrameworkPyTorch), "pytorch"},
		{string(FrameworkXGBoost), "xgboost"},
		{string(FrameworkLightGBM), "lightgbm"},
		{string(FrameworkONNX), "onnx"},
		{string(FrameworkHuggingFace), "huggingface"},
		{string(FrameworkLlamaCpp), "llama-cpp"},
		{string(FrameworkSafetensors), "safetensors"},
		{string(StrategyMarketMaking), "market-making"},
		{string(StrategyArbitrage), "arbitrage"},
		{string(StrategyMLPrediction), "ml-prediction"},
		{string(StrategyVolArbitrage), "vol-arbitrage"},
		{string(DataL3OrderBook), "l3-orderbook"},
		{string(DataClientKYC), "client-kyc"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"model_strategy_v1.pkl",
		"model_strategy.joblib",
		"model_strategy.pt",
		"model_strategy.onnx",
		"model_strategy.h5",
		"model_strategy.safetensors",
		"model_strategy.gguf",
		"training_data_strategy_2026.parquet",
		"feature_store_v1.arrow",
		"hyperparam_search_optuna.csv",
		"walk_forward_strategy.csv",
		"oos_test_strategy.csv",
		"monte_carlo_strategy.csv",
		"model_drift_20260615.json",
		"live_attribution_20260615.csv",
		"ab_test_dashboard.html",
		"quant_config.ini",
	}
	no := []string{"", "factura.xml", "random.bin", "report.pdf", "notes.txt"}
	for _, v := range yes {
		if !IsCandidateName(v) {
			t.Fatalf("expected candidate: %q", v)
		}
	}
	for _, v := range no {
		if IsCandidateName(v) {
			t.Fatalf("expected NOT candidate: %q", v)
		}
	}
}

func TestArtifactKindFromName(t *testing.T) {
	cases := map[string]ArtifactKind{
		"model_strategy_v1.pkl":               KindModelWeights,
		"model_strategy.joblib":               KindModelWeights,
		"model_strategy.onnx":                 KindModelWeights,
		"model_strategy.gguf":                 KindModelWeights,
		"model_strategy.safetensors":          KindModelWeights,
		"training_data_strategy_2026.parquet": KindTrainingDataset,
		"feature_store_v1.arrow":              KindFeatureStore,
		"hyperparam_search_optuna.csv":        KindHyperparamSearch,
		"walk_forward_strategy.csv":           KindWalkForwardAnalysis,
		"oos_test_strategy.csv":               KindOOSTestResult,
		"monte_carlo_strategy.csv":            KindMonteCarloOutput,
		"model_drift_20260615.json":           KindModelDriftAlert,
		"live_attribution_20260615.csv":       KindLiveAttribution,
		"ab_test_dashboard.html":              KindABTestDashboard,
		"quant_config.ini":                    KindConfig,
		"credentials.json":                    KindCredentials,
		"quant_setup.msi":                     KindInstaller,
		"":                                    KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestFrameworkFromExt(t *testing.T) {
	cases := map[string]ModelFramework{
		"model.pkl":         FrameworkScikitLearn,
		"model.joblib":      FrameworkScikitLearn,
		"model_torch.pkl":   FrameworkPyTorch,
		"model.pt":          FrameworkPyTorch,
		"model.pth":         FrameworkPyTorch,
		"model.onnx":        FrameworkONNX,
		"model.h5":          FrameworkKeras,
		"model.keras":       FrameworkKeras,
		"model.gguf":        FrameworkLlamaCpp,
		"model.safetensors": FrameworkSafetensors,
		"model.ubj":         FrameworkXGBoost,
		"model.lgb":         FrameworkLightGBM,
		"model.cbm":         FrameworkCatBoost,
		"model.msgpack":     FrameworkJAX,
		"pytorch_model.bin": FrameworkHuggingFace,
		"random.bin":        FrameworkUnknown,
		"plain.txt":         FrameworkUnknown,
	}
	for in, want := range cases {
		got := FrameworkFromExt(in)
		if got != want {
			t.Fatalf("FrameworkFromExt(%q)=%q want %q", in, got, want)
		}
	}
}

func TestExtensionDetectors(t *testing.T) {
	if !IsPickleExt("model.pkl") {
		t.Fatal(".pkl must be pickle")
	}
	if !IsPickleExt("model.joblib") {
		t.Fatal(".joblib must be pickle")
	}
	if IsPickleExt("model.onnx") {
		t.Fatal(".onnx must NOT be pickle")
	}
	if !IsSafetensorsExt("model.safetensors") {
		t.Fatal(".safetensors must flag")
	}
	if !IsONNXExt("model.onnx") {
		t.Fatal(".onnx must flag")
	}
	if !IsLLMQuantExt("model.gguf") {
		t.Fatal(".gguf must be LLM quant")
	}
	if !IsLLMQuantExt("model.safetensors") {
		t.Fatal(".safetensors must be LLM quant")
	}
}

func TestCuitFingerprint(t *testing.T) {
	p, s := CuitFingerprint("cliente 27-11111111-4")
	if p != "27" || s != "1114" {
		t.Fatalf("cuit=(%q,%q)", p, s)
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindModelWeights, KindTrainingDataset,
		KindFeatureStore, KindHyperparamSearch,
		KindWalkForwardAnalysis, KindOOSTestResult,
		KindMonteCarloOutput, KindModelDriftAlert,
		KindLiveAttribution, KindABTestDashboard,
		KindConfig, KindCredentials,
	}
	for _, k := range yes {
		if !IsCredentialKind(k) {
			t.Fatalf("expected cred: %q", k)
		}
	}
	for _, k := range []ArtifactKind{KindInstaller, KindOther, KindUnknown} {
		if IsCredentialKind(k) {
			t.Fatalf("expected NOT cred: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		FilePath:            "/tmp/model.pkl",
		ArtifactKind:        KindModelWeights,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "30",
		ClienteCuitSuffix4:  "5678",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasModelWeights {
		t.Fatal("model weights kind must auto-flag")
	}
	if !r.HasPickleFormat {
		t.Fatal(".pkl must flag pickle")
	}
	if !r.IsStrategyIPExfiltrationRisk {
		t.Fatal("readable + model weights = IP exfiltration")
	}
	if !r.IsPickleRCERisk {
		t.Fatal("readable + .pkl = pickle RCE")
	}
}

func TestAnnotateTrainingDataPIIRisk(t *testing.T) {
	r := Row{
		FilePath:           "/tmp/training.parquet",
		ArtifactKind:       KindTrainingDataset,
		HasPIIFeatures:     true,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsTrainingDataPIIRisk {
		t.Fatal("readable + training + PII = PII risk")
	}
}

func TestAnnotateClientKYCDataSourcePII(t *testing.T) {
	r := Row{
		FilePath:     "/tmp/training_kyc.parquet",
		ArtifactKind: KindTrainingDataset,
		DataSource:   DataClientKYC,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsTrainingDataPIIRisk {
		t.Fatal("readable + training + KYC data source = PII risk")
	}
}

func TestAnnotateSafetensorsNoRCE(t *testing.T) {
	r := Row{
		FilePath:     "/tmp/model.safetensors",
		ArtifactKind: KindModelWeights,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasSafetensorsFormat {
		t.Fatal("safetensors must flag")
	}
	if r.IsPickleRCERisk {
		t.Fatal("safetensors must NOT flag pickle RCE")
	}
	if !r.IsStrategyIPExfiltrationRisk {
		t.Fatal("model weights = IP risk regardless of format")
	}
}

func TestAnnotateLLMQuant(t *testing.T) {
	r := Row{
		FilePath:     "/tmp/llama2-7b.gguf",
		ArtifactKind: KindModelWeights,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasLLMQuantWeights {
		t.Fatal(".gguf must flag LLM quant")
	}
}

func TestParseTrainingDataset(t *testing.T) {
	body := []byte(`Training Dataset Metadata
strategy_id: STRAT-2026-001
data_source: client KYC
training_record_count: 5000000
feature_count: 150
pii_columns: dni_feature, cuit_feature, email_feature
cliente_cuit: 27-11111111-4
`)
	f := ParseTrainingDataset(body)
	if f.StrategyID != "STRAT-2026-001" {
		t.Fatalf("strategy=%q", f.StrategyID)
	}
	if f.DataSource != DataClientKYC {
		t.Fatalf("source=%q want client-kyc", f.DataSource)
	}
	if f.TrainingRecordCount != 5_000_000 {
		t.Fatalf("records=%d", f.TrainingRecordCount)
	}
	if f.FeatureCount != 150 {
		t.Fatalf("features=%d", f.FeatureCount)
	}
	if !f.HasPIIFeatures {
		t.Fatal("PII columns marker must flag")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cuit must extract")
	}
}

func TestParseHyperparamSearch(t *testing.T) {
	body := []byte(`Optuna Hyperparam Search
strategy_id: STRAT-2026-002
optuna_trials: 500
`)
	f := ParseHyperparamSearch(body)
	if f.HyperparamTrialsCount != 500 {
		t.Fatalf("trials=%d", f.HyperparamTrialsCount)
	}
}

func TestParseWalkForwardAnalysis(t *testing.T) {
	body := []byte(`Walk-Forward Analysis
strategy_id: STRAT-2026-003
sharpe: 1.85
max_drawdown_pct: 18
`)
	f := ParseWalkForwardAnalysis(body)
	if f.SharpeX100 != 185 {
		t.Fatalf("sharpe x100=%d want 185", f.SharpeX100)
	}
	if f.DrawdownPct != 18 {
		t.Fatalf("dd=%d", f.DrawdownPct)
	}
}

func TestParseSharpeX100Negative(t *testing.T) {
	if got := parseSharpeX100("-0.42"); got != -42 {
		t.Fatalf("parseSharpeX100(-0.42)=%d want -42", got)
	}
	if got := parseSharpeX100("2"); got != 200 {
		t.Fatalf("parseSharpeX100(2)=%d want 200", got)
	}
	if got := parseSharpeX100("1.5"); got != 150 {
		t.Fatalf("parseSharpeX100(1.5)=%d want 150", got)
	}
}

func TestDetectStrategyClass(t *testing.T) {
	cases := map[string]StrategyClass{
		"market making":   StrategyMarketMaking,
		"arbitrage":       StrategyArbitrage,
		"arbitraje":       StrategyArbitrage,
		"trend":           StrategyTrendFollowing,
		"mean reversion":  StrategyMeanReversion,
		"factor":          StrategyFactor,
		"hft":             StrategyHFTExecution,
		"ml prediction":   StrategyMLPrediction,
		"sentiment":       StrategySentimentTrading,
		"options pricing": StrategyOptionsPricing,
		"vol arbitrage":   StrategyVolArbitrage,
		"sov bond":        StrategySovBond,
		"fci":             StrategyFCIStrategy,
		"random":          StrategyUnknown,
	}
	for in, want := range cases {
		got := detectStrategyClass(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectDataSource(t *testing.T) {
	cases := map[string]DataSource{
		"tick":          DataTickData,
		"L1 quote":      DataL1Quote,
		"L3 orderbook":  DataL3OrderBook,
		"news":          DataNewsFeed,
		"fundamentals":  DataFundamentals,
		"alternative":   DataAlternative,
		"social":        DataSocialSentiment,
		"satellite":     DataSatellite,
		"weather":       DataWeather,
		"credit rating": DataCreditRating,
		"client KYC":    DataClientKYC,
		"order flow":    DataOrderFlow,
		"random":        DataUnknown,
	}
	for in, want := range cases {
		got := detectDataSource(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	quantDir := filepath.Join(usersBase, "alice", "quant")
	must(t, os.MkdirAll(filepath.Join(quantDir, "models"), 0o755))
	must(t, os.MkdirAll(filepath.Join(quantDir, "data"), 0o755))
	must(t, os.MkdirAll(filepath.Join(quantDir, "reports"), 0o755))

	pklPath := filepath.Join(quantDir, "models", "model_strategy_v1.pkl")
	must(t, os.WriteFile(pklPath, []byte("PICKLE\x00\x00mockbinary"), 0o644))

	stPath := filepath.Join(quantDir, "models", "model_strategy.safetensors")
	must(t, os.WriteFile(stPath, []byte("SAFETENSORSHEADER"), 0o644))

	dataPath := filepath.Join(quantDir, "data", "training_data_strategy_2026.csv")
	must(t, os.WriteFile(dataPath, []byte(`Training Data Metadata
strategy_id: STRAT-001
data_source: client KYC
training_record_count: 5000000
pii_columns: dni_feature
cliente_cuit: 27-11111111-4
`), 0o644))

	wfaPath := filepath.Join(quantDir, "reports", "walk_forward_strategy.csv")
	must(t, os.WriteFile(wfaPath, []byte(`Walk-Forward Analysis
sharpe: 1.85
max_drawdown_pct: 18
`), 0o644))

	must(t, os.WriteFile(filepath.Join(quantDir, "random.txt"),
		[]byte(`nope`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 (pkl+st+data+wfa), got %d: %+v", len(got), got)
	}

	var pkl, st, data, wfa Row
	for _, r := range got {
		switch r.FilePath {
		case pklPath:
			pkl = r
		case stPath:
			st = r
		case dataPath:
			data = r
		case wfaPath:
			wfa = r
		}
	}

	if pkl.ArtifactKind != KindModelWeights {
		t.Fatalf("pkl kind=%q", pkl.ArtifactKind)
	}
	if pkl.ModelFramework != FrameworkScikitLearn {
		t.Fatalf("pkl framework=%q", pkl.ModelFramework)
	}
	if !pkl.HasPickleFormat {
		t.Fatalf("pkl must flag pickle: %+v", pkl)
	}
	if !pkl.IsPickleRCERisk {
		t.Fatalf("pkl must flag RCE risk: %+v", pkl)
	}
	if !pkl.IsStrategyIPExfiltrationRisk {
		t.Fatalf("pkl must flag IP exfiltration: %+v", pkl)
	}

	if st.ArtifactKind != KindModelWeights {
		t.Fatalf("st kind=%q", st.ArtifactKind)
	}
	if st.ModelFramework != FrameworkSafetensors {
		t.Fatalf("st framework=%q", st.ModelFramework)
	}
	if !st.HasSafetensorsFormat {
		t.Fatalf("st must flag safetensors: %+v", st)
	}
	if st.IsPickleRCERisk {
		t.Fatalf("st must NOT flag pickle RCE: %+v", st)
	}
	if !st.IsStrategyIPExfiltrationRisk {
		t.Fatalf("st must still flag IP: %+v", st)
	}

	if data.ArtifactKind != KindTrainingDataset {
		t.Fatalf("data kind=%q", data.ArtifactKind)
	}
	if data.DataSource != DataClientKYC {
		t.Fatalf("data source=%q", data.DataSource)
	}
	if data.TrainingRecordCount != 5_000_000 {
		t.Fatalf("data records=%d", data.TrainingRecordCount)
	}
	if !data.HasPIIFeatures {
		t.Fatalf("data must flag PII: %+v", data)
	}
	if !data.IsTrainingDataPIIRisk {
		t.Fatalf("data must flag training PII risk: %+v", data)
	}

	if wfa.ArtifactKind != KindWalkForwardAnalysis {
		t.Fatalf("wfa kind=%q", wfa.ArtifactKind)
	}
	if wfa.SharpeX100 != 185 {
		t.Fatalf("wfa sharpe=%d", wfa.SharpeX100)
	}
	if wfa.DrawdownPct != 18 {
		t.Fatalf("wfa dd=%d", wfa.DrawdownPct)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-quant")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "quant_config.ini"),
		[]byte(`[Quant]
quant_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "MODEL_DIR" {
				return custom
			}
			return ""
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
		now:      func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 from env-override, got %d", len(got))
	}
	if !got[0].HasPasswordInConfig {
		t.Fatalf("env-override row must flag password")
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-model"},
		usersBases:   []string{"/nope-users"},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortRowsDeterministic(t *testing.T) {
	rs := []Row{
		{FilePath: "/b", ArtifactKind: KindModelWeights},
		{FilePath: "/a", ArtifactKind: KindTrainingDataset},
		{FilePath: "/a", ArtifactKind: KindModelWeights},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindModelWeights {
		t.Fatalf("sort drift: %+v", rs)
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("abc")
	b := HashSecret("ABC")
	if a != b {
		t.Fatal("hash must be case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
