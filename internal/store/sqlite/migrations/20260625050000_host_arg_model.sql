-- host_arg_model inventories AR quant-strategy ML-model and
-- training-data artifact files cached on AR institutional and
-- retail-pro quant-desk workstations.
--
-- Direct algotrading-focus: AR quant analysts cache binary model
-- weights, training datasets, feature stores, hyperparameter-
-- sweep outputs, walk-forward analyses, OOS tests, Monte Carlo
-- runs, model-drift alerts. Distinct because the shape is the
-- **ML-strategy IP layer** itself — not the trading platform
-- (NinjaTrader/Quantower/MotiveWave), not the Python backtest
-- framework (Backtrader/QuantConnect Lean), but the serialized
-- model weights + the training-data corpus that produced them.
--
-- Distinct from prior iters:
--
--   - vs iter 184 winargninja      — trading platform code, not ML.
--   - vs iter 176 winargkdb        — KDB+/Q time-series, not ML.
--   - winargpybacktest (preexisting) — Python backtest engine.
--   - winarglean (preexisting)      — QuantConnect Lean.
--
-- Quant-model leak risk surface:
--
--   * Strategy IP exfiltration — model weights = serialized
--     trading edge. Onnx / pickle / safetensors can be loaded
--     verbatim into competitor's stack.
--   * Training data PII — features may include client KYC
--     (cross-ref iter 195 winargacdi), insider tick data
--     (cross-ref iter 188 winargfgs), rating data (cross-ref
--     iter 190 winargcalificadora), audit-extracted balances
--     (cross-ref iter 191 winargperito).
--   * Pickle deserialization RCE — Python pickle is unsafe by
--     design; cached `.pkl` files with attacker-controlled
--     content can execute arbitrary code on load (T1059 + CWE-
--     502).
--   * Hyperparameter-sweep output reveals fitness landscape
--     (overfitting / lookback bias evidence).
--   * Walk-forward analysis reveals strategy decay rate.
--   * OOS test result reveals true performance (vs marketed).
--   * Monte Carlo simulation = stress-test scenarios run.
--   * Model drift alert = production-system telemetry leak.
--
-- ML-framework distinctive features:
--
--   - scikit-learn  — .pkl (joblib.dump), .joblib
--   - TensorFlow    — .pb SavedModel, .h5 Keras legacy, .keras
--   - PyTorch       — .pt / .pth (torch.save state_dict)
--   - XGBoost       — .ubj UBJSON, .json model dump
--   - LightGBM      — .txt LGBM, .lgb binary
--   - CatBoost      — .cbm binary
--   - JAX / Flax    — .msgpack pickle
--   - ONNX runtime  — .onnx open standard
--   - HuggingFace   — config.json + pytorch_model.bin
--   - Llama.cpp     — .gguf (GGML universal format)
--   - safetensors   — .safetensors (zero-RCE-risk pickle alt)
--
-- Workstation cache footprint (typical):
--
--   ~/quant/models/                          model store root
--     model_<strategy>_<version>.pkl         scikit-learn pickle
--     model_<strategy>.joblib                joblib dump
--     model_<strategy>.onnx                  ONNX serialized
--     model_<strategy>.h5                    Keras H5
--     model_<strategy>.pt                    PyTorch state
--     model_<strategy>.safetensors           safe tensor
--     model_<strategy>.gguf                  LLM quantized
--   ~/quant/data/                            training data
--     training_data_<strategy>_<date>.parquet
--     features_<strategy>.h5
--     feature_store_<v>.arrow
--   ~/quant/reports/                         analysis reports
--     hyperparam_search_<study>.csv
--     walk_forward_<strategy>.csv
--     oos_test_<strategy>_<date>.csv
--     monte_carlo_<strategy>.csv
--     model_drift_<dt>.json
--     live_attribution_<dt>.csv
--     ab_test_<test>.html
--
-- Regulatory base:
--
--   Ley 26.831         Mercado de Capitales (AR)
--   CNV RG 622 art.23  Sistemas Automatizados
--   CNV RG 622 art.50  Insider information (training data)
--   CNV RG 731         Régimen de Agentes
--   CNV RG 1023        Ciberresiliencia
--   Ley 25.326         Datos Personales (training features)
--   Ley 25.246         PLA/FT (model-driven order generation)
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories (model store)
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (HuggingFace / model registry)
--   T1059    Command and Scripting (pickle RCE)
--   T1005    Data from Local System (training Parquet)
--   T1027    Obfuscated Files (binary model weights)
--   CWE-200, CWE-359, CWE-502 (pickle deserialize), CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config        — cleartext.
--   has_model_weights             — model weights file.
--   has_training_dataset          — training data corpus.
--   has_feature_store             — feature store output.
--   has_hyperparam_search         — Optuna / Hyperopt study.
--   has_walk_forward_analysis     — WFA output.
--   has_oos_test_result           — OOS test.
--   has_monte_carlo_output        — MC sim output.
--   has_model_drift_alert         — drift alert.
--   has_live_attribution          — live attribution CSV.
--   has_ab_test_dashboard         — A/B test HTML.
--   has_pickle_format             — .pkl / .joblib (RCE risk).
--   has_safetensors_format        — .safetensors (no-RCE).
--   has_onnx_format               — .onnx open standard.
--   has_llm_quant_weights         — .gguf / .safetensors LLM.
--   has_cliente_cuit              — cliente CUIT in dataset.
--   has_pii_features              — KYC / DOB / address fields.
--   is_credential_exposure_risk   — readable + (password OR
--                                   model weights OR training
--                                   dataset OR cliente CUIT).
--   is_strategy_ip_exfiltration_risk — readable + model weights.
--   is_training_data_pii_risk     — readable + training dataset
--                                   + (PII features OR CUIT).
--   is_pickle_rce_risk            — readable + pickle format.

CREATE TABLE IF NOT EXISTS host_arg_model (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    artifact_kind               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (artifact_kind IN (
            'qm-model-weights','qm-training-dataset',
            'qm-feature-store','qm-hyperparam-search',
            'qm-walk-forward-analysis','qm-oos-test-result',
            'qm-monte-carlo-output','qm-model-drift-alert',
            'qm-live-attribution','qm-ab-test-dashboard',
            'qm-config','qm-credentials',
            'qm-installer','other','unknown'
        )),
    model_framework             TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (model_framework IN (
            'scikit-learn','tensorflow','pytorch',
            'xgboost','lightgbm','catboost',
            'jax','onnx','keras',
            'huggingface','llama-cpp','safetensors',
            'custom','none','unknown'
        )),
    strategy_class              TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (strategy_class IN (
            'market-making','arbitrage','trend-following',
            'mean-reversion','factor','hft-execution',
            'ml-prediction','sentiment-trading',
            'options-pricing','vol-arbitrage',
            'sov-bond','fci-strategy',
            'custom','none','unknown'
        )),
    data_source                 TEXT    NOT NULL DEFAULT ''
        CHECK (data_source IN (
            '','tick-data','l1-quote','l3-orderbook',
            'news-feed','fundamentals','alternative-data',
            'social-sentiment','satellite','weather',
            'credit-rating','client-kyc','order-flow',
            'custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    strategy_id                 TEXT    NOT NULL DEFAULT '',
    model_version               TEXT    NOT NULL DEFAULT '',
    training_record_count       INTEGER NOT NULL DEFAULT 0,
    feature_count               INTEGER NOT NULL DEFAULT 0,
    hyperparam_trials_count     INTEGER NOT NULL DEFAULT 0,
    drawdown_pct                INTEGER NOT NULL DEFAULT 0,
    sharpe_x100                 INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_model_weights           INTEGER NOT NULL DEFAULT 0 CHECK (has_model_weights IN (0,1)),
    has_training_dataset        INTEGER NOT NULL DEFAULT 0 CHECK (has_training_dataset IN (0,1)),
    has_feature_store           INTEGER NOT NULL DEFAULT 0 CHECK (has_feature_store IN (0,1)),
    has_hyperparam_search       INTEGER NOT NULL DEFAULT 0 CHECK (has_hyperparam_search IN (0,1)),
    has_walk_forward_analysis   INTEGER NOT NULL DEFAULT 0 CHECK (has_walk_forward_analysis IN (0,1)),
    has_oos_test_result         INTEGER NOT NULL DEFAULT 0 CHECK (has_oos_test_result IN (0,1)),
    has_monte_carlo_output      INTEGER NOT NULL DEFAULT 0 CHECK (has_monte_carlo_output IN (0,1)),
    has_model_drift_alert       INTEGER NOT NULL DEFAULT 0 CHECK (has_model_drift_alert IN (0,1)),
    has_live_attribution        INTEGER NOT NULL DEFAULT 0 CHECK (has_live_attribution IN (0,1)),
    has_ab_test_dashboard       INTEGER NOT NULL DEFAULT 0 CHECK (has_ab_test_dashboard IN (0,1)),
    has_pickle_format           INTEGER NOT NULL DEFAULT 0 CHECK (has_pickle_format IN (0,1)),
    has_safetensors_format      INTEGER NOT NULL DEFAULT 0 CHECK (has_safetensors_format IN (0,1)),
    has_onnx_format             INTEGER NOT NULL DEFAULT 0 CHECK (has_onnx_format IN (0,1)),
    has_llm_quant_weights       INTEGER NOT NULL DEFAULT 0 CHECK (has_llm_quant_weights IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    has_pii_features            INTEGER NOT NULL DEFAULT 0 CHECK (has_pii_features IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_strategy_ip_exfiltration_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_strategy_ip_exfiltration_risk IN (0,1)),
    is_training_data_pii_risk   INTEGER NOT NULL DEFAULT 0 CHECK (is_training_data_pii_risk IN (0,1)),
    is_pickle_rce_risk          INTEGER NOT NULL DEFAULT 0 CHECK (is_pickle_rce_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_qm_password
    ON host_arg_model(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_qm_weights
    ON host_arg_model(strategy_id, model_framework) WHERE has_model_weights = 1;

CREATE INDEX IF NOT EXISTS idx_qm_training
    ON host_arg_model(strategy_id, training_record_count) WHERE has_training_dataset = 1;

CREATE INDEX IF NOT EXISTS idx_qm_features
    ON host_arg_model(strategy_id, feature_count) WHERE has_feature_store = 1;

CREATE INDEX IF NOT EXISTS idx_qm_hyperparam
    ON host_arg_model(strategy_id, hyperparam_trials_count) WHERE has_hyperparam_search = 1;

CREATE INDEX IF NOT EXISTS idx_qm_wfa
    ON host_arg_model(strategy_id, sharpe_x100) WHERE has_walk_forward_analysis = 1;

CREATE INDEX IF NOT EXISTS idx_qm_oos
    ON host_arg_model(strategy_id, sharpe_x100) WHERE has_oos_test_result = 1;

CREATE INDEX IF NOT EXISTS idx_qm_mc
    ON host_arg_model(strategy_id, drawdown_pct) WHERE has_monte_carlo_output = 1;

CREATE INDEX IF NOT EXISTS idx_qm_drift
    ON host_arg_model(strategy_id, reporting_period) WHERE has_model_drift_alert = 1;

CREATE INDEX IF NOT EXISTS idx_qm_live
    ON host_arg_model(strategy_id, sharpe_x100) WHERE has_live_attribution = 1;

CREATE INDEX IF NOT EXISTS idx_qm_pickle
    ON host_arg_model(file_path) WHERE has_pickle_format = 1;

CREATE INDEX IF NOT EXISTS idx_qm_safetensors
    ON host_arg_model(file_path) WHERE has_safetensors_format = 1;

CREATE INDEX IF NOT EXISTS idx_qm_onnx
    ON host_arg_model(file_path) WHERE has_onnx_format = 1;

CREATE INDEX IF NOT EXISTS idx_qm_llm
    ON host_arg_model(file_path) WHERE has_llm_quant_weights = 1;

CREATE INDEX IF NOT EXISTS idx_qm_pii_features
    ON host_arg_model(strategy_id) WHERE has_pii_features = 1;

CREATE INDEX IF NOT EXISTS idx_qm_cliente
    ON host_arg_model(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_qm_exposure
    ON host_arg_model(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_qm_ip
    ON host_arg_model(file_path) WHERE is_strategy_ip_exfiltration_risk = 1;

CREATE INDEX IF NOT EXISTS idx_qm_pii
    ON host_arg_model(file_path) WHERE is_training_data_pii_risk = 1;

CREATE INDEX IF NOT EXISTS idx_qm_rce
    ON host_arg_model(file_path) WHERE is_pickle_rce_risk = 1;

CREATE INDEX IF NOT EXISTS idx_qm_drift_check
    ON host_arg_model(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_qm_kind
    ON host_arg_model(artifact_kind, model_framework);
