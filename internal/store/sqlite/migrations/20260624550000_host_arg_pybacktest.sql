-- host_arg_pybacktest inventories Python quant-framework
-- backtest result files cached on Argentine retail-trader,
-- prop-desk, and quant workstations.
--
-- Python quant frameworks produce specific structured output
-- when traders backtest strategies. The common families:
--
--   vectorbt    .pkl Portfolio objects, parquet OHLCV history
--   backtrader  csv equity curve, txt TradeAnalyzer output
--   zipline     .pkl performance DataFrame
--   freqtrade   JSON backtest result with stats per pair
--   quantstats  HTML tear sheets
--   bt          .pkl Strategy objects
--   custom      ad-hoc Python backtest harnesses
--
-- For Argentine markets the local-ticker presence (GGAL /
-- YPFD / PAMP / AL30 / GD30 / etc.) flags the strategy as
-- locally-focused — material for CNV / BCRA risk reviews
-- if the trader is a regulated broker-dealer employee.
--
-- Workstation cache footprint:
--
--   ~/Documents/Backtests/<strategy>_<dt>.pkl
--   ~/Documents/Backtests/equity_curve_<strategy>.csv
--   ~/Documents/Backtests/tradelog_<strategy>.txt
--   ~/Documents/Backtests/tear_sheet_<strategy>.html
--   ~/.config/freqtrade/user_data/backtest_results/*.json
--   ~/.zipline/quotes/*.bcolz
--   ~/.cache/vectorbt/*.pkl
--
-- **The Python quant backtest result layer.** Distinct from:
--   - iter 108 winalgotrading  — generic EA/Jupyter cover
--   - iter 139 winargprimary   — Primary REST/WS API
--   - iter 143 winargmt        — MetaTrader EAs deep-dive
--   - iter 141 winargpyhomebroker pyhomebroker portal-scrape
--
-- Backtest-specific risk signals:
--   * Sharpe > 5 = likely overfit (real-world stocks ~1.0
--     long-term).
--   * Annual return > 100 % = likely overfit / unrealistic.
--   * Max drawdown > 50 % = strategy unsuitable for live.
--   * Lookahead-bias markers (`shift(-1)`, `future_data`,
--     `peek_ahead`) = invalid backtest.
--   * Compiled .pkl strategy = obfuscated algorithm IP.
--   * API key in .py source file = T1552 unsecured creds.
--   * In-sample vs out-of-sample mismatch indicates overfit.
--
-- Regulatory base:
--   CNV RG 731       Régimen de Agentes (algo-trader)
--   CNV RG 622       Operativa (live deployment requirements)
--   CNV RG 1023      Tecnología + ciberseguridad
--   Ley 25.326       Protección datos personales
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials (api key in source)
--   T1567    Exfiltration over Web Service (strategy IP)
--   CWE-200, CWE-359, CWE-798
--
-- Headline finding shapes:
--   has_overfit_sharpe         — sharpe > 5.
--   has_extreme_drawdown       — max drawdown > 50 %.
--   has_unrealistic_returns    — annual return > 100 %.
--   has_lookahead_bias         — lookahead-bias markers.
--   has_argentine_tickers      — Argentine ticker(s) found.
--   has_compiled_strategy      — .pkl / .pickle on disk.
--   has_api_key_in_code        — API key in .py source.
--   has_ipynb_with_secrets     — .ipynb with embedded secrets.
--   is_credential_exposure_risk — readable file +
--                              (api-key OR compiled IP).

CREATE TABLE IF NOT EXISTS host_arg_pybacktest (
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
            'pybt-vectorbt-portfolio','pybt-backtrader-output',
            'pybt-zipline-result','pybt-freqtrade-result',
            'pybt-quantstats-tearsheet','pybt-bt-strategy',
            'pybt-ohlcv-history','pybt-equity-curve',
            'pybt-trade-log','pybt-params-grid',
            'pybt-strategy-script','pybt-installer',
            'other','unknown'
        )),
    framework                   TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (framework IN (
            'vectorbt','backtrader','zipline','freqtrade',
            'quantstats','bt','custom','other','unknown'
        )),
    strategy_class              TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (strategy_class IN (
            'equity','bonds','futures','fx','crypto',
            'mixed','other','unknown'
        )),
    sharpe_x100                 INTEGER NOT NULL DEFAULT 0,
    annual_return_pct           INTEGER NOT NULL DEFAULT 0,
    max_drawdown_pct            INTEGER NOT NULL DEFAULT 0
        CHECK (max_drawdown_pct BETWEEN 0 AND 100),
    trade_count                 INTEGER NOT NULL DEFAULT 0,
    argentine_ticker_count      INTEGER NOT NULL DEFAULT 0,
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    strategy_name               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_overfit_sharpe          INTEGER NOT NULL DEFAULT 0 CHECK (has_overfit_sharpe IN (0,1)),
    has_extreme_drawdown        INTEGER NOT NULL DEFAULT 0 CHECK (has_extreme_drawdown IN (0,1)),
    has_unrealistic_returns     INTEGER NOT NULL DEFAULT 0 CHECK (has_unrealistic_returns IN (0,1)),
    has_lookahead_bias          INTEGER NOT NULL DEFAULT 0 CHECK (has_lookahead_bias IN (0,1)),
    has_argentine_tickers       INTEGER NOT NULL DEFAULT 0 CHECK (has_argentine_tickers IN (0,1)),
    has_compiled_strategy       INTEGER NOT NULL DEFAULT 0 CHECK (has_compiled_strategy IN (0,1)),
    has_api_key_in_code         INTEGER NOT NULL DEFAULT 0 CHECK (has_api_key_in_code IN (0,1)),
    has_ipynb_with_secrets      INTEGER NOT NULL DEFAULT 0 CHECK (has_ipynb_with_secrets IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_pybt_overfit
    ON host_arg_pybacktest(framework) WHERE has_overfit_sharpe = 1;

CREATE INDEX IF NOT EXISTS idx_pybt_drawdown
    ON host_arg_pybacktest(framework) WHERE has_extreme_drawdown = 1;

CREATE INDEX IF NOT EXISTS idx_pybt_unrealistic
    ON host_arg_pybacktest(framework) WHERE has_unrealistic_returns = 1;

CREATE INDEX IF NOT EXISTS idx_pybt_lookahead
    ON host_arg_pybacktest(file_path) WHERE has_lookahead_bias = 1;

CREATE INDEX IF NOT EXISTS idx_pybt_argentine
    ON host_arg_pybacktest(strategy_class) WHERE has_argentine_tickers = 1;

CREATE INDEX IF NOT EXISTS idx_pybt_compiled
    ON host_arg_pybacktest(file_path) WHERE has_compiled_strategy = 1;

CREATE INDEX IF NOT EXISTS idx_pybt_apikey
    ON host_arg_pybacktest(file_path) WHERE has_api_key_in_code = 1;

CREATE INDEX IF NOT EXISTS idx_pybt_ipynb_secrets
    ON host_arg_pybacktest(file_path) WHERE has_ipynb_with_secrets = 1;

CREATE INDEX IF NOT EXISTS idx_pybt_exposure
    ON host_arg_pybacktest(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_pybt_drift
    ON host_arg_pybacktest(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_pybt_framework
    ON host_arg_pybacktest(framework, artifact_kind);

CREATE INDEX IF NOT EXISTS idx_pybt_class
    ON host_arg_pybacktest(strategy_class, period_yyyymm);
