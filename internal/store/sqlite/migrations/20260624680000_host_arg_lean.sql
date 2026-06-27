-- host_arg_lean inventories QuantConnect LEAN open-source
-- algotrading framework artifact files cached on Argentine
-- quant, prop-desk, and retail-quant workstations.
--
-- LEAN (https://github.com/QuantConnect/Lean) is a C#/Python
-- algotrading engine used to backtest + live-deploy strategies
-- across equity, options, futures, forex, and crypto. The
-- Argentine quant community uses LEAN to backtest before
-- deploying live via:
--
--   Primary REST/WS   MATba-Rofex via iter 139 winargprimary
--   IB Gateway        Interactive Brokers for global markets
--   Alpaca            US equities
--   Coinbase/Binance  crypto exchange brokerages
--
-- **The LEAN-framework layer.** Distinct from:
--   - iter 147 winargpybacktest    generic Python backtest
--   - iter 149 winargtradingview   TradingView/Pine Script
--   - iter 143 winargmt            MetaTrader 4/5 EA
--   - iter 148 winargninjatrader   NinjaTrader 8 NinjaScript
--   - iter 139 winargprimary       Primary REST/WS API (target)
--   - iter 150 winargpyhomebroker  portal scrape lib
--
-- Workstation cache footprint:
--
--   C:\Lean\config.json            engine config
--   C:\Lean\algorithm.py           strategy code (Python)
--   C:\Lean\algorithm.cs           strategy code (C#)
--   C:\Lean\backtests\<id>.json    backtest result
--   C:\Lean\live\<id>\config.json  live deployment cfg
--   C:\Lean\data\equity\usa\...    US equity data
--   C:\Lean\data\crypto\...        crypto data
--   C:\Lean\data\future\rofex\...  ROFEX futures data
--   %APPDATA%\QuantConnect\        QuantConnect cloud creds
--   ~/.lean-cli/credentials.json   LEAN CLI credentials
--
-- LEAN-specific risk signals:
--   * Brokerage API key in lean.json (Primary/IB/Alpaca/etc.)
--     = T1552 + direct live-trading account compromise
--   * Live deployment config with `live-mode=true` = production
--     trading running (vs. backtest sandbox)
--   * Argentine-Primary brokerage = MATba-Rofex live trading
--     subject to CNV RG 731 + BCRA Com. A 7916
--   * Crypto brokerage = AFIP RG 5527 reporting obligation
--   * High-frequency strategy (resolution=tick/second) = CNV
--     scrutiny under RG 731 art. 23 (manipulation concern)
--   * Cliente CUIT in algorithm parameter = Ley 25.326 PII
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes (algotrading subset)
--   CNV RG 622       Operativa
--   CNV RG 1023      Ciberresiliencia
--   AFIP RG 5193     Securities tax reporting
--   AFIP RG 5527     Crypto tax reporting
--   BCRA Com. A 7916 Operaciones cambiarias
--   Ley 25.326       Protección de Datos Personales
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1059.006 Python Command and Scripting Interpreter
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_password_in_config       — config cleartext.
--   has_brokerage_api_key        — any broker adapter key.
--   has_live_deployment          — live-mode strategy running.
--   has_argentine_brokerage      — Primary REST/WS adapter.
--   has_crypto_brokerage         — Coinbase/Binance/Bitfinex.
--   has_us_equities              — Alpaca/IB US equity adapter.
--   has_futures_subscription     — futures resolution data.
--   has_high_frequency_strategy  — tick/second resolution.
--   has_large_data_footprint     — > 1000 data files cached.
--   has_cliente_cuit             — cliente CUIT detected.
--   is_credential_exposure_risk  — readable + (password OR
--                                  broker API key OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_lean (
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
            'lean-config','lean-credentials',
            'lean-algorithm-cs','lean-algorithm-py',
            'lean-backtest-result','lean-live-config',
            'lean-data-subscription','lean-nodepacket',
            'lean-cli-config','lean-installer',
            'other','unknown'
        )),
    algorithm_class             TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (algorithm_class IN (
            'equity','options','futures','forex','crypto',
            'multi-asset','other','unknown'
        )),
    deployment_target           TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (deployment_target IN (
            'backtest','paper',
            'live-primary','live-ib','live-alpaca',
            'live-coinbase','live-binance','live-bitfinex',
            'live-kraken','live-other','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    brokerage_key_hash          TEXT    NOT NULL DEFAULT '',
    qc_user_token_hash          TEXT    NOT NULL DEFAULT '',
    algorithm_name              TEXT    NOT NULL DEFAULT '',
    data_resolution             TEXT    NOT NULL DEFAULT ''
        CHECK (data_resolution IN ('','tick','second','minute','hour','daily','unknown')),
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    backtest_count              INTEGER NOT NULL DEFAULT 0,
    data_file_count             INTEGER NOT NULL DEFAULT 0,
    distinct_symbol_count       INTEGER NOT NULL DEFAULT 0,
    sharpe_ratio_bps            INTEGER NOT NULL DEFAULT 0,
    annual_return_bps           INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_brokerage_api_key       INTEGER NOT NULL DEFAULT 0 CHECK (has_brokerage_api_key IN (0,1)),
    has_live_deployment         INTEGER NOT NULL DEFAULT 0 CHECK (has_live_deployment IN (0,1)),
    has_argentine_brokerage     INTEGER NOT NULL DEFAULT 0 CHECK (has_argentine_brokerage IN (0,1)),
    has_crypto_brokerage        INTEGER NOT NULL DEFAULT 0 CHECK (has_crypto_brokerage IN (0,1)),
    has_us_equities             INTEGER NOT NULL DEFAULT 0 CHECK (has_us_equities IN (0,1)),
    has_futures_subscription    INTEGER NOT NULL DEFAULT 0 CHECK (has_futures_subscription IN (0,1)),
    has_high_frequency_strategy INTEGER NOT NULL DEFAULT 0 CHECK (has_high_frequency_strategy IN (0,1)),
    has_large_data_footprint    INTEGER NOT NULL DEFAULT 0 CHECK (has_large_data_footprint IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_lean_password
    ON host_arg_lean(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_lean_brokerage_key
    ON host_arg_lean(file_path) WHERE has_brokerage_api_key = 1;

CREATE INDEX IF NOT EXISTS idx_lean_live
    ON host_arg_lean(deployment_target, period_yyyymm) WHERE has_live_deployment = 1;

CREATE INDEX IF NOT EXISTS idx_lean_argentina
    ON host_arg_lean(deployment_target, period_yyyymm) WHERE has_argentine_brokerage = 1;

CREATE INDEX IF NOT EXISTS idx_lean_crypto
    ON host_arg_lean(deployment_target, period_yyyymm) WHERE has_crypto_brokerage = 1;

CREATE INDEX IF NOT EXISTS idx_lean_hfreq
    ON host_arg_lean(deployment_target, data_resolution) WHERE has_high_frequency_strategy = 1;

CREATE INDEX IF NOT EXISTS idx_lean_cliente
    ON host_arg_lean(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_lean_exposure
    ON host_arg_lean(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_lean_drift
    ON host_arg_lean(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_lean_kind
    ON host_arg_lean(artifact_kind, algorithm_class, deployment_target);
