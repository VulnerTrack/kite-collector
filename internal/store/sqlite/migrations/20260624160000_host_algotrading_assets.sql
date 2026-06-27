-- host_algotrading_assets inventories FIX-protocol session
-- logs + algorithmic-trading software assets on broker-dealer,
-- quant-trader, and proprietary-desk workstations.
--
-- Every broker-dealer integrating with BYMA / MAV / MATba-
-- Rofex / MAE runs a FIX (Financial Information eXchange)
-- session. Every order, execution report, and quote
-- request lands on disk as a FIX message in QuickFIX-style
-- session logs. The session config (`fix.cfg`) carries
-- SenderCompID / TargetCompID / password — a leak gives
-- impersonation capability for the entire order flow.
--
-- Algorithmic-trading workstations additionally carry:
--   MetaTrader 4/5 Expert Advisors (.ex4/.ex5 + .mq4/.mq5)
--   NinjaTrader custom strategies (.cs)
--   StrategyQuant generated strategies (.sqx)
--   Python algos (.pkl pickled models, .parquet OHLCV,
--     .ipynb notebooks with hardcoded API keys)
--   Quant configs (algo_params.json, strategy_config.yaml)
--
-- **The algorithmic-trading capability inventory.** Pairs
-- with iter 107 winargcnvalyc (ALYC broker-dealer regulatory
-- layer) to give the full broker-desk asset picture.
--
-- Regulatory / standards base:
--   FIX Protocol 4.4 / 5.0 SP2 (FIX Trading Community)
--   CNV RG 731 art. 6 — registro de operaciones
--   BYMA Reglamento Operativo
--   MATba-Rofex Reglamento de Operaciones
--
-- MITRE / CWE:
--   T1552.001 Credentials in Files (FIX cfg password)
--   T1213    Data from Information Repositories
--   T1027    Obfuscated Files (compiled EAs)
--   CWE-256, CWE-522 (cleartext credentials)
--   CWE-359 (PII), CWE-732 (perms)
--
-- Headline finding shapes:
--   has_credentials_in_config — FIX cfg has `Password=` /
--                              `SocketKeyStorePassword=` row.
--   has_strategy_logic        — compiled EA or source script
--                              on disk (algorithmic IP).
--   has_backtest_results      — pickle / parquet / CSV from
--                              backtest output.
--   fix_record_count          — line-count for FIX session log.
--   is_credential_exposure_risk — FIX-credential file readable,
--                              OR strategy-IP file readable.

CREATE TABLE IF NOT EXISTS host_algotrading_assets (
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
            'fix-session-log','fix-config',
            'mt4-ea','mt5-ea','mql-source',
            'ninjatrader-strategy','sqx-strategy',
            'python-pkl','ohlcv-parquet','jupyter-notebook',
            'algo-config','backtest-result','other','unknown'
        )),
    application                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (application IN (
            'quickfix','primarytrader','esco','metatrader-4',
            'metatrader-5','ninjatrader','strategyquant',
            'custom-python','tradingview','jupyterlab',
            'other','unknown'
        )),
    fix_sender_compid           TEXT    NOT NULL DEFAULT '',
    fix_target_compid           TEXT    NOT NULL DEFAULT '',
    fix_record_count            INTEGER NOT NULL DEFAULT 0,
    earliest_session            TEXT    NOT NULL DEFAULT '',
    latest_session              TEXT    NOT NULL DEFAULT '',
    has_credentials_in_config   INTEGER NOT NULL DEFAULT 0 CHECK (has_credentials_in_config IN (0,1)),
    has_strategy_logic          INTEGER NOT NULL DEFAULT 0 CHECK (has_strategy_logic IN (0,1)),
    has_backtest_results        INTEGER NOT NULL DEFAULT 0 CHECK (has_backtest_results IN (0,1)),
    has_api_key_in_notebook     INTEGER NOT NULL DEFAULT 0 CHECK (has_api_key_in_notebook IN (0,1)),
    is_compiled_binary          INTEGER NOT NULL DEFAULT 0 CHECK (is_compiled_binary IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_algo_creds
    ON host_algotrading_assets(file_path) WHERE has_credentials_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_algo_strategy
    ON host_algotrading_assets(file_path) WHERE has_strategy_logic = 1;

CREATE INDEX IF NOT EXISTS idx_algo_apikey
    ON host_algotrading_assets(file_path) WHERE has_api_key_in_notebook = 1;

CREATE INDEX IF NOT EXISTS idx_algo_exposure
    ON host_algotrading_assets(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_algo_drift
    ON host_algotrading_assets(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_algo_fix_session
    ON host_algotrading_assets(fix_sender_compid, fix_target_compid);
