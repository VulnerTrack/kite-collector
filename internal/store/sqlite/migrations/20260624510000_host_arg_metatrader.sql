-- host_arg_metatrader inventories MetaTrader 4 / 5 algo-
-- trading files cached on Argentine retail-trader, prop-desk,
-- and quant workstations.
--
-- MetaTrader (MT4 + MT5) is the dominant retail forex / CFD
-- terminal. Argentine traders use MT4/MT5 against:
--
--   Local FX (Forexar, Saxoxar — limited)
--   Offshore prop firms (FTMO, MyForexFunds, FundedNext,
--                        The5%ers, TopstepFX)
--   Offshore brokers (Tickmill, Pepperstone, IC Markets,
--                     OANDA, FXCM, Exness, XM)
--
-- Workstation footprint:
--
--   C:\Program Files\MetaTrader 4\terminal.exe
--   %APPDATA%\MetaQuotes\Terminal\<id>\         per-terminal cache
--      origin.txt                               install origin
--      config\terminal.ini                      terminal config
--      config\accounts.ini                      account list
--      config\servers.dat                       broker server list
--      MQL4\Experts\*.ex4 / *.mq4               EAs
--      MQL4\Indicators\*.ex4 / *.mq4            indicators
--      MQL4\Scripts\*.ex4 / *.mq4               scripts
--      MQL4\Libraries\*.dll                     DLL plugins
--      MQL4\Files\                              EA-local files
--      tester\logs\                             backtest logs
--      tester\caches\                           backtest data
--      history\<server>\*.hst                   HST history
--      logs\<date>.log                          terminal log
--   MQL5\ variants for MT5
--
-- **The MetaTrader deep-dive layer.** Distinct from:
--   - iter 108 winalgotrading  — generic EA / Jupyter cover
--   - iter 109 winargmatbarofex MATba-Rofex positions
--   - iter 113 winargfix       — raw FIX session logs
--   - iter 139 winargprimary   — Primary REST/WS (no MT)
--
-- MetaTrader-specific risk signals:
--   * .mq4/.mq5 source = algorithmic IP exposure (full
--     strategy logic readable).
--   * .ex4/.ex5 compiled = obfuscated IP (but still IP).
--   * DLL plugins (Libraries\*.dll) = supply-chain risk;
--     EAs can call arbitrary native code.
--   * Offshore broker server config = Argentine investor
--     residing offshore (AFIP Bienes Personales + BCRA
--     Comunicación "A" 7916 scrutiny).
--   * Prop-firm account = fee-paid funded trading; the
--     funded-trader is the broker's counterparty.
--   * Strategy Optimizer report with > 50 % out-of-sample
--     dropoff = over-fitted strategy.
--
-- Regulatory base:
--   AFIP Bienes Personales (offshore brokerage account)
--   BCRA Com. A 7916 (operaciones cambiarias)
--   CNV RG 622 (general operativa)
--   Ley 25.246 (PLA/FT — funded trading is income)
--   Ley 25.326 (cliente PII en terminal.ini)
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials (accounts.ini)
--   T1547    Boot/Logon Autostart (DLL plugins)
--   T1574    Hijack Execution Flow (untrusted DLL)
--   CWE-200, CWE-359, CWE-532, CWE-798
--   CWE-829  (untrusted DLL functionality)
--   Ley 25.326 (cuenta + login)
--
-- Headline finding shapes:
--   has_compiled_ea          — .ex4 or .ex5 EA on disk.
--   has_source_ea            — .mq4 or .mq5 source on disk.
--   has_dll_plugin           — .dll in MQL Libraries\ dir.
--   has_account_password     — terminal.ini / accounts.ini
--                              with cleartext Password=.
--   has_offshore_broker      — server config maps to a known
--                              offshore broker hostname.
--   has_prop_firm_account    — server config maps to a prop-
--                              firm hostname (FTMO/MFF/etc.).
--   has_signal_provider      — Signal service subscription
--                              persisted (TradingSignal=).
--   has_optimizer_overfit    — Strategy Optimizer report shows
--                              out-of-sample dropoff > 50 %.
--   has_backtest_history     — HST file or backtest report.
--   is_credential_exposure_risk — readable file +
--                              (Password= OR account ID OR
--                              IP exposure body).
--
-- Account login IDs reduced to last 4 digits. Server names
-- retained verbatim (broker identification is not PII).

CREATE TABLE IF NOT EXISTS host_arg_metatrader (
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
            'mt-ea-mq4-source','mt-ea-mq5-source',
            'mt-ea-ex4-compiled','mt-ea-ex5-compiled',
            'mt-indicator-mq','mt-script-mq',
            'mt-terminal-config','mt-account-config',
            'mt-broker-servers','mt-history-hst',
            'mt-optimize-report','mt-backtest-report',
            'mt-dll-plugin','mt-installer',
            'other','unknown'
        )),
    platform                    TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (platform IN (
            'mt4','mt5','mt-mobile','other','unknown'
        )),
    broker_class                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (broker_class IN (
            'arg-broker','offshore-broker','demo-server',
            'prop-firm','other','unknown'
        )),
    broker_hostname             TEXT    NOT NULL DEFAULT '',
    account_login_suffix4       TEXT    NOT NULL DEFAULT '',
    server_name                 TEXT    NOT NULL DEFAULT '',
    ea_name                     TEXT    NOT NULL DEFAULT '',
    optimizer_oos_dropoff_pct   INTEGER NOT NULL DEFAULT 0
        CHECK (optimizer_oos_dropoff_pct BETWEEN 0 AND 100),
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_compiled_ea             INTEGER NOT NULL DEFAULT 0 CHECK (has_compiled_ea IN (0,1)),
    has_source_ea               INTEGER NOT NULL DEFAULT 0 CHECK (has_source_ea IN (0,1)),
    has_dll_plugin              INTEGER NOT NULL DEFAULT 0 CHECK (has_dll_plugin IN (0,1)),
    has_account_password        INTEGER NOT NULL DEFAULT 0 CHECK (has_account_password IN (0,1)),
    has_offshore_broker         INTEGER NOT NULL DEFAULT 0 CHECK (has_offshore_broker IN (0,1)),
    has_prop_firm_account       INTEGER NOT NULL DEFAULT 0 CHECK (has_prop_firm_account IN (0,1)),
    has_signal_provider         INTEGER NOT NULL DEFAULT 0 CHECK (has_signal_provider IN (0,1)),
    has_optimizer_overfit       INTEGER NOT NULL DEFAULT 0 CHECK (has_optimizer_overfit IN (0,1)),
    has_backtest_history        INTEGER NOT NULL DEFAULT 0 CHECK (has_backtest_history IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_mt_compiled
    ON host_arg_metatrader(file_path) WHERE has_compiled_ea = 1;

CREATE INDEX IF NOT EXISTS idx_mt_source
    ON host_arg_metatrader(file_path) WHERE has_source_ea = 1;

CREATE INDEX IF NOT EXISTS idx_mt_dll
    ON host_arg_metatrader(file_path) WHERE has_dll_plugin = 1;

CREATE INDEX IF NOT EXISTS idx_mt_password
    ON host_arg_metatrader(file_path) WHERE has_account_password = 1;

CREATE INDEX IF NOT EXISTS idx_mt_offshore
    ON host_arg_metatrader(broker_hostname) WHERE has_offshore_broker = 1;

CREATE INDEX IF NOT EXISTS idx_mt_prop
    ON host_arg_metatrader(broker_hostname) WHERE has_prop_firm_account = 1;

CREATE INDEX IF NOT EXISTS idx_mt_overfit
    ON host_arg_metatrader(file_path) WHERE has_optimizer_overfit = 1;

CREATE INDEX IF NOT EXISTS idx_mt_exposure
    ON host_arg_metatrader(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_mt_drift
    ON host_arg_metatrader(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_mt_platform
    ON host_arg_metatrader(platform, artifact_kind);

CREATE INDEX IF NOT EXISTS idx_mt_broker
    ON host_arg_metatrader(broker_class, broker_hostname);
