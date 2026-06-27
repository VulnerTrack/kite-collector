-- host_arg_ninjatrader inventories NinjaTrader 8 futures-
-- algotrading files cached on Argentine prop-desk and quant
-- workstations.
--
-- NinjaTrader 8 is the dominant Windows desktop platform for
-- futures algo trading (CME e-minis, energy, metals, crops).
-- Argentine prop desks use NT8 against:
--
--   ROFEX bridged futures (DLR / DOM / ROS / Soja-MAY)
--   CME e-minis (ES / NQ / RTY / YM)
--   ICE energy (CL / BZ / NG)
--   COMEX metals (GC / SI / HG)
--   ICE softs (KC / SB / CC)
--
-- Workstation cache footprint:
--
--   C:\Program Files (x86)\NinjaTrader 8\               install
--   %USERPROFILE%\Documents\NinjaTrader 8\
--      bin\Custom\Strategies\*.cs                       C# strategy
--      bin\Custom\Indicators\*.cs                       C# indicator
--      bin\Custom\BarsTypes\*.cs                        custom bar
--      bin\Custom\DrawingTools\*.cs                     custom draw
--      bin\Custom\AddOns\*.cs                           add-on
--      templates\Strategy\*.xml                         strategy params
--      templates\Chart\*.xml                            chart layout
--      db\*.db                                          account DB
--      log\Output_*.txt                                 NT8 log
--      log\Trace_*.txt                                  trace log
--   %APPDATA%\NinjaTrader 8\
--
-- **The NinjaTrader 8 futures deep-dive.** Distinct from:
--   - iter 108 winalgotrading  — generic EA cover
--   - iter 143 winargmt        — MetaTrader 4/5 deep-dive
--   - iter 139 winargprimary   — Primary REST/WS API
--   - iter 109 winargmatbarofex MATba-Rofex positions
--
-- NinjaTrader-specific risk signals:
--   * .cs source = algorithmic IP exposure (full C# strategy
--     code readable).
--   * Live broker route (Rithmic / AMP / IB) = real-money
--     trading exposure.
--   * Account credentials in db\Accounts.db = full account
--     impersonation.
--   * Data-provider login in connections.xml = persistent
--     market-data subscription leak.
--   * Strategy Optimizer with > 5000 iterations = curve-fit
--     signature.
--   * Replay mode used in production strategy = invalid live
--     trades.
--
-- Regulatory base:
--   AFIP Bienes Personales (offshore brokerage account)
--   BCRA Com. A 7916 (operaciones cambiarias)
--   CNV RG 731       Régimen de Agentes
--   CNV RG 622       Operativa
--   Ley 25.246       PLA/FT (income from futures trading)
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials (accounts.db)
--   T1574    Hijack Execution Flow (add-on)
--   CWE-200, CWE-359, CWE-532, CWE-798
--   Ley 25.326 (account holder PII)
--
-- Headline finding shapes:
--   has_compiled_strategy     — .cs strategy source on disk.
--   has_live_broker_route     — connection to live broker
--                              (Rithmic / AMP / IB).
--   has_account_credentials   — db\Accounts.db readable.
--   has_data_provider_login   — connections.xml has login.
--   has_overfit_optimization  — optimizer > 5000 iterations.
--   has_replay_dump           — market-replay file on disk.
--   has_addon_dll             — third-party add-on .cs / .dll.
--   is_credential_exposure_risk — readable file +
--                              (creds OR live route OR addon).
--
-- Account login retained as truncated last-4-chars (NT8
-- accounts are alphanumeric, not pure digit).

CREATE TABLE IF NOT EXISTS host_arg_ninjatrader (
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
            'ninja-strategy-cs','ninja-indicator-cs',
            'ninja-bartype-cs','ninja-drawing-cs',
            'ninja-addon-cs','ninja-templates-xml',
            'ninja-account-db','ninja-instrument-db',
            'ninja-position-cache','ninja-log',
            'ninja-installer','other','unknown'
        )),
    account_type                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_type IN (
            'live','demo','replay','continuous-futures',
            'other','unknown'
        )),
    broker_route                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (broker_route IN (
            'ninjatrader-brokerage','continuum-data','kinetick',
            'rithmic','amp-futures','tradestation',
            'interactive-brokers','other','unknown'
        )),
    account_login_suffix4       TEXT    NOT NULL DEFAULT '',
    instrument_count            INTEGER NOT NULL DEFAULT 0,
    strategy_name               TEXT    NOT NULL DEFAULT '',
    optimizer_iterations        INTEGER NOT NULL DEFAULT 0,
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_compiled_strategy       INTEGER NOT NULL DEFAULT 0 CHECK (has_compiled_strategy IN (0,1)),
    has_live_broker_route       INTEGER NOT NULL DEFAULT 0 CHECK (has_live_broker_route IN (0,1)),
    has_account_credentials     INTEGER NOT NULL DEFAULT 0 CHECK (has_account_credentials IN (0,1)),
    has_data_provider_login     INTEGER NOT NULL DEFAULT 0 CHECK (has_data_provider_login IN (0,1)),
    has_overfit_optimization    INTEGER NOT NULL DEFAULT 0 CHECK (has_overfit_optimization IN (0,1)),
    has_replay_dump             INTEGER NOT NULL DEFAULT 0 CHECK (has_replay_dump IN (0,1)),
    has_addon_dll               INTEGER NOT NULL DEFAULT 0 CHECK (has_addon_dll IN (0,1)),
    has_argentine_futures       INTEGER NOT NULL DEFAULT 0 CHECK (has_argentine_futures IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_nt_strategy
    ON host_arg_ninjatrader(file_path) WHERE has_compiled_strategy = 1;

CREATE INDEX IF NOT EXISTS idx_nt_live
    ON host_arg_ninjatrader(broker_route) WHERE has_live_broker_route = 1;

CREATE INDEX IF NOT EXISTS idx_nt_creds
    ON host_arg_ninjatrader(file_path) WHERE has_account_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_nt_data_login
    ON host_arg_ninjatrader(broker_route) WHERE has_data_provider_login = 1;

CREATE INDEX IF NOT EXISTS idx_nt_overfit
    ON host_arg_ninjatrader(file_path) WHERE has_overfit_optimization = 1;

CREATE INDEX IF NOT EXISTS idx_nt_replay
    ON host_arg_ninjatrader(file_path) WHERE has_replay_dump = 1;

CREATE INDEX IF NOT EXISTS idx_nt_addon
    ON host_arg_ninjatrader(file_path) WHERE has_addon_dll = 1;

CREATE INDEX IF NOT EXISTS idx_nt_arg_fut
    ON host_arg_ninjatrader(period_yyyymm) WHERE has_argentine_futures = 1;

CREATE INDEX IF NOT EXISTS idx_nt_exposure
    ON host_arg_ninjatrader(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_nt_drift
    ON host_arg_ninjatrader(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_nt_route
    ON host_arg_ninjatrader(broker_route, account_type);

CREATE INDEX IF NOT EXISTS idx_nt_kind
    ON host_arg_ninjatrader(artifact_kind, account_type);
