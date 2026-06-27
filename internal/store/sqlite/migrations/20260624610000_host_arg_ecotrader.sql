-- host_arg_ecotrader inventories Eco Trader / ROFEX Trader
-- Pro desktop-terminal artifact files cached on Argentine
-- prop-desk, quant, and broker workstations.
--
-- ROFEX Trader Pro (also branded "Eco Trader") is the
-- commercial Windows desktop terminal for ROFEX (now
-- MATba-Rofex) futures + options trading. It is the GUI
-- alternative to the Primary REST/WS API (used by quants)
-- and SIOPEL (used for MAE OTC). Eco Trader bridges to the
-- MATba-Rofex matching engine via either:
--
--   Primary API gateway   (REST)
--   Direct FIX            (FIX 4.4 session)
--
-- ROFEX-listed instruments include:
--
--   DLR / DOM            Dollar-futures (BCRA Com. A 7916)
--   ROS / WK             Soja / Trigo / Maíz / Girasol
--   CER / UVA            Inflation-linked futures
--   MTR-USD              MERVAL-USD micro-futures
--   AL30F / GD30F        Sovereign futures (rare)
--
-- Workstation cache footprint:
--
--   C:\ROFEX\TraderPro\config\settings.xml       terminal cfg
--   C:\ROFEX\TraderPro\logs\session_<dt>.log     session log
--   C:\ROFEX\TraderPro\positions_cache.json      positions
--   C:\ROFEX\TraderPro\watchlists\<name>.xml     watchlist
--   C:\ROFEX\TraderPro\charts\<symbol>.cht       chart template
--   C:\ROFEX\TraderPro\quotes\<dt>.qte           quote cache
--   C:\Eco Trader\settings.ini                   Eco brand cfg
--
-- **The ROFEX-desktop-GUI layer.** Distinct from:
--   - iter 109 winargmatbarofex  MATba-Rofex positions
--   - iter 139 winargprimary     Primary REST/WS (pyRofex)
--   - iter 143 winargmt          MetaTrader 4/5
--   - iter 148 winargninjatrader NinjaTrader 8 futures
--   - iter 136 winargsiopel      SIOPEL/MAE OTC terminal
--
-- Eco Trader-specific risk signals:
--   * Dollar-futures (DLR / DOM) trading > monthly cap =
--     BCRA Com. A 7916 dollarization breach risk.
--   * Agro-futures concentration > 50 % of portfolio =
--     hedge-fund signal (not retail).
--   * Cleartext Password / Clave in settings.xml = T1552.
--   * Session activity outside 09:00-16:00 ART = after-hours
--     operations (CNV monitoring threshold).
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes
--   CNV RG 622       Operativa
--   BCRA Com. A 7916 operaciones cambiarias
--   MATba-Rofex Manual de Operatoria
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials (settings.xml Password)
--   T1078    Valid Accounts
--   CWE-200, CWE-359, CWE-532, CWE-798
--   Ley 25.326 (cliente CUIT en positions cache)
--
-- Headline finding shapes:
--   has_password_in_config     — settings.xml cleartext.
--   has_dollar_futures_dlr     — DLR / DOM in watchlist.
--   has_agro_futures           — SOJ / MAI / TRI / GIR / SOR.
--   has_inflation_futures      — CER / UVA.
--   has_mtr_usd_bridge         — MTR-USD micro-future.
--   has_after_hours_session    — session outside venue hrs.
--   has_cliente_cuit           — cliente CUIT detected.
--   is_credential_exposure_risk — readable file +
--                              (password OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_ecotrader (
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
            'ecotrader-config','ecotrader-session-log',
            'ecotrader-positions-cache','ecotrader-watchlist',
            'ecotrader-chart-template','ecotrader-quotes-cache',
            'ecotrader-installer','other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'primary-api','direct-fix','demo',
            'other','unknown'
        )),
    broker_matricula            TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    account_login_suffix4       TEXT    NOT NULL DEFAULT '',
    distinct_futures_count      INTEGER NOT NULL DEFAULT 0,
    max_position_lots           INTEGER NOT NULL DEFAULT 0,
    dollar_futures_lots         INTEGER NOT NULL DEFAULT 0,
    agro_futures_lots           INTEGER NOT NULL DEFAULT 0,
    session_first_seen          TEXT    NOT NULL DEFAULT '',
    session_last_seen           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_dollar_futures_dlr      INTEGER NOT NULL DEFAULT 0 CHECK (has_dollar_futures_dlr IN (0,1)),
    has_agro_futures            INTEGER NOT NULL DEFAULT 0 CHECK (has_agro_futures IN (0,1)),
    has_inflation_futures       INTEGER NOT NULL DEFAULT 0 CHECK (has_inflation_futures IN (0,1)),
    has_mtr_usd_bridge          INTEGER NOT NULL DEFAULT 0 CHECK (has_mtr_usd_bridge IN (0,1)),
    has_after_hours_session     INTEGER NOT NULL DEFAULT 0 CHECK (has_after_hours_session IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_ecotrader_password
    ON host_arg_ecotrader(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_ecotrader_dlr
    ON host_arg_ecotrader(broker_matricula, period_yyyymm) WHERE has_dollar_futures_dlr = 1;

CREATE INDEX IF NOT EXISTS idx_ecotrader_agro
    ON host_arg_ecotrader(broker_matricula, period_yyyymm) WHERE has_agro_futures = 1;

CREATE INDEX IF NOT EXISTS idx_ecotrader_cer
    ON host_arg_ecotrader(broker_matricula, period_yyyymm) WHERE has_inflation_futures = 1;

CREATE INDEX IF NOT EXISTS idx_ecotrader_mtr
    ON host_arg_ecotrader(broker_matricula) WHERE has_mtr_usd_bridge = 1;

CREATE INDEX IF NOT EXISTS idx_ecotrader_afterhours
    ON host_arg_ecotrader(broker_matricula, period_yyyymm) WHERE has_after_hours_session = 1;

CREATE INDEX IF NOT EXISTS idx_ecotrader_cliente
    ON host_arg_ecotrader(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ecotrader_exposure
    ON host_arg_ecotrader(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ecotrader_drift
    ON host_arg_ecotrader(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_ecotrader_kind
    ON host_arg_ecotrader(artifact_kind, account_class);
