-- host_arg_motivewave inventories MotiveWave artifact files
-- cached on Argentine technical-analyst, Elliott-wave-focused,
-- pro-futures, prop-trader, and backtest-researcher
-- workstations.
--
-- MotiveWave is a **Java-based desktop algotrading platform**
-- specialized in:
--
--   1. Automatic Elliott Wave detection (its flagship niche).
--   2. Java Strategy SDK — .java strategies compiled to
--      .class, deployable as automated trading.
--   3. Extensions ecosystem — third-party Study .zip packs.
--   4. Plug-ins for Interactive Brokers, Rithmic, CQG,
--      IQFeed, TradeStation, TradeKing, etc.
--   5. DOM Trading panel + trading replay (paper mode).
--
-- **The MotiveWave Java + Elliott Wave layer.** Distinct from:
--
--   - iter 167 winargcqg          — CQG vendor terminal.
--   - iter 169 winargtt           — TT vendor terminal.
--   - iter 170 winargsierra       — Sierra Chart (DTC + ACSIL).
--   - iter 171 winargamibroker    — AmiBroker AFL (equity).
--   - iter 172 winargmulticharts  — MultiCharts PowerLanguage.
--   - iter 173 winargtradestation — TradeStation EasyLanguage.
--   - iter 179 winargquantower    — Quantower multi-asset .NET.
--
-- Workstation cache footprint (typical):
--
--   C:\Program Files\MotiveWave\          install root
--   ~/MotiveWave/                         user data
--   ~/MotiveWave/extensions/              .zip Study packs
--   ~/MotiveWave/workspaces/<name>.mwk    workspace
--   ~/MotiveWave/templates/<name>.mwt     template
--   ~/MotiveWave/strategies/<name>.java   Java strategy
--   ~/MotiveWave/strategies/<name>.class  compiled
--   ~/MotiveWave/connections/<broker>.cfg plug-in cfg
--   ~/MotiveWave/data/                    bar / tick cache
--   ~/MotiveWave/logs/<dt>.log            session log
--
-- MotiveWave-specific risk signals:
--
--   * Cleartext password in connection cfg = T1552 + CNV RG
--     1023.
--   * Broker plug-in credentials (IB TWS port, Rithmic R |
--     API user, CQG Continuum FIX) = T1078 across multi-
--     broker surface.
--   * Java Strategy with `Order(...)` / `submitOrder(...)` +
--     active deployment = CNV RG 622 art. 23 (Sistemas
--     Automatizados).
--   * Elliott Wave auto-detection rules with auto-trade =
--     unique signal-driven algo (transparency disclosure
--     concern under CNV RG 622 art. 23).
--   * Third-party extension .zip = supply-chain CWE-829
--     (arbitrary Java code from unverified author).
--   * DOM Trading armed with one-click execution = scalper /
--     HFT pattern.
--   * Paper-trading mode = simulated execution (lower-risk
--     but still credential surface).
--   * MATba-Rofex routing via IB plug-in = AR futures
--     contract surface (rare combo).
--   * Per-strategy cliente CUIT = client identity (Ley
--     26.831 art. 117 secreto bursátil).
--
-- Regulatory base:
--
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes (ALYC)
--   CNV RG 622 art.23 Sistemas Automatizados
--   CNV RG 622 art.50 Operativa con divisas
--   CNV RG 1023      Ciberresiliencia
--   BCRA Com. A 7916 Operaciones cambiarias
--   BCRA Com. A 8005 Ciberseguridad financiera
--   AFIP RG 5193     Securities tax reporting
--   AFIP F.8125      Cross-border transfer
--   Ley 25.326       Datos Personales
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1218    System Binary Proxy Execution (Java)
--   T1078    Valid Accounts
--   CWE-200, CWE-359, CWE-532, CWE-798, CWE-829
--
-- Headline finding shapes:
--
--   has_password_in_config         — cfg cleartext.
--   has_broker_plugin_credentials  — plug-in cred leak.
--   has_java_algo_strategy         — .java algo source.
--   has_elliott_wave_rules         — Elliott Wave auto-rule.
--   has_third_party_extension      — .zip Study pack.
--   has_dom_armed                  — DOM auto-execute.
--   has_paper_trading_mode         — paper-trading.
--   has_matba_rofex_routing        — MATba symbol via IB.
--   has_cme_futures                — CME futures symbol.
--   has_us_equity                  — US equity ticker.
--   has_cross_venue_arb            — multi-venue tables.
--   has_high_message_rate          — > 1000 msg/s.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable + (password OR
--                                    plug-in cred OR cliente
--                                    CUIT OR DOM armed).

CREATE TABLE IF NOT EXISTS host_arg_motivewave (
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
            'motivewave-config','motivewave-credentials',
            'motivewave-workspace','motivewave-template',
            'motivewave-java-strategy','motivewave-class-compiled',
            'motivewave-extension-pack','motivewave-connection-config',
            'motivewave-dom-config','motivewave-session-log',
            'motivewave-installer','other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'technical-analyst','elliott-wave-trader',
            'pro-futures','prop-trader','hft',
            'backtest-researcher','algotrader',
            'api','demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'matba-rofex','cme-futures','us-equity',
            'multi-asset','options','forex',
            'hft-execution','other','unknown'
        )),
    broker_plugin               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (broker_plugin IN (
            '','ib','rithmic','cqg','iqfeed','tradestation',
            'tradeking','custom','none','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    motivewave_account_id       TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    matba_symbols_count         INTEGER NOT NULL DEFAULT 0,
    cme_symbols_count           INTEGER NOT NULL DEFAULT 0,
    us_equity_symbols_count     INTEGER NOT NULL DEFAULT 0,
    peak_msg_per_sec            INTEGER NOT NULL DEFAULT 0,
    strategy_count              INTEGER NOT NULL DEFAULT 0,
    elliott_wave_rule_count     INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_broker_plugin_credentials INTEGER NOT NULL DEFAULT 0 CHECK (has_broker_plugin_credentials IN (0,1)),
    has_java_algo_strategy      INTEGER NOT NULL DEFAULT 0 CHECK (has_java_algo_strategy IN (0,1)),
    has_elliott_wave_rules      INTEGER NOT NULL DEFAULT 0 CHECK (has_elliott_wave_rules IN (0,1)),
    has_third_party_extension   INTEGER NOT NULL DEFAULT 0 CHECK (has_third_party_extension IN (0,1)),
    has_dom_armed               INTEGER NOT NULL DEFAULT 0 CHECK (has_dom_armed IN (0,1)),
    has_paper_trading_mode      INTEGER NOT NULL DEFAULT 0 CHECK (has_paper_trading_mode IN (0,1)),
    has_matba_rofex_routing     INTEGER NOT NULL DEFAULT 0 CHECK (has_matba_rofex_routing IN (0,1)),
    has_cme_futures             INTEGER NOT NULL DEFAULT 0 CHECK (has_cme_futures IN (0,1)),
    has_us_equity               INTEGER NOT NULL DEFAULT 0 CHECK (has_us_equity IN (0,1)),
    has_cross_venue_arb         INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_venue_arb IN (0,1)),
    has_high_message_rate       INTEGER NOT NULL DEFAULT 0 CHECK (has_high_message_rate IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_mw_password
    ON host_arg_motivewave(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_mw_plugin_creds
    ON host_arg_motivewave(broker_plugin, period_yyyymm) WHERE has_broker_plugin_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_mw_java_strategy
    ON host_arg_motivewave(file_path) WHERE has_java_algo_strategy = 1;

CREATE INDEX IF NOT EXISTS idx_mw_elliott_wave
    ON host_arg_motivewave(file_path) WHERE has_elliott_wave_rules = 1;

CREATE INDEX IF NOT EXISTS idx_mw_extension
    ON host_arg_motivewave(file_path) WHERE has_third_party_extension = 1;

CREATE INDEX IF NOT EXISTS idx_mw_dom
    ON host_arg_motivewave(file_path) WHERE has_dom_armed = 1;

CREATE INDEX IF NOT EXISTS idx_mw_paper
    ON host_arg_motivewave(file_path) WHERE has_paper_trading_mode = 1;

CREATE INDEX IF NOT EXISTS idx_mw_arb
    ON host_arg_motivewave(motivewave_account_id, period_yyyymm) WHERE has_cross_venue_arb = 1;

CREATE INDEX IF NOT EXISTS idx_mw_hft
    ON host_arg_motivewave(broker_plugin, peak_msg_per_sec) WHERE has_high_message_rate = 1;

CREATE INDEX IF NOT EXISTS idx_mw_cliente
    ON host_arg_motivewave(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_mw_exposure
    ON host_arg_motivewave(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_mw_drift
    ON host_arg_motivewave(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_mw_kind
    ON host_arg_motivewave(artifact_kind, account_class);
