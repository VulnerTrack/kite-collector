-- host_arg_multicharts inventories MultiCharts artifact files
-- cached on Argentine pro futures, prop-trader, HFT, and
-- backtest-researcher workstations.
--
-- MultiCharts is a Windows desktop algotrading platform using
-- **PowerLanguage** (a TradeStation EasyLanguage dialect) and,
-- for the MultiCharts.NET variant, **C# / .NET strategies**.
-- AR / LatAm prop shops use it for the multi-broker plug-in
-- ecosystem (IB, Rithmic, CQG Continuum, IQFeed, Interactive
-- Data) and the **Portfolio Trader** for multi-symbol algos.
--
-- MultiCharts distinctive surfaces:
--
--   - .pla              encrypted PowerLanguage strategy
--   - .ela              exported PowerLanguage archive
--   - .wsp              workspace
--   - .pls              portfolio session
--   - .cs               C# script (MultiCharts.NET)
--   - QuoteManager SQL  local market-data database
--   - Profile.cfg       user profile
--   - MultiCharts.cfg   global config
--   - DOM config        Depth-of-Market trading panel
--   - Send-Order flag   auto-trading armed state
--   - Broker plug-ins   IB, Rithmic, CQG, IQFeed,
--                       Interactive Data, TT, MATba-Rofex
--
-- **The MultiCharts PowerLanguage layer.** Distinct from:
--
--   - iter 143 winargmt           — MetaTrader EAs (FX retail).
--   - iter 148 winargninjatrader  — NinjaTrader (NinjaScript).
--   - iter 160 winarglean         — LEAN Python (backtest).
--   - iter 167 winargcqg          — CQG vendor terminal.
--   - iter 169 winargtt           — TT vendor terminal.
--   - iter 170 winargsierra       — Sierra Chart (DTC + ACSIL).
--   - iter 171 winargamibroker    — AmiBroker AFL (equity).
--
-- Workstation cache footprint (typical):
--
--   C:\Program Files\TS Support\MultiCharts\
--   C:\Program Files\TS Support\MultiCharts64\
--   C:\Program Files\TS Support\MultiCharts .NET\
--   %APPDATA%\TS Support\MultiCharts\        user data
--   %APPDATA%\TS Support\MultiCharts\Studies\<*.pla,*.ela>
--   %APPDATA%\TS Support\MultiCharts\Workspaces\*.wsp
--   %APPDATA%\TS Support\MultiCharts\Portfolios\*.pls
--   %APPDATA%\TS Support\QuoteManager\       SQL data DB
--   MultiCharts.cfg                          global cfg
--   Profile.cfg                              user cfg
--   BrokerProfiles\<broker>.cfg              plug-in cfg
--
-- MultiCharts-specific risk signals:
--
--   * Cleartext password in BrokerProfiles\<broker>.cfg =
--     T1552 + CNV RG 1023.
--   * Broker plug-in credentials (IB TWS port 7496/7497,
--     Rithmic R | API user/server, CQG Continuum FIX) =
--     T1078.
--   * Send-Order Strategy flag enabled + strategy assigned
--     to chart = CNV RG 622 art. 23 (Sistemas Automatizados).
--   * Portfolio Trader with auto-execution = multi-symbol
--     algo execution (CNV RG 622 art. 23 + 50 combined).
--   * .pla encrypted strategy = intent to obfuscate
--     (review of strategy logic blocked, supply-chain
--     concern CWE-829).
--   * QuoteManager SQL DB > 1 GB = market-data
--     redistribution concern (CME / BYMA / CQG license).
--   * MATba-Rofex AND CME symbols in same workspace =
--     cross-venue arbitrage account.
--   * DOM Trading panel armed = scalper / HFT pattern.
--   * Custom C# strategy DLL = arbitrary native code
--     (T1218 + supply-chain CWE-829).
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
--   Ley 25.326       Protección de Datos Personales
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1218    System Binary Proxy Execution (.cs / .dll)
--   T1078    Valid Accounts
--   CWE-200, CWE-359, CWE-532, CWE-798, CWE-829
--
-- Headline finding shapes:
--
--   has_password_in_config         — config cleartext.
--   has_broker_plugin_credentials  — IB/Rithmic/CQG plug-in
--                                    bearer/port/token leak.
--   has_send_order_strategy        — Send-Order armed.
--   has_pla_encrypted              — .pla encrypted strategy.
--   has_portfolio_trader           — multi-symbol portfolio.
--   has_dom_armed                  — DOM Trading panel armed.
--   has_matba_rofex_routing        — MATba symbol present.
--   has_cme_futures                — CME group symbol.
--   has_cross_venue_arb            — both MATba + CME.
--   has_high_message_rate          — > 1000 msg/s.
--   has_quotemanager_db            — local QuoteManager DB.
--   has_large_quotemanager_db      — > 1 GB QuoteManager DB.
--   has_cs_native_strategy         — .cs C# script.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable + (password OR
--                                    plug-in cred OR cliente
--                                    CUIT OR send-order
--                                    armed).

CREATE TABLE IF NOT EXISTS host_arg_multicharts (
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
            'mc-config','mc-credentials',
            'mc-pla-strategy','mc-ela-strategy',
            'mc-workspace','mc-portfolio',
            'mc-quotemanager-db','mc-broker-plugin',
            'mc-portfolio-trader-config','mc-dom-config',
            'mc-net-script','mc-backtest-report',
            'mc-trade-log','mc-installer',
            'other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'pro-futures','prop-trader','arbitrageur',
            'hft','backtest-researcher','algotrader',
            'api','demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'cme-futures','matba-rofex','multi-venue',
            'options','forex','crypto',
            'hft-execution','other','unknown'
        )),
    broker_plugin               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (broker_plugin IN (
            '','ib','rithmic','cqg','iqfeed','interactive_data',
            'tt','matba_rofex','custom','none','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    mc_account_id               TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    matba_symbols_count         INTEGER NOT NULL DEFAULT 0,
    cme_symbols_count           INTEGER NOT NULL DEFAULT 0,
    peak_msg_per_sec            INTEGER NOT NULL DEFAULT 0,
    quotemanager_db_bytes       INTEGER NOT NULL DEFAULT 0,
    fill_count                  INTEGER NOT NULL DEFAULT 0,
    portfolio_symbol_count      INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_broker_plugin_credentials INTEGER NOT NULL DEFAULT 0 CHECK (has_broker_plugin_credentials IN (0,1)),
    has_send_order_strategy     INTEGER NOT NULL DEFAULT 0 CHECK (has_send_order_strategy IN (0,1)),
    has_pla_encrypted           INTEGER NOT NULL DEFAULT 0 CHECK (has_pla_encrypted IN (0,1)),
    has_portfolio_trader        INTEGER NOT NULL DEFAULT 0 CHECK (has_portfolio_trader IN (0,1)),
    has_dom_armed               INTEGER NOT NULL DEFAULT 0 CHECK (has_dom_armed IN (0,1)),
    has_matba_rofex_routing     INTEGER NOT NULL DEFAULT 0 CHECK (has_matba_rofex_routing IN (0,1)),
    has_cme_futures             INTEGER NOT NULL DEFAULT 0 CHECK (has_cme_futures IN (0,1)),
    has_cross_venue_arb         INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_venue_arb IN (0,1)),
    has_high_message_rate       INTEGER NOT NULL DEFAULT 0 CHECK (has_high_message_rate IN (0,1)),
    has_quotemanager_db         INTEGER NOT NULL DEFAULT 0 CHECK (has_quotemanager_db IN (0,1)),
    has_large_quotemanager_db   INTEGER NOT NULL DEFAULT 0 CHECK (has_large_quotemanager_db IN (0,1)),
    has_cs_native_strategy      INTEGER NOT NULL DEFAULT 0 CHECK (has_cs_native_strategy IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_mc_password
    ON host_arg_multicharts(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_mc_plugin_creds
    ON host_arg_multicharts(broker_plugin, period_yyyymm) WHERE has_broker_plugin_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_mc_send_order
    ON host_arg_multicharts(file_path) WHERE has_send_order_strategy = 1;

CREATE INDEX IF NOT EXISTS idx_mc_pla
    ON host_arg_multicharts(file_path) WHERE has_pla_encrypted = 1;

CREATE INDEX IF NOT EXISTS idx_mc_portfolio
    ON host_arg_multicharts(mc_account_id, period_yyyymm) WHERE has_portfolio_trader = 1;

CREATE INDEX IF NOT EXISTS idx_mc_dom
    ON host_arg_multicharts(file_path) WHERE has_dom_armed = 1;

CREATE INDEX IF NOT EXISTS idx_mc_arb
    ON host_arg_multicharts(mc_account_id, period_yyyymm) WHERE has_cross_venue_arb = 1;

CREATE INDEX IF NOT EXISTS idx_mc_hft
    ON host_arg_multicharts(broker_plugin, peak_msg_per_sec) WHERE has_high_message_rate = 1;

CREATE INDEX IF NOT EXISTS idx_mc_qm_db
    ON host_arg_multicharts(file_path) WHERE has_large_quotemanager_db = 1;

CREATE INDEX IF NOT EXISTS idx_mc_cs_strategy
    ON host_arg_multicharts(file_path) WHERE has_cs_native_strategy = 1;

CREATE INDEX IF NOT EXISTS idx_mc_cliente
    ON host_arg_multicharts(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_mc_exposure
    ON host_arg_multicharts(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_mc_drift
    ON host_arg_multicharts(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_mc_kind
    ON host_arg_multicharts(artifact_kind, account_class);
