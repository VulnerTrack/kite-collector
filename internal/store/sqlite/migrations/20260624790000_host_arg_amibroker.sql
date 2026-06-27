-- host_arg_amibroker inventories AmiBroker artifact files
-- cached on Argentine retail equity day-trader, technician,
-- algotrader, and backtest-researcher workstations.
--
-- AmiBroker is a Windows desktop technical-analysis platform
-- centered on **AFL (AmiBroker Formula Language)**. AR retail
-- traders favor it over MetaTrader for equity work because:
--
--   1. Native BYMA / MERVAL ticker coverage via plug-ins.
--   2. CEDEAR analysis (foreign-stock receipts).
--   3. AR sovereign-bond curve plotting (AL30, GD30, AE38).
--   4. AutoTrade Window can fire live orders via broker
--      plug-in DLLs (IB, IOL, Cocos, custom).
--   5. .adat local market-data database lets a single
--      workstation hold years of intraday history.
--
-- **The AmiBroker AFL layer.** Distinct from:
--
--   - iter 143 winargmt           — MetaTrader EAs (FX retail).
--   - iter 148 winargninjatrader  — NinjaTrader (futures).
--   - iter 160 winarglean         — LEAN Python (backtest).
--   - iter 162 winargccxt         — CCXT (crypto).
--   - iter 167 winargcqg          — CQG (futures vendor).
--   - iter 169 winargtt           — TT (futures vendor).
--   - iter 170 winargsierra       — Sierra Chart (DTC).
--
-- Workstation cache footprint (typical):
--
--   C:\Program Files\AmiBroker\
--   C:\Program Files\AmiBroker\Plugins\          broker DLLs
--   %USERPROFILE%\Documents\AmiBroker\
--   %USERPROFILE%\Documents\AmiBroker\Formulas\  AFL formulas
--   %USERPROFILE%\Documents\AmiBroker\Databases\ .adat caches
--   %USERPROFILE%\Documents\AmiBroker\<proj>.apx project
--   %USERPROFILE%\Documents\AmiBroker\<wsp>.awx  workspace
--   Broker.txt                                   broker cfg
--   Layouts\<name>.cdl                           chart layouts
--
-- AmiBroker-specific risk signals:
--
--   * Cleartext password in Broker.txt = T1552 + CNV RG 1023
--   * Broker plug-in credentials (Interactive Brokers TWS
--     port 7496/7497, IOL/Cocos API tokens) = T1078
--   * AutoTrade Window armed + AFL with Buy/Sell statements
--     = CNV RG 622 art. 23 (Sistemas Automatizados)
--   * .adat > 500 MB = BYMA market-data redistribution
--     concern (BYMA Reglamento Operativo cap. VII)
--   * AFL formula with broker-specific Order() / PlaceTrade()
--     calls = live-execution capability
--   * MERV/MERVAL index in AFL = AR equity strategy
--   * GGAL/YPFD/PAMP/EDN/TXAR (BYMA tickers) in AFL
--   * AL30/AE38/GD30/AL35/GD35 (AR sovereigns) in AFL
--   * <ticker>D / <ticker>C suffix = CEDEAR class
--   * Cliente CUIT in trade log = AML/UIF reporting target
--   * Plug-in DLL signed by foreign vendor = supply-chain
--     review surface (CWE-829)
--
-- Regulatory base:
--
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes (ALYC)
--   CNV RG 622 art.23 Sistemas Automatizados
--   CNV RG 622 art.50 Operativa con divisas
--   CNV RG 1023      Ciberresiliencia
--   BCRA Com. A 7916 Operaciones cambiarias
--   BYMA Reglamento Operativo cap. VII (datos)
--   AFIP RG 5193     Securities tax reporting
--   Ley 25.326       Protección de Datos Personales
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1218    System Binary Proxy Execution (plug-in DLL)
--   T1078    Valid Accounts
--   CWE-200, CWE-359, CWE-532, CWE-798, CWE-829
--
-- Headline finding shapes:
--
--   has_password_in_config       — Broker.txt cleartext.
--   has_broker_plugin_credentials — IB/IOL/Cocos plug-in
--                                  bearer/port/token.
--   has_autotrade_armed          — AutoTrade Window enabled.
--   has_afl_with_orders          — AFL with Buy/Sell/Cover/Short.
--   has_byma_equity              — BYMA equity ticker present.
--   has_merv_strategy            — MERVAL index strategy.
--   has_cedear                   — CEDEAR ticker.
--   has_ar_bond                  — AR sovereign bond (AL30,
--                                  GD30, AE38…).
--   has_live_trade_log           — trade log shows fills.
--   has_large_adat_cache         — > 500 MB local market-data.
--   has_plugin_dll               — broker plug-in DLL.
--   has_cliente_cuit             — cliente CUIT detected.
--   is_credential_exposure_risk  — readable + (password OR
--                                  plug-in cred OR live trade
--                                  log OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_amibroker (
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
            'ami-config','ami-credentials',
            'ami-afl-formula','ami-apx-project',
            'ami-adat-database','ami-workspace',
            'ami-broker-plugin','ami-autotrade-config',
            'ami-backtest-report','ami-trade-log',
            'ami-layout','ami-installer',
            'other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'equity-daytrader','algotrader',
            'backtest-researcher','prop-trader',
            'api','demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'byma-equity','merv-index','ar-bonds',
            'ar-cedears','multi-asset',
            'crypto','forex','other','unknown'
        )),
    broker_plugin               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (broker_plugin IN (
            '','ib','iol','cocos','byma','rofex','tws',
            'custom','none','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    plugin_dll_name             TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_tickers_count      INTEGER NOT NULL DEFAULT 0,
    byma_tickers_count          INTEGER NOT NULL DEFAULT 0,
    cedear_tickers_count        INTEGER NOT NULL DEFAULT 0,
    ar_bond_tickers_count       INTEGER NOT NULL DEFAULT 0,
    order_statement_count       INTEGER NOT NULL DEFAULT 0,
    fill_count                  INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_broker_plugin_credentials INTEGER NOT NULL DEFAULT 0 CHECK (has_broker_plugin_credentials IN (0,1)),
    has_autotrade_armed         INTEGER NOT NULL DEFAULT 0 CHECK (has_autotrade_armed IN (0,1)),
    has_afl_with_orders         INTEGER NOT NULL DEFAULT 0 CHECK (has_afl_with_orders IN (0,1)),
    has_byma_equity             INTEGER NOT NULL DEFAULT 0 CHECK (has_byma_equity IN (0,1)),
    has_merv_strategy           INTEGER NOT NULL DEFAULT 0 CHECK (has_merv_strategy IN (0,1)),
    has_cedear                  INTEGER NOT NULL DEFAULT 0 CHECK (has_cedear IN (0,1)),
    has_ar_bond                 INTEGER NOT NULL DEFAULT 0 CHECK (has_ar_bond IN (0,1)),
    has_live_trade_log          INTEGER NOT NULL DEFAULT 0 CHECK (has_live_trade_log IN (0,1)),
    has_large_adat_cache        INTEGER NOT NULL DEFAULT 0 CHECK (has_large_adat_cache IN (0,1)),
    has_plugin_dll              INTEGER NOT NULL DEFAULT 0 CHECK (has_plugin_dll IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_ami_password
    ON host_arg_amibroker(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_ami_plugin_creds
    ON host_arg_amibroker(broker_plugin, period_yyyymm) WHERE has_broker_plugin_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_ami_autotrade
    ON host_arg_amibroker(file_path) WHERE has_autotrade_armed = 1;

CREATE INDEX IF NOT EXISTS idx_ami_afl_orders
    ON host_arg_amibroker(file_path) WHERE has_afl_with_orders = 1;

CREATE INDEX IF NOT EXISTS idx_ami_byma
    ON host_arg_amibroker(broker_plugin, period_yyyymm) WHERE has_byma_equity = 1;

CREATE INDEX IF NOT EXISTS idx_ami_merv
    ON host_arg_amibroker(file_path) WHERE has_merv_strategy = 1;

CREATE INDEX IF NOT EXISTS idx_ami_cedear
    ON host_arg_amibroker(file_path) WHERE has_cedear = 1;

CREATE INDEX IF NOT EXISTS idx_ami_ar_bond
    ON host_arg_amibroker(file_path) WHERE has_ar_bond = 1;

CREATE INDEX IF NOT EXISTS idx_ami_live_log
    ON host_arg_amibroker(broker_plugin, period_yyyymm) WHERE has_live_trade_log = 1;

CREATE INDEX IF NOT EXISTS idx_ami_adat
    ON host_arg_amibroker(file_path) WHERE has_large_adat_cache = 1;

CREATE INDEX IF NOT EXISTS idx_ami_plugin_dll
    ON host_arg_amibroker(broker_plugin, plugin_dll_name) WHERE has_plugin_dll = 1;

CREATE INDEX IF NOT EXISTS idx_ami_cliente
    ON host_arg_amibroker(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ami_exposure
    ON host_arg_amibroker(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ami_drift
    ON host_arg_amibroker(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_ami_kind
    ON host_arg_amibroker(artifact_kind, account_class);
