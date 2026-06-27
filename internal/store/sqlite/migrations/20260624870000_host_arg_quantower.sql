-- host_arg_quantower inventories Quantower artifact files
-- cached on Argentine pro futures, crypto-arbitrageur, prop-
-- trader, HFT, and backtest-researcher workstations.
--
-- Quantower is a Windows / macOS desktop **multi-asset .NET
-- algotrading platform**. Unique among AR-adopted platforms,
-- it bundles crypto, futures, equity, and FX into a single
-- workstation. Core differentiators:
--
--   1. Crypto plug-ins        Binance, Bybit, Bitfinex,
--                             Kraken, Coinbase Pro.
--   2. Futures plug-ins       Rithmic, CQG Continuum, TT.
--   3. Equity / FX plug-ins   Interactive Brokers, dxFeed,
--                             OANDA.
--   4. C# Algo SDK            .cs strategies compiled to .dll.
--   5. Algo Builder           visual no-code strategy editor.
--   6. Multi-strategy launcher batch-run cfg.
--   7. DOM Trading            depth-of-market panel with
--                             one-click execution.
--   8. Paper-trading mode     simulated execution for QA.
--
-- **The Quantower multi-asset layer.** Distinct from:
--
--   - iter 167 winargcqg          — CQG vendor terminal.
--   - iter 169 winargtt           — TT vendor terminal.
--   - iter 170 winargsierra       — Sierra Chart (DTC futures).
--   - iter 171 winargamibroker    — AmiBroker AFL (equity).
--   - iter 172 winargmulticharts  — MultiCharts PowerLanguage.
--   - iter 173 winargtradestation — TradeStation EasyLanguage.
--   - iter 176 winargkdb          — KDB+/Q (HFT tick DB).
--   - iter 162 winargccxt         — CCXT lib (crypto SDK).
--
-- Workstation cache footprint (typical):
--
--   C:\Quantower\                     install root
--   C:\Quantower\Connections\         per-broker plug-in cfg
--   C:\Quantower\Strategies\          C# strategy .cs / .dll
--   C:\Quantower\AlgoBuilder\         visual algo cfg
--   C:\Quantower\Workspaces\*.qwt     workspace
--   C:\Quantower\Symbols.json         curated symbol list
--   C:\Quantower\Settings.xml         global settings
--   C:\Quantower\MultiStrategyLauncher\<batch>.json
--   %APPDATA%\Quantower\              user data
--   ~/.quantower/                     cross-platform SDK
--   ~/Library/Application Support/Quantower/
--
-- Quantower-specific risk signals:
--
--   * Cleartext password / API key in ConnectionConfig =
--     T1552 + CNV RG 1023.
--   * Broker plug-in credentials (Binance HMAC key, IB TWS
--     port, Rithmic R | API user/server, CQG Continuum FIX) =
--     T1078 across multi-broker surface.
--   * C# Algo SDK strategy with Buy/Sell/Cover orders +
--     active deployment = CNV RG 622 art. 23 (Sistemas
--     Automatizados).
--   * Multi-strategy launcher batch with auto-execute = bulk
--     algo activation surface.
--   * Quantower Algo Builder cfg = no-code visual strategy
--     (supply-chain CWE-829 if imported from third party).
--   * DOM Trading with `auto_execute=true` = scalper / HFT
--     pattern (CNV RG 622 art. 23 + 50 if FX).
--   * Crypto + futures + equity tables in same workspace =
--     extreme multi-venue / arbitrage account class.
--   * USDT/ARS or USDC/ARS in symbols = AR brecha-cambiaria
--     arbitrage (BCRA Com. A 7916 + AFIP RG 5527 trigger).
--   * Paper-trading mode = QA / non-production strategies
--     (lower-tier risk but still credential surface).
--   * Cliente CUIT in strategy / log = client identity
--     (Ley 26.831 art. 117).
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
--   AFIP RG 5527     Crypto / VASP reporting
--   AFIP F.8125      Cross-border transfer
--   Ley 25.326       Datos Personales
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
--   has_password_in_config         — cfg cleartext.
--   has_broker_plugin_credentials  — plug-in cred leak.
--   has_algo_sdk_script            — C# strategy script.
--   has_visual_algo_builder        — Algo Builder cfg.
--   has_multi_strategy_launcher    — batch launcher cfg.
--   has_dom_armed                  — DOM auto-execute.
--   has_paper_trading_mode         — paper-trading enabled.
--   has_matba_rofex_routing        — MATba symbol.
--   has_cme_futures                — CME futures symbol.
--   has_us_equity                  — US equity ticker.
--   has_crypto_data                — crypto symbol.
--   has_usdt_ars_arbitrage         — brecha logic.
--   has_cross_venue_arb            — multi-venue tables.
--   has_high_message_rate          — > 1000 msg/s HFT.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable + (password OR
--                                    plug-in cred OR cliente
--                                    CUIT OR DOM armed).

CREATE TABLE IF NOT EXISTS host_arg_quantower (
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
            'quantower-config','quantower-credentials',
            'quantower-workspace','quantower-symbols',
            'quantower-connection-config','quantower-algo-sdk-script',
            'quantower-algo-builder','quantower-multi-strategy-launcher',
            'quantower-dom-config','quantower-trade-log',
            'quantower-installer','other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'pro-futures','crypto-arbitrageur','prop-trader',
            'hft','backtest-researcher','algotrader',
            'multi-asset','api','demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'matba-rofex','cme-futures','us-equity',
            'crypto','forex','multi-asset',
            'hft-execution','other','unknown'
        )),
    broker_plugin               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (broker_plugin IN (
            '','binance','bybit','bitfinex','kraken','coinbase',
            'rithmic','cqg','tt','ib','dxfeed','oanda',
            'custom','none','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    quantower_account_id        TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    api_secret_hash             TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    matba_symbols_count         INTEGER NOT NULL DEFAULT 0,
    cme_symbols_count           INTEGER NOT NULL DEFAULT 0,
    us_equity_symbols_count     INTEGER NOT NULL DEFAULT 0,
    crypto_symbols_count        INTEGER NOT NULL DEFAULT 0,
    peak_msg_per_sec            INTEGER NOT NULL DEFAULT 0,
    strategy_count              INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_broker_plugin_credentials INTEGER NOT NULL DEFAULT 0 CHECK (has_broker_plugin_credentials IN (0,1)),
    has_algo_sdk_script         INTEGER NOT NULL DEFAULT 0 CHECK (has_algo_sdk_script IN (0,1)),
    has_visual_algo_builder     INTEGER NOT NULL DEFAULT 0 CHECK (has_visual_algo_builder IN (0,1)),
    has_multi_strategy_launcher INTEGER NOT NULL DEFAULT 0 CHECK (has_multi_strategy_launcher IN (0,1)),
    has_dom_armed               INTEGER NOT NULL DEFAULT 0 CHECK (has_dom_armed IN (0,1)),
    has_paper_trading_mode      INTEGER NOT NULL DEFAULT 0 CHECK (has_paper_trading_mode IN (0,1)),
    has_matba_rofex_routing     INTEGER NOT NULL DEFAULT 0 CHECK (has_matba_rofex_routing IN (0,1)),
    has_cme_futures             INTEGER NOT NULL DEFAULT 0 CHECK (has_cme_futures IN (0,1)),
    has_us_equity               INTEGER NOT NULL DEFAULT 0 CHECK (has_us_equity IN (0,1)),
    has_crypto_data             INTEGER NOT NULL DEFAULT 0 CHECK (has_crypto_data IN (0,1)),
    has_usdt_ars_arbitrage      INTEGER NOT NULL DEFAULT 0 CHECK (has_usdt_ars_arbitrage IN (0,1)),
    has_cross_venue_arb         INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_venue_arb IN (0,1)),
    has_high_message_rate       INTEGER NOT NULL DEFAULT 0 CHECK (has_high_message_rate IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_quantower_password
    ON host_arg_quantower(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_quantower_plugin_creds
    ON host_arg_quantower(broker_plugin, period_yyyymm) WHERE has_broker_plugin_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_quantower_algo_script
    ON host_arg_quantower(file_path) WHERE has_algo_sdk_script = 1;

CREATE INDEX IF NOT EXISTS idx_quantower_visual_algo
    ON host_arg_quantower(file_path) WHERE has_visual_algo_builder = 1;

CREATE INDEX IF NOT EXISTS idx_quantower_multi_launcher
    ON host_arg_quantower(file_path) WHERE has_multi_strategy_launcher = 1;

CREATE INDEX IF NOT EXISTS idx_quantower_dom
    ON host_arg_quantower(file_path) WHERE has_dom_armed = 1;

CREATE INDEX IF NOT EXISTS idx_quantower_paper
    ON host_arg_quantower(file_path) WHERE has_paper_trading_mode = 1;

CREATE INDEX IF NOT EXISTS idx_quantower_arb
    ON host_arg_quantower(quantower_account_id, period_yyyymm) WHERE has_cross_venue_arb = 1;

CREATE INDEX IF NOT EXISTS idx_quantower_usdt_ars
    ON host_arg_quantower(file_path) WHERE has_usdt_ars_arbitrage = 1;

CREATE INDEX IF NOT EXISTS idx_quantower_hft
    ON host_arg_quantower(broker_plugin, peak_msg_per_sec) WHERE has_high_message_rate = 1;

CREATE INDEX IF NOT EXISTS idx_quantower_cliente
    ON host_arg_quantower(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_quantower_exposure
    ON host_arg_quantower(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_quantower_drift
    ON host_arg_quantower(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_quantower_kind
    ON host_arg_quantower(artifact_kind, account_class);
