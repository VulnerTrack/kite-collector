-- host_arg_tradestation inventories TradeStation EasyLanguage
-- artifact files cached on Argentine retail US-equity, futures
-- day-trader, prop-trader, HFT, and backtest-researcher
-- workstations.
--
-- TradeStation Securities (TS Group) is a US-regulated broker
-- whose desktop platform is built around **EasyLanguage** —
-- the original strategy / indicator language from which the
-- MultiCharts PowerLanguage (iter 172) was forked.
--
-- AR retail traders use TradeStation to:
--
--   1. Trade US equities (NYSE / NASDAQ).
--   2. Trade CME group futures (ES, NQ, CL, ZC...).
--   3. Run Walk Forward Optimizer (WFO) backtests.
--   4. Run RadarScreen real-time scanners.
--   5. Distribute strategies as .eld download packages.
--   6. Hit the TradeStation REST API from Python / .NET.
--
-- TradeStation distinctive surfaces:
--
--   - .els                EasyLanguage source (encrypted).
--   - .eld                EasyLanguage download package.
--   - .elc                EasyLanguage compiled.
--   - .tsi / .tss / .tsg  indicator / strategy / chart-group.
--   - .wkspace            workspace.
--   - .wfo                Walk Forward Optimizer.
--   - .rds                RadarScreen scanner.
--   - tsserver.cfg        TradeStation Network server cfg.
--   - OrderLog.txt        full order/fill trail.
--   - TradeManager.csv    trade-manager export.
--   - TradingAccount<id>  per-account cfg.
--   - TS API REST tokens  (`tradestation_token.json`).
--
-- **The TradeStation EasyLanguage layer.** Distinct from:
--
--   - iter 172 winargmulticharts  — MultiCharts PowerLanguage
--                                    (independent fork).
--   - iter 148 winargninjatrader  — NinjaTrader (NinjaScript).
--   - iter 170 winargsierra       — Sierra Chart (DTC + ACSIL).
--   - iter 171 winargamibroker    — AmiBroker AFL.
--   - iter 143 winargmt           — MetaTrader EAs (FX).
--   - iter 160 winarglean         — LEAN Python.
--   - iter 165 winargib           — Interactive Brokers TWS.
--
-- Workstation cache footprint (typical):
--
--   C:\Program Files (x86)\TradeStation 10.0\
--   C:\TradeStation 10.0\
--   %USERPROFILE%\Documents\TradeStation 10.0\
--   %USERPROFILE%\Documents\TradeStation 10.0\StudiesEL\
--   %USERPROFILE%\Documents\TradeStation 10.0\Workspaces\
--   %USERPROFILE%\Documents\TradeStation 10.0\Reports\
--   %APPDATA%\TradeStation\
--   %APPDATA%\TradeStation\tsserver.cfg
--   %APPDATA%\TradeStation\TradingAccount<id>.cfg
--   %APPDATA%\TradeStation\OrderLog.txt
--   ~/.tradestation/                       (cross-platform SDK)
--   ~/.config/tradestation/api_token.json
--
-- TradeStation-specific risk signals:
--
--   * Cleartext password in tsserver.cfg / TradingAccount.cfg
--     = T1552 + CNV RG 1023.
--   * TS API REST token leak = brokerage-account compromise
--     across all US equity + futures.
--   * .els encrypted strategy = intent to obfuscate logic
--     (review of strategy logic blocked, supply-chain
--     concern CWE-829).
--   * .eld download package from third-party vendor =
--     supply-chain code injection vector (T1218).
--   * Strategy assigned to chart with `AutoTrade=true` =
--     CNV RG 622 art. 23 (Sistemas Automatizados).
--   * RadarScreen scanner running > 100 symbols = market-
--     data redistribution concern (NYSE / CME license).
--   * WFO results with optimization metrics = competitive
--     IP (strategy disclosure risk).
--   * OrderLog.txt = full fill-level order trail
--     (BCRA Com. A 7916 if USD pair routed via wire).
--   * TradeManager.csv = aggregate P/L export
--     (AFIP RG 5193 if AR resident with US accounts).
--   * Cross-border USD flow > US$ 10 K = AFIP F.8125 trigger.
--   * Cliente CUIT + foreign brokerage = BCRA outbound
--     scrutiny + AFIP Bienes Personales aggregator.
--
-- Regulatory base:
--
--   Ley 26.831       Mercado de Capitales (AR side)
--   CNV RG 731       Régimen de Agentes
--   CNV RG 622 art.23 Sistemas Automatizados
--   CNV RG 622 art.50 Operativa con divisas
--   CNV RG 1023      Ciberresiliencia
--   BCRA Com. A 7916 Operaciones cambiarias
--   BCRA Com. A 8005 Ciberseguridad financiera
--   AFIP RG 5193     Securities tax reporting
--   AFIP F.8125      Cross-border transfer
--   Ley 25.246       PLA/FT
--   Ley 25.326       Protección de Datos Personales
--
-- US-side regs (TS broker-side, brokers must abide):
--
--   SEC Reg ATS / Reg NMS / FINRA Rule 4370 BCP
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1218    System Binary Proxy Execution
--   T1078    Valid Accounts
--   CWE-200, CWE-359, CWE-532, CWE-798, CWE-829
--
-- Headline finding shapes:
--
--   has_password_in_config        — cfg cleartext.
--   has_api_credentials           — TS REST API token.
--   has_easylanguage_encrypted    — .els encrypted strategy.
--   has_eld_download_package      — third-party .eld package.
--   has_strategy_autotrade        — auto-trade armed.
--   has_radar_screen              — RadarScreen scanner cfg.
--   has_walk_forward_optimization — WFO results.
--   has_orderlog_export           — OrderLog.txt present.
--   has_trademanager_export       — TradeManager.csv present.
--   has_us_equity                 — US equity ticker present.
--   has_cme_futures               — CME futures symbol.
--   has_matba_rofex_routing       — MATba symbol (rare).
--   has_cross_venue_arb           — multi-venue / cross-asset.
--   has_high_message_rate         — > 1000 msg/s pattern.
--   has_large_radar_screen        — > 100 RadarScreen symbols.
--   has_cliente_cuit              — cliente CUIT detected.
--   is_credential_exposure_risk   — readable + (password OR
--                                   API token OR orderlog OR
--                                   cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_tradestation (
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
            'ts-config','ts-credentials',
            'ts-els-source','ts-eld-package','ts-elc-compiled',
            'ts-indicator','ts-strategy','ts-chartgroup',
            'ts-workspace','ts-wfo-result','ts-radarscreen',
            'ts-orderlog','ts-trademanager','ts-trade-log',
            'ts-network-log','ts-api-script','ts-installer',
            'other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'us-equity-daytrader','pro-futures','prop-trader',
            'hft','backtest-researcher','algotrader',
            'api','demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'us-equity','cme-futures','matba-rofex',
            'options','forex','crypto',
            'multi-asset','hft-execution',
            'other','unknown'
        )),
    ts_account_id               TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    us_equity_symbols_count     INTEGER NOT NULL DEFAULT 0,
    cme_symbols_count           INTEGER NOT NULL DEFAULT 0,
    matba_symbols_count         INTEGER NOT NULL DEFAULT 0,
    radar_screen_symbols_count  INTEGER NOT NULL DEFAULT 0,
    peak_msg_per_sec            INTEGER NOT NULL DEFAULT 0,
    fill_count                  INTEGER NOT NULL DEFAULT 0,
    wfo_run_count               INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_api_credentials         INTEGER NOT NULL DEFAULT 0 CHECK (has_api_credentials IN (0,1)),
    has_easylanguage_encrypted  INTEGER NOT NULL DEFAULT 0 CHECK (has_easylanguage_encrypted IN (0,1)),
    has_eld_download_package    INTEGER NOT NULL DEFAULT 0 CHECK (has_eld_download_package IN (0,1)),
    has_strategy_autotrade      INTEGER NOT NULL DEFAULT 0 CHECK (has_strategy_autotrade IN (0,1)),
    has_radar_screen            INTEGER NOT NULL DEFAULT 0 CHECK (has_radar_screen IN (0,1)),
    has_walk_forward_optimization INTEGER NOT NULL DEFAULT 0 CHECK (has_walk_forward_optimization IN (0,1)),
    has_orderlog_export         INTEGER NOT NULL DEFAULT 0 CHECK (has_orderlog_export IN (0,1)),
    has_trademanager_export     INTEGER NOT NULL DEFAULT 0 CHECK (has_trademanager_export IN (0,1)),
    has_us_equity               INTEGER NOT NULL DEFAULT 0 CHECK (has_us_equity IN (0,1)),
    has_cme_futures             INTEGER NOT NULL DEFAULT 0 CHECK (has_cme_futures IN (0,1)),
    has_matba_rofex_routing     INTEGER NOT NULL DEFAULT 0 CHECK (has_matba_rofex_routing IN (0,1)),
    has_cross_venue_arb         INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_venue_arb IN (0,1)),
    has_high_message_rate       INTEGER NOT NULL DEFAULT 0 CHECK (has_high_message_rate IN (0,1)),
    has_large_radar_screen      INTEGER NOT NULL DEFAULT 0 CHECK (has_large_radar_screen IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_ts_password
    ON host_arg_tradestation(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_ts_api
    ON host_arg_tradestation(file_path) WHERE has_api_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_ts_els
    ON host_arg_tradestation(file_path) WHERE has_easylanguage_encrypted = 1;

CREATE INDEX IF NOT EXISTS idx_ts_eld
    ON host_arg_tradestation(file_path) WHERE has_eld_download_package = 1;

CREATE INDEX IF NOT EXISTS idx_ts_autotrade
    ON host_arg_tradestation(ts_account_id, period_yyyymm) WHERE has_strategy_autotrade = 1;

CREATE INDEX IF NOT EXISTS idx_ts_radar
    ON host_arg_tradestation(file_path, radar_screen_symbols_count) WHERE has_radar_screen = 1;

CREATE INDEX IF NOT EXISTS idx_ts_wfo
    ON host_arg_tradestation(ts_account_id, period_yyyymm) WHERE has_walk_forward_optimization = 1;

CREATE INDEX IF NOT EXISTS idx_ts_orderlog
    ON host_arg_tradestation(ts_account_id, period_yyyymm) WHERE has_orderlog_export = 1;

CREATE INDEX IF NOT EXISTS idx_ts_trademanager
    ON host_arg_tradestation(ts_account_id, period_yyyymm) WHERE has_trademanager_export = 1;

CREATE INDEX IF NOT EXISTS idx_ts_us_equity
    ON host_arg_tradestation(ts_account_id, period_yyyymm) WHERE has_us_equity = 1;

CREATE INDEX IF NOT EXISTS idx_ts_arb
    ON host_arg_tradestation(ts_account_id, period_yyyymm) WHERE has_cross_venue_arb = 1;

CREATE INDEX IF NOT EXISTS idx_ts_hft
    ON host_arg_tradestation(ts_account_id, peak_msg_per_sec) WHERE has_high_message_rate = 1;

CREATE INDEX IF NOT EXISTS idx_ts_large_radar
    ON host_arg_tradestation(file_path) WHERE has_large_radar_screen = 1;

CREATE INDEX IF NOT EXISTS idx_ts_cliente
    ON host_arg_tradestation(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ts_exposure
    ON host_arg_tradestation(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ts_drift
    ON host_arg_tradestation(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_ts_kind
    ON host_arg_tradestation(artifact_kind, account_class);
