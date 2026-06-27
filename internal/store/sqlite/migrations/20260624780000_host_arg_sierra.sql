-- host_arg_sierra inventories Sierra Chart artifact files cached
-- on Argentine pro futures, prop-trader, HFT, and quant
-- workstations.
--
-- Sierra Chart is a desktop futures / options charting and
-- execution platform that speaks the **DTC (Data and Trading
-- Communications) protocol** — a binary, low-latency wire
-- protocol distinct from FIX. AR prop shops use Sierra to
-- trade MATba-Rofex DLR futures + CME index/oil/grain
-- futures, often via Stage 5 Trading / Edge Clear / Optimus
-- Futures DTC servers.
--
-- Sierra Chart distinctive surfaces:
--
--   - Workspaces (.cwsp)        chart-page layouts
--   - Chartbooks (.cht)         multi-chart bundles
--   - .scid                     intraday tick-by-tick data
--   - .dly                      daily OHLC bars
--   - .scss                     study source (C++ for ACSIL)
--   - ACSIL .dll                custom-study compiled module
--   - .spreadsheet              spreadsheet trade-system
--   - tradingactivity.txt       full order/fill trail
--   - logs/<date>.txt           DTC session + msg log
--   - sierra.config             global config (cleartext)
--   - sierrachart.com           account / billing config
--
-- **The Sierra Chart DTC layer.** Distinct from:
--
--   - iter 167 winargcqg          — CQG vendor-tier.
--   - iter 169 winargtt           — TT vendor-tier (FIX 4.4).
--   - iter 148 winargninjatrader  — NinjaTrader (similar tier).
--   - iter 143 winargmt           — MetaTrader (FX retail).
--   - iter 109 winargmatbarofex   — MATba-Rofex direct.
--   - iter 139 winargprimary      — Primary REST/WS.
--
-- Workstation cache footprint (typical):
--
--   C:\SierraChart\Data\<symbol>.scid         tick data
--   C:\SierraChart\Data\<symbol>.dly          daily bars
--   C:\SierraChart\<workspace>.cwsp           workspace
--   C:\SierraChart\<chartbook>.cht            chart book
--   C:\SierraChart\ACS_Source\<study>.cpp     ACSIL source
--   C:\SierraChart\Data\<study>.dll           ACSIL module
--   C:\SierraChart\sierra.config              config
--   C:\SierraChart\tradingactivity.txt        order trail
--   C:\SierraChart\logs\<YYYYMMDD>.txt        DTC log
--   %USERPROFILE%\Documents\SierraChart\...
--   /opt/SierraChart/...   (via Wine)
--
-- Sierra-specific risk signals:
--
--   * Cleartext password / DTC server password in
--     sierra.config = T1552 + CNV RG 1023
--   * DTC server URL leak = broker-routing intelligence
--     (Stage 5 / Edge Clear / Optimus address surface)
--   * tradingactivity.txt = full fill-level order trail
--     (CNV RG 622 art. 50 + BCRA Com. A 7916 if USD pair)
--   * .scid tick data > 1 GB = market-data redistribution
--     concern (BYMA / CME license)
--   * ACSIL .dll custom study = arbitrary native code
--     (T1218 + CWE-829 supply chain)
--   * Cross-venue (MATba-Rofex + CME) symbols in same
--     workspace = arbitrage account class
--   * Spreadsheet trade-system with auto-trade enabled =
--     CNV RG 622 art. 23 automated-trading flag
--   * High msg/s in DTC log = HFT pattern
--
-- Regulatory base:
--
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes (ALYC)
--   CNV RG 622 art.23 Operativa Sistemas Automatizados
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
--   T1218    System Binary Proxy Execution (ACSIL DLL)
--   T1078    Valid Accounts
--   CWE-200, CWE-359, CWE-532, CWE-798, CWE-829
--
-- Headline finding shapes:
--
--   has_password_in_config        — config cleartext.
--   has_dtc_session               — DTC binary-protocol log.
--   has_dtc_server_url            — broker-routing leak.
--   has_trading_activity_export   — order/fill trail dump.
--   has_acsil_native_module       — custom .dll study.
--   has_matba_rofex_routing       — MATba symbol in artifact.
--   has_cme_futures               — CME group symbol.
--   has_cross_venue_arb           — both MATba + CME.
--   has_spreadsheet_autotrade     — .spreadsheet auto-trade.
--   has_high_message_rate         — > 1000 msg/s DTC pattern.
--   has_large_tick_cache          — > 1 GB .scid file.
--   has_cliente_cuit              — cliente CUIT detected.
--   is_credential_exposure_risk   — readable + (password OR
--                                   tradingactivity OR DTC URL
--                                   OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_sierra (
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
            'sierra-config','sierra-credentials',
            'sierra-workspace','sierra-chartbook',
            'sierra-scid-tick','sierra-dly-daily',
            'sierra-acsil-source','sierra-acsil-module',
            'sierra-spreadsheet','sierra-trading-activity',
            'sierra-dtc-log','sierra-installer',
            'other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'pro-futures','prop-trader','arbitrageur',
            'hft','quant-research','demo',
            'other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'cme-futures','matba-rofex','global-futures',
            'multi-venue','options','hft-execution',
            'other','unknown'
        )),
    dtc_server_host             TEXT    NOT NULL DEFAULT '',
    dtc_server_port             INTEGER NOT NULL DEFAULT 0,
    sierra_account_id           TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    matba_symbols_count         INTEGER NOT NULL DEFAULT 0,
    cme_symbols_count           INTEGER NOT NULL DEFAULT 0,
    peak_msg_per_sec            INTEGER NOT NULL DEFAULT 0,
    tick_cache_bytes            INTEGER NOT NULL DEFAULT 0,
    fill_count                  INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_dtc_session             INTEGER NOT NULL DEFAULT 0 CHECK (has_dtc_session IN (0,1)),
    has_dtc_server_url          INTEGER NOT NULL DEFAULT 0 CHECK (has_dtc_server_url IN (0,1)),
    has_trading_activity_export INTEGER NOT NULL DEFAULT 0 CHECK (has_trading_activity_export IN (0,1)),
    has_acsil_native_module     INTEGER NOT NULL DEFAULT 0 CHECK (has_acsil_native_module IN (0,1)),
    has_matba_rofex_routing     INTEGER NOT NULL DEFAULT 0 CHECK (has_matba_rofex_routing IN (0,1)),
    has_cme_futures             INTEGER NOT NULL DEFAULT 0 CHECK (has_cme_futures IN (0,1)),
    has_cross_venue_arb         INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_venue_arb IN (0,1)),
    has_spreadsheet_autotrade   INTEGER NOT NULL DEFAULT 0 CHECK (has_spreadsheet_autotrade IN (0,1)),
    has_high_message_rate       INTEGER NOT NULL DEFAULT 0 CHECK (has_high_message_rate IN (0,1)),
    has_large_tick_cache        INTEGER NOT NULL DEFAULT 0 CHECK (has_large_tick_cache IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_sierra_password
    ON host_arg_sierra(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_sierra_dtc_session
    ON host_arg_sierra(dtc_server_host, period_yyyymm) WHERE has_dtc_session = 1;

CREATE INDEX IF NOT EXISTS idx_sierra_dtc_url
    ON host_arg_sierra(dtc_server_host, dtc_server_port) WHERE has_dtc_server_url = 1;

CREATE INDEX IF NOT EXISTS idx_sierra_trading_activity
    ON host_arg_sierra(sierra_account_id, period_yyyymm) WHERE has_trading_activity_export = 1;

CREATE INDEX IF NOT EXISTS idx_sierra_acsil
    ON host_arg_sierra(file_path) WHERE has_acsil_native_module = 1;

CREATE INDEX IF NOT EXISTS idx_sierra_arb
    ON host_arg_sierra(sierra_account_id, period_yyyymm) WHERE has_cross_venue_arb = 1;

CREATE INDEX IF NOT EXISTS idx_sierra_autotrade
    ON host_arg_sierra(file_path) WHERE has_spreadsheet_autotrade = 1;

CREATE INDEX IF NOT EXISTS idx_sierra_hft
    ON host_arg_sierra(dtc_server_host, peak_msg_per_sec) WHERE has_high_message_rate = 1;

CREATE INDEX IF NOT EXISTS idx_sierra_tick_cache
    ON host_arg_sierra(file_path) WHERE has_large_tick_cache = 1;

CREATE INDEX IF NOT EXISTS idx_sierra_cliente
    ON host_arg_sierra(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_sierra_exposure
    ON host_arg_sierra(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_sierra_drift
    ON host_arg_sierra(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_sierra_kind
    ON host_arg_sierra(artifact_kind, account_class);
