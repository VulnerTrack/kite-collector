-- host_arg_bookmap inventories Bookmap artifact files cached
-- on Argentine HFT, scalper, prop-trader, and order-flow-
-- research workstations.
--
-- Bookmap is a pro-grade desktop **order-book heatmap
-- visualization** platform with three distinguishing surfaces:
--
--   1. L3 order-book heatmap (full price-by-price depth).
--   2. Speed of Tape analytics (cluster / iceberg / spoof
--      detection).
--   3. BTR (Bookmap Recording) — full order-book replay
--      capture stored as binary files (often multi-GB).
--
-- Bookmap integrates with futures (Rithmic, CQG, TT, IB),
-- crypto (Kraken, Binance, Bitfinex), and equities (DAS, IB).
-- It also has the **Bookmap Marketplace** for third-party
-- Java-SDK indicators (.indicator).
--
-- **The Bookmap L3 order-book heatmap layer.** Distinct from:
--
--   - iter 167 winargcqg          — CQG vendor terminal.
--   - iter 169 winargtt           — TT vendor terminal.
--   - iter 170 winargsierra       — Sierra Chart (DTC).
--   - iter 172 winargmulticharts  — MultiCharts.
--   - iter 173 winargtradestation — TradeStation.
--   - iter 176 winargkdb          — KDB+ (tick DB).
--   - iter 179 winargquantower    — Quantower multi-asset.
--   - iter 180 winargmotivewave   — MotiveWave Elliott Wave.
--
-- Workstation cache footprint (typical):
--
--   C:\Program Files\Bookmap\              install root
--   ~/Bookmap/                             user data
--   ~/Bookmap/workspaces/<name>.bookmap    workspace
--   ~/Bookmap/recordings/<dt>.btr          BTR recording
--   ~/Bookmap/indicators/<name>.indicator  Java indicator SDK
--   ~/Bookmap/connections/<broker>.cfg     plug-in cfg
--   ~/Bookmap/marketplace/<plugin>.jar     marketplace plug
--   ~/Bookmap/logs/<dt>.log                session log
--   ~/Bookmap/api_token.json               API token cache
--
-- Bookmap-specific risk signals:
--
--   * Cleartext password / API key in connection cfg =
--     T1552 + CNV RG 1023.
--   * Broker plug-in credentials (Rithmic R | API user, CQG
--     Continuum FIX, Binance HMAC secret) = T1078 across
--     multi-broker surface.
--   * BTR recording > 5 GB = L3 order-book redistribution
--     concern (CME / BYMA / NYSE L3 license; some venues
--     forbid persistent L3 storage altogether).
--   * Per-recording symbol = single-instrument capture
--     (potentially evidence in market-manipulation case if
--     adversary recorded their own activity).
--   * MBO (Market By Order) subscription = $5K+/month CME
--     premium feed (license verification target).
--   * .indicator (Java SDK) = arbitrary code on workstation
--     (supply-chain CWE-829 if from Marketplace).
--   * Marketplace plug-in .jar from third-party vendor =
--     same supply-chain concern.
--   * Speed of Tape analytics cfg with iceberg detection +
--     auto-trade = HFT execution layer (CNV RG 622 art. 23).
--   * MATba-Rofex routing via IB plug-in = AR futures
--     surface (rare combo via Bookmap).
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
--   AFIP RG 5527     Crypto reporting
--   Ley 25.326       Datos Personales
--   CME L3 license   Market Data Subscriber Agreement
--   NYSE Open Book   L3 redistribution
--   BYMA Reglamento Operativo cap. VII (datos)
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1218    System Binary Proxy Execution (Java indicator)
--   T1078    Valid Accounts
--   CWE-200, CWE-359, CWE-532, CWE-798, CWE-829
--
-- Headline finding shapes:
--
--   has_password_in_config         — cfg cleartext.
--   has_broker_plugin_credentials  — plug-in cred leak.
--   has_btr_recording              — Bookmap order-book replay.
--   has_large_btr_recording        — BTR > 5 GiB (license).
--   has_indicator_sdk              — Bookmap Java indicator.
--   has_marketplace_plugin         — third-party .jar plug.
--   has_mbo_subscription           — Market-By-Order feed.
--   has_l3_orderbook_data          — L3 depth captured.
--   has_speed_of_tape_armed        — speed-of-tape auto-trade.
--   has_matba_rofex_routing        — MATba symbol via IB.
--   has_cme_futures                — CME futures symbol.
--   has_crypto_data                — crypto symbol.
--   has_cross_venue_arb            — multi-venue tables.
--   has_high_message_rate          — > 1000 msg/s.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable + (password OR
--                                    plug-in cred OR cliente
--                                    CUIT OR BTR recording).

CREATE TABLE IF NOT EXISTS host_arg_bookmap (
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
            'bookmap-config','bookmap-credentials',
            'bookmap-workspace','bookmap-btr-recording',
            'bookmap-indicator-sdk','bookmap-marketplace-plugin',
            'bookmap-connection-config','bookmap-session-log',
            'bookmap-mbo-cache','bookmap-installer',
            'other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'hft','scalper','prop-trader',
            'order-flow-researcher','algotrader',
            'api','demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'cme-futures','matba-rofex','us-equity',
            'crypto','multi-venue',
            'hft-execution','other','unknown'
        )),
    broker_plugin               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (broker_plugin IN (
            '','ib','rithmic','cqg','tt','das',
            'kraken','binance','bitfinex',
            'custom','none','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    bookmap_account_id          TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    btr_recording_bytes         INTEGER NOT NULL DEFAULT 0,
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    matba_symbols_count         INTEGER NOT NULL DEFAULT 0,
    cme_symbols_count           INTEGER NOT NULL DEFAULT 0,
    crypto_symbols_count        INTEGER NOT NULL DEFAULT 0,
    peak_msg_per_sec            INTEGER NOT NULL DEFAULT 0,
    indicator_count             INTEGER NOT NULL DEFAULT 0,
    marketplace_plugin_count    INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_broker_plugin_credentials INTEGER NOT NULL DEFAULT 0 CHECK (has_broker_plugin_credentials IN (0,1)),
    has_btr_recording           INTEGER NOT NULL DEFAULT 0 CHECK (has_btr_recording IN (0,1)),
    has_large_btr_recording     INTEGER NOT NULL DEFAULT 0 CHECK (has_large_btr_recording IN (0,1)),
    has_indicator_sdk           INTEGER NOT NULL DEFAULT 0 CHECK (has_indicator_sdk IN (0,1)),
    has_marketplace_plugin      INTEGER NOT NULL DEFAULT 0 CHECK (has_marketplace_plugin IN (0,1)),
    has_mbo_subscription        INTEGER NOT NULL DEFAULT 0 CHECK (has_mbo_subscription IN (0,1)),
    has_l3_orderbook_data       INTEGER NOT NULL DEFAULT 0 CHECK (has_l3_orderbook_data IN (0,1)),
    has_speed_of_tape_armed     INTEGER NOT NULL DEFAULT 0 CHECK (has_speed_of_tape_armed IN (0,1)),
    has_matba_rofex_routing     INTEGER NOT NULL DEFAULT 0 CHECK (has_matba_rofex_routing IN (0,1)),
    has_cme_futures             INTEGER NOT NULL DEFAULT 0 CHECK (has_cme_futures IN (0,1)),
    has_crypto_data             INTEGER NOT NULL DEFAULT 0 CHECK (has_crypto_data IN (0,1)),
    has_cross_venue_arb         INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_venue_arb IN (0,1)),
    has_high_message_rate       INTEGER NOT NULL DEFAULT 0 CHECK (has_high_message_rate IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_bookmap_password
    ON host_arg_bookmap(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_bookmap_plugin_creds
    ON host_arg_bookmap(broker_plugin, period_yyyymm) WHERE has_broker_plugin_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_bookmap_btr
    ON host_arg_bookmap(file_path, btr_recording_bytes) WHERE has_btr_recording = 1;

CREATE INDEX IF NOT EXISTS idx_bookmap_large_btr
    ON host_arg_bookmap(file_path, btr_recording_bytes) WHERE has_large_btr_recording = 1;

CREATE INDEX IF NOT EXISTS idx_bookmap_indicator
    ON host_arg_bookmap(file_path) WHERE has_indicator_sdk = 1;

CREATE INDEX IF NOT EXISTS idx_bookmap_marketplace
    ON host_arg_bookmap(file_path) WHERE has_marketplace_plugin = 1;

CREATE INDEX IF NOT EXISTS idx_bookmap_mbo
    ON host_arg_bookmap(broker_plugin) WHERE has_mbo_subscription = 1;

CREATE INDEX IF NOT EXISTS idx_bookmap_l3
    ON host_arg_bookmap(broker_plugin) WHERE has_l3_orderbook_data = 1;

CREATE INDEX IF NOT EXISTS idx_bookmap_sot
    ON host_arg_bookmap(file_path) WHERE has_speed_of_tape_armed = 1;

CREATE INDEX IF NOT EXISTS idx_bookmap_arb
    ON host_arg_bookmap(bookmap_account_id, period_yyyymm) WHERE has_cross_venue_arb = 1;

CREATE INDEX IF NOT EXISTS idx_bookmap_hft
    ON host_arg_bookmap(broker_plugin, peak_msg_per_sec) WHERE has_high_message_rate = 1;

CREATE INDEX IF NOT EXISTS idx_bookmap_cliente
    ON host_arg_bookmap(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_bookmap_exposure
    ON host_arg_bookmap(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_bookmap_drift
    ON host_arg_bookmap(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_bookmap_kind
    ON host_arg_bookmap(artifact_kind, account_class);
