-- host_arg_tradingview inventories TradingView Desktop +
-- Pine Script algotrading files cached on Argentine retail-
-- trader and prop-desk workstations.
--
-- TradingView (tradingview.com) is the dominant web-based
-- charting + algotrading platform. The Desktop app (Electron)
-- caches local copies of Pine Script source, strategy alerts,
-- webhook configs (used to bridge TradingView signals to
-- broker APIs), watchlists, chart layouts, and linked broker
-- accounts (via the TradingView Brokers Network).
--
-- Pine Script v6 (2024) added full algotrading via webhook
-- integrations. Argentine retail algotraders rely on:
--
--   Pine `strategy()` functions          backtesting engine
--   Pine alerts with webhook JSON        live signal dispatch
--   Linked broker accounts               trade execution
--
-- Workstation cache footprint:
--
--   %APPDATA%\TradingView Desktop\User Data\
--   ~/.config/tradingview/
--   ~/.tradingview-desktop/
--   ~/Library/Application Support/TradingView/
--      Local Storage\, IndexedDB\
--      Cache\, Code Cache\
--      Preferences (JSON)
--   ~/Documents/TradingView\
--      <strategy>.pine                   Pine source
--      <strategy>_alert.json             alert config
--      <strategy>_webhook.json           webhook → broker
--      watchlist_<n>.csv                 watchlist export
--      chart_layout_<n>.json             saved layout
--
-- **The TradingView desktop + Pine layer.** Distinct from:
--   - iter 108 winalgotrading  — generic EA cover
--   - iter 143 winargmt        — MetaTrader 4/5
--   - iter 148 winargninjatrader NinjaTrader 8 futures
--   - iter 139 winargprimary   — Primary REST/WS
--
-- TradingView-specific risk signals:
--   * `strategy(...)` Pine function = algorithmic IP exposure.
--   * Webhook config with bearer token / api_key = automatic
--     broker-impersonation surface.
--   * Linked broker account in live mode = real-money signal
--     dispatch.
--   * Argentine ticker in Pine strategy = local-market focus
--     (broker-dealer / prop-desk affiliation marker).
--   * API key inside .pine comment / variable = T1552.
--
-- Regulatory base:
--   AFIP Bienes Personales (offshore broker account)
--   BCRA Com. A 7916        operaciones cambiarias
--   CNV RG 731              Régimen de Agentes
--   CNV RG 622              Operativa
--   Ley 25.326              protección datos personales
--   TradingView ToS         api-key / webhook usage
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials (webhook key)
--   T1078    Valid Accounts (broker link)
--   T1567    Exfiltration over Web Service (webhook payload)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_pine_strategy            — `strategy(...)` in .pine.
--   has_webhook_with_secret      — webhook config carries
--                                  bearer / api_key / secret.
--   has_broker_linked_live       — linked broker is live.
--   has_alert_with_pii           — alert payload has cliente
--                                  CUIT.
--   has_argentine_pine_strategy  — Argentine ticker in .pine.
--   has_api_key_in_pine          — API key in .pine source.
--   is_credential_exposure_risk  — readable file +
--                                  (webhook secret OR pine
--                                  api-key OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_tradingview (
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
            'tv-pine-script','tv-strategy-alert',
            'tv-webhook-config','tv-watchlist',
            'tv-chart-layout','tv-indicator',
            'tv-broker-link','tv-config',
            'tv-cache','tv-installer',
            'other','unknown'
        )),
    linked_broker               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (linked_broker IN (
            'oanda','fxcm','capitalcom','easymarkets',
            'alpaca','forexcom','saxo','tradier',
            'gemini','bitstamp','tradovate','paperonly',
            'webhook-other','other','unknown'
        )),
    pine_version                TEXT    NOT NULL DEFAULT ''
        CHECK (pine_version IN ('','v3','v4','v5','v6','other')),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    webhook_url_hash            TEXT    NOT NULL DEFAULT '',
    strategy_name               TEXT    NOT NULL DEFAULT '',
    argentine_ticker_count      INTEGER NOT NULL DEFAULT 0,
    alert_count                 INTEGER NOT NULL DEFAULT 0,
    watchlist_ticker_count      INTEGER NOT NULL DEFAULT 0,
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_pine_strategy           INTEGER NOT NULL DEFAULT 0 CHECK (has_pine_strategy IN (0,1)),
    has_webhook_with_secret     INTEGER NOT NULL DEFAULT 0 CHECK (has_webhook_with_secret IN (0,1)),
    has_broker_linked_live      INTEGER NOT NULL DEFAULT 0 CHECK (has_broker_linked_live IN (0,1)),
    has_alert_with_pii          INTEGER NOT NULL DEFAULT 0 CHECK (has_alert_with_pii IN (0,1)),
    has_argentine_pine_strategy INTEGER NOT NULL DEFAULT 0 CHECK (has_argentine_pine_strategy IN (0,1)),
    has_api_key_in_pine         INTEGER NOT NULL DEFAULT 0 CHECK (has_api_key_in_pine IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_tv_pine
    ON host_arg_tradingview(file_path) WHERE has_pine_strategy = 1;

CREATE INDEX IF NOT EXISTS idx_tv_webhook
    ON host_arg_tradingview(file_path) WHERE has_webhook_with_secret = 1;

CREATE INDEX IF NOT EXISTS idx_tv_live
    ON host_arg_tradingview(linked_broker) WHERE has_broker_linked_live = 1;

CREATE INDEX IF NOT EXISTS idx_tv_pii_alert
    ON host_arg_tradingview(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_alert_with_pii = 1;

CREATE INDEX IF NOT EXISTS idx_tv_arg_pine
    ON host_arg_tradingview(file_path) WHERE has_argentine_pine_strategy = 1;

CREATE INDEX IF NOT EXISTS idx_tv_apikey
    ON host_arg_tradingview(file_path) WHERE has_api_key_in_pine = 1;

CREATE INDEX IF NOT EXISTS idx_tv_cliente
    ON host_arg_tradingview(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_tv_exposure
    ON host_arg_tradingview(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_tv_drift
    ON host_arg_tradingview(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_tv_kind
    ON host_arg_tradingview(artifact_kind, linked_broker);

CREATE INDEX IF NOT EXISTS idx_tv_pine_ver
    ON host_arg_tradingview(pine_version, artifact_kind);
