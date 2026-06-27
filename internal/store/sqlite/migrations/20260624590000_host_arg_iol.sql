-- host_arg_iol inventories IOL InvertirOnline retail-broker
-- artifact files cached on Argentine retail-trader, prop-desk,
-- and quant workstations.
--
-- IOL InvertirOnline (invertironline.com, founded 2000) is
-- Argentina's dominant retail brokerage with ~50% market
-- share by client count. It runs:
--
--   api.invertironline.com   REST API (OAuth bearer tokens)
--   ws.invertironline.com    WebSocket market data
--   IOL Trade (desktop)      Windows .NET trader terminal
--   IOL Mobile (iOS/Android) mobile app
--
-- The dominant Python wrapper is `pyiol` (and `iol-api`).
-- Argentine retail algotraders bridge to IOL for equity (BYMA)
-- trading, FCI subscription, MEP/CCL dollar arbitrage, and
-- caución bursátil.
--
-- Workstation cache footprint:
--
--   ~/.iol/credentials.json                bearer + refresh
--   ~/.iol/cache/portfolio_<dt>.json       portfolio snap
--   ~/.iol/cache/orders_<dt>.json          recent orders
--   ~/.iol/cache/marketdata_<dt>.json      md snap
--   ~/Documents/IOL/exports/*.csv          account exports
--   ~/Documents/IOL/Bienes_Personales_<yr>.xlsx tax report
--   *.py importing pyiol                   strategy script
--   %APPDATA%\IOL Trade\config.xml         desktop config
--
-- **The IOL retail-broker layer.** Distinct from:
--   - iter 141 winargpyhomebroker pyhomebroker portal-scrape
--                                 (Cohen/BullMarket/Allaria/
--                                  Adcap/EcoValores/IOL-legacy)
--   - iter 139 winargprimary      Primary REST/WS (ROFEX)
--   - iter 137 winargbyma         BYMA equity terminal
--
-- IOL-specific risk signals matter for:
--   * Bearer token leak → full account-flow impersonation
--     across REST + WS + mobile.
--   * Refresh token leak → persistent long-lived access.
--   * MEP/CCL paired-bond patterns in orders cache → Com. A
--     7916 forex arbitrage scrutiny.
--   * High-frequency polling (> 60 req/min) violates IOL ToS
--     and can trigger account lock.
--   * Strategy script with hardcoded password/secret in .py.
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes
--   CNV RG 622       Operativa
--   BCRA Com. A 7916 operaciones cambiarias (MEP/CCL)
--   AFIP RG 5193     declaración tributaria cripto + valores
--   Ley 25.326       protección datos personales
--   IOL ToS          api rate limits + scraping prohibition
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials (bearer / refresh)
--   T1539    Steal Web Session Cookie (cookie jar)
--   T1078    Valid Accounts (compromised retail account)
--   CWE-200, CWE-359, CWE-532, CWE-798
--   Ley 25.326 (cliente CUIT + cuenta-comitente)
--
-- Headline finding shapes:
--   has_bearer_token         — credentials.json access_token.
--   has_refresh_token        — credentials.json refresh_token.
--   has_username_password    — username + password in cfg/.py.
--   has_2fa_token            — TOTP / 2FA secret persisted.
--   has_mep_ccl_arbitrage    — paired AL30/AL30D in orders
--                              cache.
--   is_high_frequency_polling — orders cache > 60 polls/min.
--   has_strategy_script      — .py imports pyiol / iol-api.
--   has_cliente_cuit         — cliente CUIT detected.
--   is_credential_exposure_risk — readable file +
--                              (bearer OR refresh OR creds OR
--                              cliente CUIT).
--
-- Bearer + refresh tokens NEVER persisted; only SHA-256 hash
-- of token fragment retained. Cliente CUITs reduced to
-- entity-prefix + last 4 digits.

CREATE TABLE IF NOT EXISTS host_arg_iol (
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
            'iol-credentials-json','iol-portfolio-cache',
            'iol-orders-cache','iol-marketdata-cache',
            'iol-account-export','iol-strategy-script',
            'iol-tax-report','iol-config',
            'iol-installer','other','unknown'
        )),
    environment                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (environment IN (
            'production','sandbox','other','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    cuenta_comitente_suffix4    TEXT    NOT NULL DEFAULT '',
    bearer_token_hash           TEXT    NOT NULL DEFAULT '',
    refresh_token_hash          TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    order_count                 INTEGER NOT NULL DEFAULT 0,
    polls_per_minute_max        INTEGER NOT NULL DEFAULT 0,
    portfolio_position_count    INTEGER NOT NULL DEFAULT 0,
    max_position_ars_cents      INTEGER NOT NULL DEFAULT 0,
    session_first_seen          TEXT    NOT NULL DEFAULT '',
    session_last_seen           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_bearer_token            INTEGER NOT NULL DEFAULT 0 CHECK (has_bearer_token IN (0,1)),
    has_refresh_token           INTEGER NOT NULL DEFAULT 0 CHECK (has_refresh_token IN (0,1)),
    has_username_password       INTEGER NOT NULL DEFAULT 0 CHECK (has_username_password IN (0,1)),
    has_2fa_token               INTEGER NOT NULL DEFAULT 0 CHECK (has_2fa_token IN (0,1)),
    has_mep_ccl_arbitrage       INTEGER NOT NULL DEFAULT 0 CHECK (has_mep_ccl_arbitrage IN (0,1)),
    is_high_frequency_polling   INTEGER NOT NULL DEFAULT 0 CHECK (is_high_frequency_polling IN (0,1)),
    has_strategy_script         INTEGER NOT NULL DEFAULT 0 CHECK (has_strategy_script IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_iol_bearer
    ON host_arg_iol(file_path) WHERE has_bearer_token = 1;

CREATE INDEX IF NOT EXISTS idx_iol_refresh
    ON host_arg_iol(file_path) WHERE has_refresh_token = 1;

CREATE INDEX IF NOT EXISTS idx_iol_creds
    ON host_arg_iol(file_path) WHERE has_username_password = 1;

CREATE INDEX IF NOT EXISTS idx_iol_2fa
    ON host_arg_iol(file_path) WHERE has_2fa_token = 1;

CREATE INDEX IF NOT EXISTS idx_iol_mep_ccl
    ON host_arg_iol(period_yyyymm) WHERE has_mep_ccl_arbitrage = 1;

CREATE INDEX IF NOT EXISTS idx_iol_hfp
    ON host_arg_iol(period_yyyymm) WHERE is_high_frequency_polling = 1;

CREATE INDEX IF NOT EXISTS idx_iol_strategy
    ON host_arg_iol(file_path) WHERE has_strategy_script = 1;

CREATE INDEX IF NOT EXISTS idx_iol_cliente
    ON host_arg_iol(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_iol_exposure
    ON host_arg_iol(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_iol_drift
    ON host_arg_iol(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_iol_kind
    ON host_arg_iol(artifact_kind, environment);
