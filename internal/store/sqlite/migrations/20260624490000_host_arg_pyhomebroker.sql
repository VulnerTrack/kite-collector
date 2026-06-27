-- host_arg_pyhomebroker inventories pyhomebroker Python
-- library files cached on Argentine retail-trader, prop-desk,
-- and quant workstations.
--
-- pyhomebroker (github.com/crapher/pyhomebroker) is the
-- dominant open-source Python library for Argentine retail
-- broker algorithmic access. It does NOT use the official
-- Primary REST/WS API — instead it scrapes the broker's
-- homebroker (web-portal) HTML/JSON over an HTTP session,
-- replaying the same flow a human browser would. Brokers
-- supported:
--
--   Cohen, Bull Market Brokers, Allaria Ledesma, Adcap,
--   Eco Valores, IOL (InvertirOnline) legacy, Proyecciones
--   Bursátiles, Mercado Bursátil, Sense Digital
--
-- Workstation cache footprint:
--
--   ~/.pyhomebroker/config.ini             client config
--   ~/.pyhomebroker/credentials.json       broker username+pwd
--   ~/.pyhomebroker/sessions/<br>_<u>.session cookie jar
--   ~/.pyhomebroker/cache/orders_<dt>.json recent orders
--   ~/.pyhomebroker/cache/portfolio_<dt>.json portfolio snap
--   ~/.pyhomebroker/cache/marketdata_<dt>.json md snap
--   ~/.pyhomebroker/trades_<dt>.log        executed trades
--   *.py / *.ipynb importing pyhomebroker  strategy script
--
-- **The retail-broker portal-scrape layer.** Distinct from:
--   - iter 108 winalgotrading   — generic algotrading
--   - iter 139 winargprimary    — Primary REST/WS (official)
--   - iter 137 winargbyma       — BYMA equity terminal
--   - iter 136 winargsiopel     — SIOPEL/MAE OTC terminal
--
-- Portal-scrape-specific risks:
--   * Session cookie jar leak → full broker-portal hijack
--     (same as stealing the browser session).
--   * Cleartext broker username + password → permanent
--     credential exposure across portal + mobile.
--   * High-frequency polling (> 1 req/sec) violates broker
--     ToS + can trigger account lock.
--   * Strategy script using pyhomebroker = retail-algo IP.
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes (cliente algo trading)
--   CNV RG 622       Operativa de mercado
--   CNV RG 1023      Tecnología y ciberseguridad
--   Ley 25.326       protección datos personales
--   Broker ToS       most prohibit automated scraping
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials (broker creds)
--   T1539    Steal Web Session Cookie (jar leak)
--   T1078    Valid Accounts (impersonation)
--   T1071    Application Layer Protocol (portal scrape)
--   CWE-200, CWE-359, CWE-532
--   CWE-798  (hardcoded credentials in .ini)
--   Ley 25.326 (cliente PII in cache)
--
-- Headline finding shapes:
--   has_cookie_jar           — *.session file with cookies.
--   has_username_password    — credentials.json/cfg with
--                              broker username + password.
--   has_2fa_token            — TOTP / 2FA secret persisted.
--   has_portfolio_export     — cached portfolio snapshot.
--   has_strategy_script      — .py imports pyhomebroker.
--   is_high_frequency_polling — orders cache shows > 60
--                              polls/min based on timestamps.
--   has_cliente_cuit         — cliente CUIT detected.
--   is_credential_exposure_risk — readable file +
--                              (cookies OR creds OR cliente).
--
-- Credentials NEVER persisted. SHA-256 hash of username +
-- session-cookie fingerprint retained. All CUITs reduced to
-- entity prefix + last 4 digits.

CREATE TABLE IF NOT EXISTS host_arg_pyhomebroker (
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
            'pyhomebroker-config','pyhomebroker-credentials',
            'pyhomebroker-session','pyhomebroker-orders-cache',
            'pyhomebroker-portfolio-cache',
            'pyhomebroker-marketdata-cache',
            'pyhomebroker-trade-log',
            'pyhomebroker-strategy-script',
            'pyhomebroker-installer','other','unknown'
        )),
    broker                      TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (broker IN (
            'cohen','bullmarket','allaria','adcap',
            'eco-valores','iol-legacy','proyecciones',
            'mercado-bursatil','sense-digital',
            'other','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    session_cookie_hash         TEXT    NOT NULL DEFAULT '',
    cookie_count                INTEGER NOT NULL DEFAULT 0,
    order_count                 INTEGER NOT NULL DEFAULT 0,
    polls_per_minute_max        INTEGER NOT NULL DEFAULT 0,
    instrument_count            INTEGER NOT NULL DEFAULT 0,
    portfolio_position_count    INTEGER NOT NULL DEFAULT 0,
    max_position_ars_cents      INTEGER NOT NULL DEFAULT 0,
    session_first_seen          TEXT    NOT NULL DEFAULT '',
    session_last_seen           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_cookie_jar              INTEGER NOT NULL DEFAULT 0 CHECK (has_cookie_jar IN (0,1)),
    has_username_password       INTEGER NOT NULL DEFAULT 0 CHECK (has_username_password IN (0,1)),
    has_2fa_token               INTEGER NOT NULL DEFAULT 0 CHECK (has_2fa_token IN (0,1)),
    has_portfolio_export        INTEGER NOT NULL DEFAULT 0 CHECK (has_portfolio_export IN (0,1)),
    has_strategy_script         INTEGER NOT NULL DEFAULT 0 CHECK (has_strategy_script IN (0,1)),
    is_high_frequency_polling   INTEGER NOT NULL DEFAULT 0 CHECK (is_high_frequency_polling IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_phb_cookie
    ON host_arg_pyhomebroker(file_path) WHERE has_cookie_jar = 1;

CREATE INDEX IF NOT EXISTS idx_phb_creds
    ON host_arg_pyhomebroker(file_path) WHERE has_username_password = 1;

CREATE INDEX IF NOT EXISTS idx_phb_2fa
    ON host_arg_pyhomebroker(file_path) WHERE has_2fa_token = 1;

CREATE INDEX IF NOT EXISTS idx_phb_hft
    ON host_arg_pyhomebroker(broker, period_yyyymm) WHERE is_high_frequency_polling = 1;

CREATE INDEX IF NOT EXISTS idx_phb_strategy
    ON host_arg_pyhomebroker(file_path) WHERE has_strategy_script = 1;

CREATE INDEX IF NOT EXISTS idx_phb_cliente
    ON host_arg_pyhomebroker(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_phb_exposure
    ON host_arg_pyhomebroker(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_phb_drift
    ON host_arg_pyhomebroker(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_phb_broker
    ON host_arg_pyhomebroker(broker, artifact_kind);
