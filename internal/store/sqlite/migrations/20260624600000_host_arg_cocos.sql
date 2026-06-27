-- host_arg_cocos inventories Cocos Capital fintech retail-
-- broker artifact files cached on Argentine retail-trader,
-- prop-desk, and quant workstations.
--
-- Cocos Capital (cocos.capital, launched 2022) is Argentina's
-- fastest-growing fintech broker, the first to offer:
--
--   * Easy-FCI subscription via mobile (one-tap)
--   * Cocos Pay USDT stablecoin (CNV Resol. 994 PSAV)
--   * Equity (BYMA) + bond (AL30/GD30) trading
--   * Credit-card linkage for instant cash-to-fund
--   * BCRA Com. A 7916 dollar-MEP/CCL flow
--
-- Cocos is mobile-first but ships a desktop app + REST API
-- (api.cocos.capital) with OAuth2 bearer tokens. The Python
-- ecosystem includes the `cocos-api` wrapper. Argentine
-- retail algotraders bridge to Cocos for retail-equity +
-- USDT arbitrage strategies.
--
-- Workstation cache footprint:
--
--   ~/.cocos/credentials.json              bearer + refresh
--   ~/.cocos/cache/portfolio_<dt>.json     portfolio snap
--   ~/.cocos/cache/orders_<dt>.json        recent orders
--   ~/.cocos/cache/marketdata_<dt>.json    md snap
--   ~/.cocos/cache/fci_subscriptions.json  FCI subs
--   ~/.cocos/cache/usdt_trades.json        USDT pay log
--   ~/Documents/Cocos/exports/*.csv        account exports
--   ~/Documents/Cocos/bienes_personales_<yr>.xlsx tax
--   *.py importing cocos_api / pycocos     strategy script
--   %APPDATA%\Cocos\config.json            desktop config
--
-- **The Cocos fintech-broker layer.** Distinct from:
--   - iter 151 winargiolinvertironline IOL retail REST
--   - iter 141 winargpyhomebroker      pyhomebroker scrape
--   - iter 140 winargcrypto            crypto-PSAV exchanges
--   - iter 137 winargbyma              BYMA equity terminal
--
-- Cocos-specific risk signals:
--   * USDT trading > 10 M ARS = "stablecoin dollar"
--     arbitrage scrutiny (BCRA Com. A 7916, AFIP RG 5193,
--     CNV Resol. 994 PSAV).
--   * MEP/CCL paired bond patterns = forex-arbitrage signal.
--   * Bearer token leak → full account-flow + Cocos Pay
--     USDT impersonation.
--   * One-tap FCI subscription cache = mass-onboarding +
--     possible category-mismatch (cliente perfil-inversor).
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes
--   CNV RG 622       Operativa
--   CNV Resol. 994/2024 PSAV (Cocos Pay USDT)
--   BCRA Com. A 7916 operaciones cambiarias (MEP/CCL)
--   AFIP RG 5193     declaración tributaria cripto + valores
--   UIF Resol. 49/2024 KYC + ROS crypto
--   Ley 25.326       protección datos personales
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials (bearer / refresh)
--   T1078    Valid Accounts (compromised retail account)
--   CWE-200, CWE-359, CWE-532, CWE-798
--   Ley 25.326 (cliente CUIT + cuenta)
--
-- Headline finding shapes:
--   has_bearer_token            — credentials.json access_token.
--   has_refresh_token           — credentials.json refresh_token.
--   has_username_password       — user+pass in cfg / .py.
--   has_2fa_token               — TOTP / 2FA secret persisted.
--   has_usdt_activity           — USDT trade log entries.
--   has_high_volume_usdt        — USDT volume > 10 M ARS.
--   has_mep_ccl_arbitrage       — paired AL30/AL30D etc.
--   is_high_frequency_polling   — > 60 polls/min.
--   has_strategy_script         — .py imports cocos_api.
--   has_cliente_cuit            — cliente CUIT detected.
--   is_credential_exposure_risk — readable file +
--                              (bearer OR refresh OR creds OR
--                              cliente CUIT).
--
-- Bearer + refresh tokens NEVER persisted; only SHA-256 hash
-- of token fragment retained. Cliente CUITs reduced to
-- entity-prefix + last 4 digits.

CREATE TABLE IF NOT EXISTS host_arg_cocos (
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
            'cocos-credentials','cocos-portfolio-cache',
            'cocos-orders-cache','cocos-marketdata-cache',
            'cocos-fci-subscriptions','cocos-usdt-trade-log',
            'cocos-account-export','cocos-strategy-script',
            'cocos-tax-report','cocos-config',
            'cocos-indexeddb','cocos-installer',
            'other','unknown'
        )),
    environment                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (environment IN (
            'production','sandbox','other','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    bearer_token_hash           TEXT    NOT NULL DEFAULT '',
    refresh_token_hash          TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    order_count                 INTEGER NOT NULL DEFAULT 0,
    polls_per_minute_max        INTEGER NOT NULL DEFAULT 0,
    portfolio_position_count    INTEGER NOT NULL DEFAULT 0,
    max_position_ars_cents      INTEGER NOT NULL DEFAULT 0,
    usdt_volume_ars_cents       INTEGER NOT NULL DEFAULT 0,
    fci_subscription_count      INTEGER NOT NULL DEFAULT 0,
    session_first_seen          TEXT    NOT NULL DEFAULT '',
    session_last_seen           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_bearer_token            INTEGER NOT NULL DEFAULT 0 CHECK (has_bearer_token IN (0,1)),
    has_refresh_token           INTEGER NOT NULL DEFAULT 0 CHECK (has_refresh_token IN (0,1)),
    has_username_password       INTEGER NOT NULL DEFAULT 0 CHECK (has_username_password IN (0,1)),
    has_2fa_token               INTEGER NOT NULL DEFAULT 0 CHECK (has_2fa_token IN (0,1)),
    has_usdt_activity           INTEGER NOT NULL DEFAULT 0 CHECK (has_usdt_activity IN (0,1)),
    has_high_volume_usdt        INTEGER NOT NULL DEFAULT 0 CHECK (has_high_volume_usdt IN (0,1)),
    has_mep_ccl_arbitrage       INTEGER NOT NULL DEFAULT 0 CHECK (has_mep_ccl_arbitrage IN (0,1)),
    is_high_frequency_polling   INTEGER NOT NULL DEFAULT 0 CHECK (is_high_frequency_polling IN (0,1)),
    has_strategy_script         INTEGER NOT NULL DEFAULT 0 CHECK (has_strategy_script IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_cocos_bearer
    ON host_arg_cocos(file_path) WHERE has_bearer_token = 1;

CREATE INDEX IF NOT EXISTS idx_cocos_refresh
    ON host_arg_cocos(file_path) WHERE has_refresh_token = 1;

CREATE INDEX IF NOT EXISTS idx_cocos_creds
    ON host_arg_cocos(file_path) WHERE has_username_password = 1;

CREATE INDEX IF NOT EXISTS idx_cocos_2fa
    ON host_arg_cocos(file_path) WHERE has_2fa_token = 1;

CREATE INDEX IF NOT EXISTS idx_cocos_usdt_high
    ON host_arg_cocos(period_yyyymm) WHERE has_high_volume_usdt = 1;

CREATE INDEX IF NOT EXISTS idx_cocos_mep_ccl
    ON host_arg_cocos(period_yyyymm) WHERE has_mep_ccl_arbitrage = 1;

CREATE INDEX IF NOT EXISTS idx_cocos_hfp
    ON host_arg_cocos(period_yyyymm) WHERE is_high_frequency_polling = 1;

CREATE INDEX IF NOT EXISTS idx_cocos_strategy
    ON host_arg_cocos(file_path) WHERE has_strategy_script = 1;

CREATE INDEX IF NOT EXISTS idx_cocos_cliente
    ON host_arg_cocos(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_cocos_exposure
    ON host_arg_cocos(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_cocos_drift
    ON host_arg_cocos(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_cocos_kind
    ON host_arg_cocos(artifact_kind, environment);
