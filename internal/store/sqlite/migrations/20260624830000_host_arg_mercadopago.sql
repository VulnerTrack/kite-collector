-- host_arg_mercadopago inventories MercadoPago Inversiones
-- artifact files cached on Argentine consumer, merchant,
-- developer (Python / JS SDK integrator), and ALYC compliance-
-- officer workstations.
--
-- MercadoPago Inversiones is the MercadoLibre (MELI) regulated
-- subsidiary that operates as an **ALYC bajo CNV RG 731**
-- (Agente de Liquidación y Compensación Integral). It is the
-- largest AR retail broker by user count (>40 M MercadoPago
-- account holders, of which a large fraction has Inversiones
-- enabled).
--
-- MercadoPago Inversiones distinctive surfaces:
--
--   - Rendimientos             FCI money-market (Mercado Fondo,
--                              Mercado Fondo Plus, Galicia FF).
--   - Inversiones              BYMA equity (acciones) + AR bonds.
--   - CEDEARs                  foreign equity via local listing.
--   - Marketplace auto-invest  merchant Rendimientos auto-fund.
--   - MercadoPago Python SDK   `mercadopago` PyPI package.
--   - REST API + OAuth2        access / refresh tokens.
--   - Webhooks                 payment / order events.
--   - DEBIN / Echeq integration ARS rail.
--
-- **The MELI ALYC fintech layer.** Distinct from:
--
--   - iter 154 winargbalanz       — Balanz Capital ALYC.
--   - iter 163 winargppi          — PPI (Banco Galicia) ALYC.
--   - iter 152 winargcocoscapital — Cocos Capital ALYC.
--   - iter 151 winargiolinvertironline — IOL ALYC.
--   - iter 164 winargallaria      — Allaria Ledesma ALYC.
--   - iter 155 winarghomebroker   — Decsis HomeBroker white-label.
--
-- Workstation cache footprint (typical):
--
--   %USERPROFILE%\.mercadopago\config.json    SDK cfg
--   %USERPROFILE%\.mercadopago\token.json     OAuth tokens
--   ./mercadopago_credentials.env             env tokens
--   ./mp_sdk_config.json                      SDK init cfg
--   ./mp_webhook_handler.py                   webhook code
--   ./mp_rendimientos_<dt>.csv                FCI positions
--   ./mp_inversiones_<dt>.csv                 equity positions
--   ./mp_marketplace_autoinvest.json          merchant cfg
--   ./mp_audit_<dt>.log                       audit ops
--   ~/Library/Application Support/MercadoPago/
--   ~/.config/mercadopago/
--
-- MercadoPago-specific risk signals:
--
--   * Cleartext password / `MP_CLIENT_SECRET` in .env =
--     T1552 + CNV RG 1023.
--   * OAuth2 `access_token` leak = full broker-API account
--     compromise (T1078, MELI API scope = `read | write |
--     offline_access`).
--   * OAuth2 `refresh_token` leak = persistent compromise
--     (refresh tokens survive access-token rotation).
--   * mp_rendimientos export = cliente FCI balances roster
--     (CNV RG 622 art. 19 perfil del inversor + Ley 25.326
--     PII; Ley 26.831 art. 117 secreto bursátil).
--   * mp_inversiones export = cliente BYMA equity positions
--     (AFIP RG 5193 + Bienes Personales aggregator).
--   * Marketplace Rendimientos auto-invest = merchant cash
--     management surface (BCRA Com. A 7916 if USD inflow).
--   * Webhook secret leak = order/payment-event spoofing
--     (CNV RG 1023 integrity loss).
--   * High-balance position > USD 50 K = AFIP RG 5193
--     trigger + UIF Resol. 30 PEP screening.
--   * Cliente CUIT export = full client roster (PII bundle
--     if name + DNI also present).
--   * MP SDK access token with > 1 year TTL = elevated
--     privilege persistence (T1098).
--
-- Regulatory base:
--
--   Ley 26.831       Mercado de Capitales
--   Ley 25.246       PLA/FT
--   Ley 25.326       Protección de Datos Personales
--   CNV RG 622       Régimen General
--   CNV RG 622 art.19 Perfil del Inversor
--   CNV RG 622 art.50 Operativa con divisas
--   CNV RG 731       Régimen de Agentes (ALYC)
--   CNV RG 1023      Ciberresiliencia
--   BCRA Com. A 7724 Régimen Informativo PSP
--   BCRA Com. A 7916 Operaciones cambiarias
--   BCRA Com. A 8005 Ciberseguridad financiera
--   AFIP RG 5193     Securities tax reporting
--   AFIP RG 5527     Crypto reporting
--   UIF Resol. 30    PEP / AML KYC
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials (.env)
--   T1078    Valid Accounts (OAuth2)
--   T1098    Account Manipulation (long-lived tokens)
--   T1530    Data from Cloud Storage Object
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config       — .env / cfg cleartext.
--   has_oauth_access_token       — MP OAuth bearer leak.
--   has_oauth_refresh_token      — MP refresh token leak.
--   has_sdk_credentials          — Python/JS SDK creds.
--   has_rendimientos_export      — FCI positions export.
--   has_inversiones_export       — BYMA equity export.
--   has_high_balance             — > USD 50 K position.
--   has_marketplace_autoinvest   — Rendimientos auto-invest.
--   has_webhook_secret           — webhook signing key.
--   has_audit_log                — audit operations log.
--   has_cliente_cuit             — cliente CUIT detected.
--   has_cliente_dni              — cliente DNI detected.
--   has_pii_bundle               — ≥2 of (DNI, CUIT, name).
--   is_credential_exposure_risk  — readable + (password OR
--                                  OAuth token OR webhook
--                                  secret OR rendimientos
--                                  export OR inversiones
--                                  export OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_mercadopago (
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
            'mp-config','mp-credentials',
            'mp-sdk-script','mp-webhook-config',
            'mp-rendimientos-export','mp-inversiones-export',
            'mp-trade-log','mp-marketplace-config',
            'mp-audit-log','mp-installer',
            'other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'consumer','merchant','developer',
            'compliance-officer','api','demo',
            'other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'rendimientos-fci','inversiones-equity',
            'inversiones-bonds','inversiones-cedears',
            'multi-product','other','unknown'
        )),
    mp_user_id                  TEXT    NOT NULL DEFAULT '',
    mp_app_id                   TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    cliente_dni_hash            TEXT    NOT NULL DEFAULT '',
    access_token_hash           TEXT    NOT NULL DEFAULT '',
    refresh_token_hash          TEXT    NOT NULL DEFAULT '',
    webhook_secret_hash         TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_tickers_count      INTEGER NOT NULL DEFAULT 0,
    cuenta_count                INTEGER NOT NULL DEFAULT 0,
    balance_usd_cents           INTEGER NOT NULL DEFAULT 0,
    pii_signal_count            INTEGER NOT NULL DEFAULT 0,
    rendimientos_record_count   INTEGER NOT NULL DEFAULT 0,
    inversiones_record_count    INTEGER NOT NULL DEFAULT 0,
    audit_event_count           INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_oauth_access_token      INTEGER NOT NULL DEFAULT 0 CHECK (has_oauth_access_token IN (0,1)),
    has_oauth_refresh_token     INTEGER NOT NULL DEFAULT 0 CHECK (has_oauth_refresh_token IN (0,1)),
    has_sdk_credentials         INTEGER NOT NULL DEFAULT 0 CHECK (has_sdk_credentials IN (0,1)),
    has_rendimientos_export     INTEGER NOT NULL DEFAULT 0 CHECK (has_rendimientos_export IN (0,1)),
    has_inversiones_export      INTEGER NOT NULL DEFAULT 0 CHECK (has_inversiones_export IN (0,1)),
    has_high_balance            INTEGER NOT NULL DEFAULT 0 CHECK (has_high_balance IN (0,1)),
    has_marketplace_autoinvest  INTEGER NOT NULL DEFAULT 0 CHECK (has_marketplace_autoinvest IN (0,1)),
    has_webhook_secret          INTEGER NOT NULL DEFAULT 0 CHECK (has_webhook_secret IN (0,1)),
    has_audit_log               INTEGER NOT NULL DEFAULT 0 CHECK (has_audit_log IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    has_cliente_dni             INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_dni IN (0,1)),
    has_pii_bundle              INTEGER NOT NULL DEFAULT 0 CHECK (has_pii_bundle IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_mp_password
    ON host_arg_mercadopago(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_mp_access_token
    ON host_arg_mercadopago(file_path) WHERE has_oauth_access_token = 1;

CREATE INDEX IF NOT EXISTS idx_mp_refresh_token
    ON host_arg_mercadopago(file_path) WHERE has_oauth_refresh_token = 1;

CREATE INDEX IF NOT EXISTS idx_mp_sdk_creds
    ON host_arg_mercadopago(mp_app_id, period_yyyymm) WHERE has_sdk_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_mp_rendimientos
    ON host_arg_mercadopago(mp_user_id, period_yyyymm) WHERE has_rendimientos_export = 1;

CREATE INDEX IF NOT EXISTS idx_mp_inversiones
    ON host_arg_mercadopago(mp_user_id, period_yyyymm) WHERE has_inversiones_export = 1;

CREATE INDEX IF NOT EXISTS idx_mp_high_balance
    ON host_arg_mercadopago(mp_user_id, balance_usd_cents) WHERE has_high_balance = 1;

CREATE INDEX IF NOT EXISTS idx_mp_autoinvest
    ON host_arg_mercadopago(mp_user_id, period_yyyymm) WHERE has_marketplace_autoinvest = 1;

CREATE INDEX IF NOT EXISTS idx_mp_webhook
    ON host_arg_mercadopago(mp_app_id) WHERE has_webhook_secret = 1;

CREATE INDEX IF NOT EXISTS idx_mp_audit
    ON host_arg_mercadopago(mp_user_id, period_yyyymm) WHERE has_audit_log = 1;

CREATE INDEX IF NOT EXISTS idx_mp_pii
    ON host_arg_mercadopago(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_pii_bundle = 1;

CREATE INDEX IF NOT EXISTS idx_mp_exposure
    ON host_arg_mercadopago(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_mp_drift
    ON host_arg_mercadopago(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_mp_kind
    ON host_arg_mercadopago(artifact_kind, account_class);
