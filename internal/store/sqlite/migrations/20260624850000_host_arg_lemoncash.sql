-- host_arg_lemoncash inventories Lemon Cash artifact files
-- cached on Argentine consumer, merchant, developer (SDK
-- integrator), and compliance-officer workstations.
--
-- Lemon Cash (formerly Lemon) is an AR-headquartered crypto
-- wallet + payment app **regulated as a Proveedor de Servicios
-- de Pago (PSP)** under BCRA Comunicación "A" 7724. It is a
-- key AR retail crypto rail with three distinguishing
-- surfaces:
--
--   1. Crypto wallet — BTC, ETH, USDT, USDC, native tokens.
--   2. Lemon Card — Visa crypto-debit card (BCRA Com. A 7916
--      cross-border USD outflow concern + AFIP RG 5527).
--   3. Lemon Earn — yield product (DeFi-style stablecoin
--      yield, regulatorily ambiguous under CNV oversight).
--
-- Additional regulated functionality:
--
--   - USDT / USDC stablecoin rails for AR retail.
--   - DEBIN / Echeq ARS-cash on / off ramp.
--   - Marketplace integration (merchant payments).
--   - REST API + OAuth2 for SDK / partner integrations.
--   - Lemon Marketplace (NFT / digital-asset purchases).
--
-- **The AR crypto-wallet PSP layer.** Distinct from:
--
--   - iter 162 winargccxt         — CCXT library (cross-
--                                   exchange Python SDK).
--   - iter 175 winargmercadopago  — MELI fintech (no crypto).
--   - iter 163 winargppi          — PPI broker (no crypto).
--   - iter 173 winargtradestation — US broker (no AR PSP).
--
-- Workstation cache footprint (typical):
--
--   ~/.lemon/credentials.json            OAuth2 tokens
--   ~/.lemon/api_token                   raw bearer token
--   ./.env                               LEMON_ACCESS_TOKEN
--   ./lemon_sdk_script.py                Python SDK script
--   ./lemon_sdk_script.js                Node.js SDK script
--   ./lemon_trade_log_<dt>.csv           trade-log export
--   ./lemon_earn_positions.csv           yield positions
--   ./lemon_kyc_<dt>.json                cliente KYC dump
--                                        (DNI + name +
--                                        selfie-ref + AML)
--   ./lemon_marketplace_config.json      merchant cfg
--   ./lemon_card_transactions.csv        crypto-card spend
--   ./lemon_arbitrage_strategy.py        USDT/ARS arb logic
--   ~/Library/Application Support/Lemon/
--   %APPDATA%\Lemon\
--
-- Lemon-specific risk signals:
--
--   * Cleartext `LEMON_ACCESS_TOKEN` in .env = T1552 + BCRA
--     Com. A 8005.
--   * OAuth2 access token leak = full wallet drain (T1078,
--     no transaction-level user re-auth on Lemon API).
--   * KYC dump containing DNI + selfie reference + AML
--     screening notes = Ley 25.326 PII (high tier) + Ley
--     25.246 PLA/FT confidentiality.
--   * Crypto-card transaction log carrying merchant + USD
--     amount = BCRA Com. A 7916 outflow target (potential
--     evasion of "dólar tarjeta" via crypto-card rail).
--   * USDT/ARS arbitrage script with brecha-cambiaria logic
--     = BCRA Com. A 7916 + 7918 evasion concern (and CNV
--     RG 622 art. 50 if execution-side).
--   * High balance > USD 10 K = AFIP RG 5527 crypto-reporting
--     trigger + Bienes Personales aggregator.
--   * Lemon Earn yield-position dump = CNV-oversight
--     ambiguity surface (Comunicado CNV-BCRA conjunto
--     2022, depending on revival).
--   * Merchant marketplace cfg with webhook secret = order /
--     payment-event spoofing surface.
--   * Per-row cliente CUIT + DNI export = AML/PEP screening
--     trigger (UIF Resol. 30).
--
-- Regulatory base:
--
--   Ley 21.526        Entidades Financieras (PSP carve-out)
--   Ley 25.246        PLA/FT
--   Ley 25.326        Datos Personales
--   Ley 26.831        Mercado de Capitales (CNV ambig.)
--   BCRA Com. A 7724  Régimen Informativo PSP
--   BCRA Com. A 7916  Operaciones cambiarias
--   BCRA Com. A 7918  Tarjeta no-cripto
--   BCRA Com. A 8005  Ciberseguridad financiera
--   CNV-BCRA          Comunicado conjunto crypto
--   AFIP RG 5193      Securities tax reporting
--   AFIP RG 5527      Crypto / VASP reporting
--   UIF Resol. 30     PEP / AML KYC
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
--   has_password_in_config        — .env / cfg cleartext.
--   has_oauth_access_token        — Lemon OAuth bearer leak.
--   has_oauth_refresh_token       — refresh token leak.
--   has_sdk_credentials           — Python/JS SDK creds.
--   has_kyc_dump                  — cliente KYC PII.
--   has_trade_log                 — wallet trade log.
--   has_earn_positions            — Lemon Earn yield dump.
--   has_card_transactions         — crypto-card spend log.
--   has_usdt_ars_arbitrage        — brecha arbitrage logic.
--   has_high_balance              — > USD 10 K crypto.
--   has_marketplace_webhook       — merchant webhook cfg.
--   has_cliente_dni               — cliente DNI detected.
--   has_cliente_cuit              — cliente CUIT detected.
--   has_pii_bundle                — ≥2 of (DNI, CUIT, name).
--   is_credential_exposure_risk   — readable + (password OR
--                                   OAuth token OR KYC dump
--                                   OR card txns OR USDT/ARS
--                                   arb OR cliente PII).

CREATE TABLE IF NOT EXISTS host_arg_lemoncash (
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
            'lemon-config','lemon-credentials',
            'lemon-sdk-script','lemon-trade-log',
            'lemon-earn-positions','lemon-kyc-dump',
            'lemon-card-transactions','lemon-arbitrage-script',
            'lemon-marketplace-config','lemon-webhook-config',
            'lemon-installer','other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'consumer','merchant','developer',
            'compliance-officer','api','demo',
            'other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'crypto-wallet','crypto-card',
            'stablecoin-rails','yield-earn',
            'marketplace','multi-product',
            'other','unknown'
        )),
    lemon_user_id               TEXT    NOT NULL DEFAULT '',
    lemon_app_id                TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    cliente_dni_hash            TEXT    NOT NULL DEFAULT '',
    access_token_hash           TEXT    NOT NULL DEFAULT '',
    refresh_token_hash          TEXT    NOT NULL DEFAULT '',
    webhook_secret_hash         TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_assets_count       INTEGER NOT NULL DEFAULT 0,
    trade_record_count          INTEGER NOT NULL DEFAULT 0,
    card_tx_count               INTEGER NOT NULL DEFAULT 0,
    earn_position_count         INTEGER NOT NULL DEFAULT 0,
    crypto_balance_usd_cents    INTEGER NOT NULL DEFAULT 0,
    pii_signal_count            INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_oauth_access_token      INTEGER NOT NULL DEFAULT 0 CHECK (has_oauth_access_token IN (0,1)),
    has_oauth_refresh_token     INTEGER NOT NULL DEFAULT 0 CHECK (has_oauth_refresh_token IN (0,1)),
    has_sdk_credentials         INTEGER NOT NULL DEFAULT 0 CHECK (has_sdk_credentials IN (0,1)),
    has_kyc_dump                INTEGER NOT NULL DEFAULT 0 CHECK (has_kyc_dump IN (0,1)),
    has_trade_log               INTEGER NOT NULL DEFAULT 0 CHECK (has_trade_log IN (0,1)),
    has_earn_positions          INTEGER NOT NULL DEFAULT 0 CHECK (has_earn_positions IN (0,1)),
    has_card_transactions       INTEGER NOT NULL DEFAULT 0 CHECK (has_card_transactions IN (0,1)),
    has_usdt_ars_arbitrage      INTEGER NOT NULL DEFAULT 0 CHECK (has_usdt_ars_arbitrage IN (0,1)),
    has_high_balance            INTEGER NOT NULL DEFAULT 0 CHECK (has_high_balance IN (0,1)),
    has_marketplace_webhook     INTEGER NOT NULL DEFAULT 0 CHECK (has_marketplace_webhook IN (0,1)),
    has_cliente_dni             INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_dni IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    has_pii_bundle              INTEGER NOT NULL DEFAULT 0 CHECK (has_pii_bundle IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_lemon_password
    ON host_arg_lemoncash(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_lemon_access_token
    ON host_arg_lemoncash(file_path) WHERE has_oauth_access_token = 1;

CREATE INDEX IF NOT EXISTS idx_lemon_refresh_token
    ON host_arg_lemoncash(file_path) WHERE has_oauth_refresh_token = 1;

CREATE INDEX IF NOT EXISTS idx_lemon_sdk_creds
    ON host_arg_lemoncash(lemon_app_id, period_yyyymm) WHERE has_sdk_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_lemon_kyc
    ON host_arg_lemoncash(lemon_user_id, period_yyyymm) WHERE has_kyc_dump = 1;

CREATE INDEX IF NOT EXISTS idx_lemon_trade
    ON host_arg_lemoncash(lemon_user_id, period_yyyymm) WHERE has_trade_log = 1;

CREATE INDEX IF NOT EXISTS idx_lemon_earn
    ON host_arg_lemoncash(lemon_user_id, period_yyyymm) WHERE has_earn_positions = 1;

CREATE INDEX IF NOT EXISTS idx_lemon_card
    ON host_arg_lemoncash(lemon_user_id, period_yyyymm) WHERE has_card_transactions = 1;

CREATE INDEX IF NOT EXISTS idx_lemon_arb
    ON host_arg_lemoncash(file_path) WHERE has_usdt_ars_arbitrage = 1;

CREATE INDEX IF NOT EXISTS idx_lemon_high_balance
    ON host_arg_lemoncash(lemon_user_id, crypto_balance_usd_cents) WHERE has_high_balance = 1;

CREATE INDEX IF NOT EXISTS idx_lemon_webhook
    ON host_arg_lemoncash(lemon_app_id) WHERE has_marketplace_webhook = 1;

CREATE INDEX IF NOT EXISTS idx_lemon_pii
    ON host_arg_lemoncash(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_pii_bundle = 1;

CREATE INDEX IF NOT EXISTS idx_lemon_exposure
    ON host_arg_lemoncash(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_lemon_drift
    ON host_arg_lemoncash(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_lemon_kind
    ON host_arg_lemoncash(artifact_kind, account_class);
