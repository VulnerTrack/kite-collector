-- host_arg_crypto_psav inventories Argentine crypto-PSAV
-- (Proveedor de Servicios de Activos Virtuales) exchange
-- files cached on retail trader, prop-desk, and OTC-broker
-- workstations.
--
-- The CNV created the PSAV registry under Resol. 994/2024
-- (Dec 2024). UIF Resol. 49/2024 mandates KYC + ROS for all
-- virtual-asset operations. PSAVs registered in Argentina:
--
--   Bitso, Lemon, Belo, Ripio, Buenbit, Decrypto, Satoshitango,
--   Fiwind, Cryptomarket, Vibrant, Letsbit
--
-- Plus offshore exchanges Argentine traders use (must self-
-- report to AFIP Bienes Personales): Binance, Kraken, OKX,
-- Bybit, Coinbase, KuCoin.
--
-- Workstation cache footprint:
--
--   ~/.bitso/credentials.json                  API key + secret
--   ~/.lemon/config.toml                       client config
--   ~/.config/binance/api.json                 Binance API key
--   ~/.config/ccxt/<exch>.json                 ccxt library cache
--   ~/Documents/Crypto/bitso_export_<dt>.csv   account export
--   ~/Documents/Crypto/p2p_otc_<dt>.log        OTC P2P trade log
--   ~/Documents/Crypto/usdt_pairs_<dt>.csv     stablecoin trades
--   ~/Documents/Crypto/wallet_seed.txt         BIP39 seed (HIGH RISK)
--   ~/Documents/Crypto/bienes_personales_<yr>.csv AFIP export
--   *.py importing ccxt / python-binance       algo script
--
-- **The crypto-PSAV layer.** Distinct from:
--   - iter 108 winalgotrading   — generic algotrading
--   - iter 109 winargmatbarofex — futures positions
--   - iter 138 winarguifros     — UIF/AML compliance
--   - iter 139 winargprimary    — Primary API
--
-- Crypto-specific risk signals matter for:
--   * Wallet seed / private key on disk → permanent fund
--     loss exposure. NEVER extract — presence-only flag.
--   * USDT/USDC pair trading > 10 M ARS = "stablecoin dollar"
--     arbitrage; BCRA Com. A 7916 + AFIP RG 5193 scrutiny.
--   * OTC P2P activity = direct dollar-acquisition channel;
--     UIF Resol. 49 KYC requirement.
--   * API key in cleartext + production endpoint = full
--     account-flow impersonation.
--
-- Regulatory base:
--   CNV Resol. 994/2024  — Registro PSAV
--   UIF Resol. 49/2024   — PLA/FT crypto
--   AFIP RG 5193/2022    — declaración tributaria cripto
--   AFIP RG 5527/2024    — régimen de información PSAV
--   BCRA Com. A 7916     — operaciones cambiarias
--   Ley 25.246           — PLA/FT general
--   Ley 25.326           — protección datos personales
--   FATF Recommendation 15 (virtual assets)
--   FATF Travel Rule (originator/beneficiary VASP data)
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials (api keys, seeds)
--   T1555    Credentials from Password Stores (wallet)
--   T1078    Valid Accounts (exchange impersonation)
--   CWE-200, CWE-359, CWE-532, CWE-798
--   CWE-922  (insecure storage of sensitive info — seed)
--   Ley 25.326 (cliente PII en KYC)
--
-- Headline finding shapes:
--   has_api_key               — api_key/api_secret in cleartext.
--   has_api_secret            — api_secret (vs key alone).
--   has_wallet_seed_marker    — BIP39 / mnemonic marker
--                               detected (presence-only).
--   has_otc_p2p_activity      — OTC P2P trade log.
--   has_stablecoin_volume     — USDT/USDC pair trading.
--   has_high_volume_stablecoin — stablecoin volume > 10M ARS.
--   has_strategy_script       — .py imports ccxt / python-binance.
--   has_afip_unreported       — large vol + no AFIP RG 5193
--                               marker in workstation cache.
--   has_cliente_cuit          — cliente CUIT detected.
--   is_credential_exposure_risk — readable file +
--                               (api-key OR seed OR P2P body).
--
-- API keys + seed phrases NEVER persisted. SHA-256 hash of
-- the api-key fragment retained. Wallet seeds are detected
-- by BIP39 wordlist marker scan only — full phrase NEVER
-- captured. All CUITs reduced to prefix + last 4 digits.

CREATE TABLE IF NOT EXISTS host_arg_crypto_psav (
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
            'crypto-api-key','crypto-account-export',
            'crypto-otc-p2p-log','crypto-wallet-seed',
            'crypto-tax-report','crypto-stablecoin-trade-log',
            'crypto-strategy-script','crypto-ccxt-cache',
            'crypto-installer','other','unknown'
        )),
    exchange                    TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (exchange IN (
            'bitso','lemon','belo','ripio','buenbit','decrypto',
            'satoshitango','fiwind','cryptomarket','vibrant','letsbit',
            'binance','kraken','okx','bybit','coinbase','kucoin',
            'other','unknown'
        )),
    psav_class                  TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (psav_class IN (
            'arg-registered-psav','offshore-self-report',
            'wallet-non-custodial','other','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    trade_count                 INTEGER NOT NULL DEFAULT 0,
    otc_p2p_count               INTEGER NOT NULL DEFAULT 0,
    stablecoin_volume_ars_cents INTEGER NOT NULL DEFAULT 0,
    max_trade_ars_cents         INTEGER NOT NULL DEFAULT 0,
    distinct_pair_count         INTEGER NOT NULL DEFAULT 0,
    session_first_seen          TEXT    NOT NULL DEFAULT '',
    session_last_seen           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_api_key                 INTEGER NOT NULL DEFAULT 0 CHECK (has_api_key IN (0,1)),
    has_api_secret              INTEGER NOT NULL DEFAULT 0 CHECK (has_api_secret IN (0,1)),
    has_wallet_seed_marker      INTEGER NOT NULL DEFAULT 0 CHECK (has_wallet_seed_marker IN (0,1)),
    has_otc_p2p_activity        INTEGER NOT NULL DEFAULT 0 CHECK (has_otc_p2p_activity IN (0,1)),
    has_stablecoin_volume       INTEGER NOT NULL DEFAULT 0 CHECK (has_stablecoin_volume IN (0,1)),
    has_high_volume_stablecoin  INTEGER NOT NULL DEFAULT 0 CHECK (has_high_volume_stablecoin IN (0,1)),
    has_strategy_script         INTEGER NOT NULL DEFAULT 0 CHECK (has_strategy_script IN (0,1)),
    has_afip_unreported         INTEGER NOT NULL DEFAULT 0 CHECK (has_afip_unreported IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_crypto_api
    ON host_arg_crypto_psav(file_path) WHERE has_api_key = 1;

CREATE INDEX IF NOT EXISTS idx_crypto_seed
    ON host_arg_crypto_psav(file_path) WHERE has_wallet_seed_marker = 1;

CREATE INDEX IF NOT EXISTS idx_crypto_otc
    ON host_arg_crypto_psav(exchange, period_yyyymm) WHERE has_otc_p2p_activity = 1;

CREATE INDEX IF NOT EXISTS idx_crypto_stable_high
    ON host_arg_crypto_psav(exchange, period_yyyymm) WHERE has_high_volume_stablecoin = 1;

CREATE INDEX IF NOT EXISTS idx_crypto_afip
    ON host_arg_crypto_psav(exchange, period_yyyymm) WHERE has_afip_unreported = 1;

CREATE INDEX IF NOT EXISTS idx_crypto_strategy
    ON host_arg_crypto_psav(file_path) WHERE has_strategy_script = 1;

CREATE INDEX IF NOT EXISTS idx_crypto_cliente
    ON host_arg_crypto_psav(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_crypto_exposure
    ON host_arg_crypto_psav(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_crypto_drift
    ON host_arg_crypto_psav(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_crypto_exchange
    ON host_arg_crypto_psav(exchange, artifact_kind);

CREATE INDEX IF NOT EXISTS idx_crypto_psav_class
    ON host_arg_crypto_psav(psav_class, exchange);
