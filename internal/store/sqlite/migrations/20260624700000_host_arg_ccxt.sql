-- host_arg_ccxt inventories CCXT Python crypto-exchange
-- library artifact files cached on Argentine quant, arbitrage-
-- desk, retail-quant, and fintech workstations.
--
-- CCXT (https://github.com/ccxt/ccxt) is the canonical Python
-- (also JS/PHP) multi-exchange crypto trading library. The
-- Argentine crypto-quant community uses CCXT for:
--
--   USDT/ARS arbitrage    Lemon/Belo/Ripio ↔ Binance/Coinbase
--   Cross-rate FX         ARS via USDT bridge (parallel dolar)
--   Funding-rate arb      perp-vs-spot, cross-exchange
--   AFIP RG 5527 prep     transaction history for tax reports
--
-- **The crypto multi-exchange library layer.** Distinct from:
--   - iter 160 winarglean         QuantConnect LEAN framework
--   - iter 161 winargmaeonlinefx  MAE OnlineFX (regulated FX)
--   - iter 159 winargafiprg5193   AFIP RG 5527 tax reporter side
--   - iter 152 winargcocoscapital Cocos USDT Pay (single-broker)
--   - iter ___ winargcrypto       generic crypto detector
--
-- Workstation cache footprint:
--
--   %APPDATA%\ccxt\config.json         CCXT engine cfg
--   ~/.ccxt/keys/<exchange>.json       per-exchange API key
--   ~/projects/arb/strategy.py         Python strategy (ccxt import)
--   ~/projects/arb/trade_log_<dt>.csv  trade ledger
--   ~/projects/arb/balance_<dt>.json   per-exchange snapshot
--   ~/projects/arb/arbitrage_bot.py    spread / triangular bot
--
-- Argentine crypto exchanges (PSAV per BCRA Com. A 7975):
--   Lemon Cash, Belo, Ripio, Buenbit, Bitso (LATAM), Decrypto,
--   SatoshiTango, ArgenBTC.
--
-- Global major exchanges:
--   Binance, Coinbase, Kraken, Bitfinex, Bybit, OKX, KuCoin,
--   Gate, Bitstamp, Gemini.
--
-- Global derivatives venues:
--   Binance Futures, BitMEX, Deribit, dYdX, Bybit Derivatives.
--
-- CCXT-specific risk signals:
--   * Per-exchange API key in cleartext = T1552 (covers all
--     ccxt-loaded exchanges)
--   * Argentine-exchange API key = PSAV trading subject to
--     BCRA Com. A 7975 + AFIP RG 5527 reporting
--   * Cross-exchange arbitrage (AR-local ↔ global) = capital
--     flight indirect surface (BCRA Com. A 7916 scrutiny)
--   * High-freq polling (>1/sec API calls) = HFT pattern,
--     IP-ban risk + CNV scrutiny if equity bridges exist
--   * Funding-rate strategy = perp derivative exposure
--   * Cliente CUIT in strategy parameter = Ley 25.326 PII
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   BCRA Com. A 7916 Operaciones cambiarias
--   BCRA Com. A 7975 PSAV (crypto) regulation
--   AFIP RG 5527     Crypto tax reporting
--   AFIP RG 5193     Securities tax reporting
--   CNV RG 731       Régimen de Agentes (crypto subset)
--   CNV RG 1023      Ciberresiliencia
--   Ley 25.326       Protección de Datos Personales
--   UIF Resol. 30    PEP / AML KYC
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1059.006 Python Command and Scripting Interpreter
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_password_in_config         — config cleartext.
--   has_exchange_api_key           — per-exchange API key leak.
--   has_argentine_exchange         — Lemon/Belo/Ripio etc.
--   has_global_exchange            — Binance/Coinbase/Kraken etc.
--   has_derivatives_exchange       — Binance Futures/BitMEX etc.
--   has_dex_integration            — Uniswap/PancakeSwap etc.
--   has_arbitrage_bot              — spread/triangular/cross.
--   has_usdt_ars_arbitrage         — AR-local + global USDT/ARS.
--   has_funding_rate_strategy      — perp funding rate arb.
--   has_high_freq_polling          — > 1/sec API calls.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable + (password OR
--                                    exchange key OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_ccxt (
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
            'ccxt-config','ccxt-credentials',
            'ccxt-exchange-keys','ccxt-strategy-py',
            'ccxt-trade-log','ccxt-balance-snapshot',
            'ccxt-arbitrage-bot','ccxt-installer',
            'other','unknown'
        )),
    exchange_class              TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (exchange_class IN (
            'argentine-local','global-major',
            'global-derivatives','dex','aggregator',
            'other','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    exchange_id                 TEXT    NOT NULL DEFAULT '',
    exchange_key_hash           TEXT    NOT NULL DEFAULT '',
    strategy_name               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_exchange_count     INTEGER NOT NULL DEFAULT 0,
    trade_count                 INTEGER NOT NULL DEFAULT 0,
    peak_api_calls_per_sec      INTEGER NOT NULL DEFAULT 0,
    total_usdt_volume_cents     INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_exchange_api_key        INTEGER NOT NULL DEFAULT 0 CHECK (has_exchange_api_key IN (0,1)),
    has_argentine_exchange      INTEGER NOT NULL DEFAULT 0 CHECK (has_argentine_exchange IN (0,1)),
    has_global_exchange         INTEGER NOT NULL DEFAULT 0 CHECK (has_global_exchange IN (0,1)),
    has_derivatives_exchange    INTEGER NOT NULL DEFAULT 0 CHECK (has_derivatives_exchange IN (0,1)),
    has_dex_integration         INTEGER NOT NULL DEFAULT 0 CHECK (has_dex_integration IN (0,1)),
    has_arbitrage_bot           INTEGER NOT NULL DEFAULT 0 CHECK (has_arbitrage_bot IN (0,1)),
    has_usdt_ars_arbitrage      INTEGER NOT NULL DEFAULT 0 CHECK (has_usdt_ars_arbitrage IN (0,1)),
    has_funding_rate_strategy   INTEGER NOT NULL DEFAULT 0 CHECK (has_funding_rate_strategy IN (0,1)),
    has_high_freq_polling       INTEGER NOT NULL DEFAULT 0 CHECK (has_high_freq_polling IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_ccxt_password
    ON host_arg_ccxt(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_ccxt_exchange_key
    ON host_arg_ccxt(file_path, exchange_id) WHERE has_exchange_api_key = 1;

CREATE INDEX IF NOT EXISTS idx_ccxt_argentine
    ON host_arg_ccxt(exchange_id, period_yyyymm) WHERE has_argentine_exchange = 1;

CREATE INDEX IF NOT EXISTS idx_ccxt_global
    ON host_arg_ccxt(exchange_id, period_yyyymm) WHERE has_global_exchange = 1;

CREATE INDEX IF NOT EXISTS idx_ccxt_derivatives
    ON host_arg_ccxt(exchange_id, period_yyyymm) WHERE has_derivatives_exchange = 1;

CREATE INDEX IF NOT EXISTS idx_ccxt_arbitrage
    ON host_arg_ccxt(file_path) WHERE has_arbitrage_bot = 1;

CREATE INDEX IF NOT EXISTS idx_ccxt_usdt_ars
    ON host_arg_ccxt(file_path, period_yyyymm) WHERE has_usdt_ars_arbitrage = 1;

CREATE INDEX IF NOT EXISTS idx_ccxt_hfreq
    ON host_arg_ccxt(file_path, peak_api_calls_per_sec) WHERE has_high_freq_polling = 1;

CREATE INDEX IF NOT EXISTS idx_ccxt_cliente
    ON host_arg_ccxt(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ccxt_exposure
    ON host_arg_ccxt(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ccxt_drift
    ON host_arg_ccxt(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_ccxt_kind
    ON host_arg_ccxt(artifact_kind, exchange_class);
