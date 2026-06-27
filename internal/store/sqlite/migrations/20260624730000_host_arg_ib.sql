-- host_arg_ib inventories Interactive Brokers TWS / IB Gateway
-- / ibapi-SDK artifact files cached on Argentine retail-quant,
-- prop-desk, and institutional-quant workstations.
--
-- Interactive Brokers (IB) is the dominant US-based brokerage
-- that Argentine residents use to access global markets (NYSE,
-- NASDAQ, LSE, HKEX, TSE), CME / CBOT / NYMEX futures, CBOE
-- options, FX, fixed income, and (since 2021) crypto.
--
-- IB is **offshore** from a CNV perspective — Argentine
-- residents who trade via IB do so directly with IBKR LLC
-- (US) or IBKR UK Ltd., subject to:
--
--   AFIP RG 5193   mandatory securities reporting for AR
--                  residents holding foreign accounts
--   AFIP F.8125    cross-border transfer reporting
--   BCRA Com. A 7916 outbound USD restriction (200 K cap)
--   AFIP Bienes Personales declaration of foreign assets
--   AFIP RG 5527   crypto reporting (if IB crypto used)
--
-- **The offshore-broker layer.** Distinct from:
--   - iter 151 winargiolinvertironline IOL local retail
--   - iter 154 winargbalanz            Balanz local
--   - iter 162 winargccxt              crypto multi-exchange
--   - iter 160 winarglean              LEAN framework (uses IB
--                                      as one of many adapters)
--
-- IB connection surfaces:
--   TWS Desktop         Java app, port 7496 (live) / 7497 (paper)
--   IB Gateway          headless, port 4001 (live) / 4002 (paper)
--   ibapi Python SDK    pip package "ibapi" or "ib-insync"
--   ib-insync          async wrapper (very common in AR quant)
--   Mobile / Web        IB Mobile, Client Portal
--
-- Workstation cache footprint:
--
--   C:\Jts\jts.ini                   TWS config
--   C:\Jts\<version>\twsstart.bat    launcher
--   C:\Jts\<version>\settings\       per-user settings
--   C:\IBKR\Gateway\config.ini       IB Gateway cfg
--   ~/Jts/jts.ini                    macOS/Linux
--   ~/Documents/IB/flex_<dt>.xml     Flex Query export
--   ~/projects/quant/strategy.py     ibapi/ib_insync import
--   ~/.ib-insync/*                   ib-insync state
--
-- IB-specific risk signals:
--   * Cleartext password in jts.ini = T1552 + CNV RG 1023
--   * API socket bound to 0.0.0.0 (vs 127.0.0.1) = remote-
--     exploit via TWS API exposure (CWE-200)
--   * Live-account mode (vs paper) = production trading
--   * US-equity / global-equity positions = AFIP RG 5193
--     + Bienes Personales obligation
--   * Cross-border transfer > USD 200 K = BCRA Com. A 7916
--     + F.8125 trigger
--   * Flex Query XML export = annual tax statement source
--     (contains full transaction history + PII)
--   * IB crypto positions = AFIP RG 5527 reporting
--   * High AUM > USD 100 K = wealth-tax tier
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   AFIP RG 5193     Securities tax reporting
--   AFIP RG 5527     Crypto tax reporting
--   AFIP F.8125      Cross-border transfer
--   BCRA Com. A 7916 Operaciones cambiarias (200 K cap)
--   BCRA Com. A 7724 Letras Liquidación
--   Ley 25.246       Encubrimiento (AML)
--   Ley 25.326       Protección de Datos Personales
--   Ley Bienes Personales (Ley 23.966)
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1071    Application Layer Protocol (TWS API socket)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_password_in_config         — jts.ini cleartext.
--   has_api_socket_exposed         — TWS API bound 0.0.0.0.
--   has_live_account               — live-mode (vs paper).
--   has_us_equity_positions        — US equity (RG 5193).
--   has_global_equity_positions    — LSE/HKEX/TSE/etc.
--   has_futures_cme                — CME futures (CBOT/NYMEX).
--   has_forex_trading              — FX cash/forward.
--   has_crypto_positions           — IB crypto (RG 5527).
--   has_flex_query_export          — XML/CSV tax export.
--   has_high_aum                   — > USD 100 K.
--   has_bcra_above_cap             — > USD 200 K cross-border.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable + (password OR
--                                    api token OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_ib (
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
            'ib-config','ib-gateway-config','ib-credentials',
            'ib-tws-settings','ib-positions','ib-orders',
            'ib-strategy-py','ib-trade-log','ib-flex-query',
            'ib-tax-statement','ib-installer','other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'retail','pro','institutional','api',
            'paper','demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'us-equity','global-equity','futures-cme',
            'options-cboe','forex','bonds','crypto',
            'multi-asset','other','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    ib_account_suffix4          TEXT    NOT NULL DEFAULT '',
    api_socket_address          TEXT    NOT NULL DEFAULT '',
    api_socket_port             INTEGER NOT NULL DEFAULT 0,
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    portfolio_aum_usd_cents     INTEGER NOT NULL DEFAULT 0,
    above_cap_count             INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_api_socket_exposed      INTEGER NOT NULL DEFAULT 0 CHECK (has_api_socket_exposed IN (0,1)),
    has_live_account            INTEGER NOT NULL DEFAULT 0 CHECK (has_live_account IN (0,1)),
    has_us_equity_positions     INTEGER NOT NULL DEFAULT 0 CHECK (has_us_equity_positions IN (0,1)),
    has_global_equity_positions INTEGER NOT NULL DEFAULT 0 CHECK (has_global_equity_positions IN (0,1)),
    has_futures_cme             INTEGER NOT NULL DEFAULT 0 CHECK (has_futures_cme IN (0,1)),
    has_forex_trading           INTEGER NOT NULL DEFAULT 0 CHECK (has_forex_trading IN (0,1)),
    has_crypto_positions        INTEGER NOT NULL DEFAULT 0 CHECK (has_crypto_positions IN (0,1)),
    has_flex_query_export       INTEGER NOT NULL DEFAULT 0 CHECK (has_flex_query_export IN (0,1)),
    has_high_aum                INTEGER NOT NULL DEFAULT 0 CHECK (has_high_aum IN (0,1)),
    has_bcra_above_cap          INTEGER NOT NULL DEFAULT 0 CHECK (has_bcra_above_cap IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_ib_password
    ON host_arg_ib(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_ib_socket_exposed
    ON host_arg_ib(api_socket_address, api_socket_port) WHERE has_api_socket_exposed = 1;

CREATE INDEX IF NOT EXISTS idx_ib_live
    ON host_arg_ib(ib_account_suffix4, period_yyyymm) WHERE has_live_account = 1;

CREATE INDEX IF NOT EXISTS idx_ib_us_equity
    ON host_arg_ib(ib_account_suffix4, period_yyyymm) WHERE has_us_equity_positions = 1;

CREATE INDEX IF NOT EXISTS idx_ib_global_equity
    ON host_arg_ib(ib_account_suffix4, period_yyyymm) WHERE has_global_equity_positions = 1;

CREATE INDEX IF NOT EXISTS idx_ib_futures
    ON host_arg_ib(ib_account_suffix4, period_yyyymm) WHERE has_futures_cme = 1;

CREATE INDEX IF NOT EXISTS idx_ib_forex
    ON host_arg_ib(ib_account_suffix4, period_yyyymm) WHERE has_forex_trading = 1;

CREATE INDEX IF NOT EXISTS idx_ib_crypto
    ON host_arg_ib(ib_account_suffix4, period_yyyymm) WHERE has_crypto_positions = 1;

CREATE INDEX IF NOT EXISTS idx_ib_flex
    ON host_arg_ib(file_path) WHERE has_flex_query_export = 1;

CREATE INDEX IF NOT EXISTS idx_ib_high_aum
    ON host_arg_ib(ib_account_suffix4, portfolio_aum_usd_cents) WHERE has_high_aum = 1;

CREATE INDEX IF NOT EXISTS idx_ib_bcra_above_cap
    ON host_arg_ib(ib_account_suffix4, above_cap_count) WHERE has_bcra_above_cap = 1;

CREATE INDEX IF NOT EXISTS idx_ib_cliente
    ON host_arg_ib(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ib_exposure
    ON host_arg_ib(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ib_drift
    ON host_arg_ib(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_ib_kind
    ON host_arg_ib(artifact_kind, account_class, product_class);
