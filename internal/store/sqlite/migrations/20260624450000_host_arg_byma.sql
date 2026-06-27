-- host_arg_byma inventories BYMA equity-terminal files
-- cached on Argentine bank, broker, prop-desk, and back-
-- office workstations.
--
-- BYMA (Bolsas y Mercados Argentinos) is the Argentine stock
-- exchange: equities (GGAL/YPF/PAMP/ALUA/etc.), CEDEARs (the
-- ADRs of foreign issuers traded in ARS), and the AL30/GD30
-- dollar-linked sovereign-bond pairs that drive MEP/CCL
-- arbitrage.
--
-- Files cached on workstations:
--
--   C:\BYMA\Edge\config\edge.ini           Edge terminal
--   C:\BYMA\Aries\aries.cfg                Aries terminal
--   C:\BYMA\SX\config.json                 SX Bursátil
--   C:\BYMA\Connect\api.json               BYMA Connect REST
--   C:\BYMA\blotter\rv_<date>.xml          RV trade blotter
--   C:\BYMA\liquidacion\T2_<date>.csv      T+2 settlement
--   C:\BYMA\caucion\rv_caucion_<date>.xml  caución RV side
--   C:\BYMA\cedears\<broker>_<date>.csv    CEDEAR positions
--   C:\BYMA\bcv\<id>.xml                   boleto compra-venta
--   %APPDATA%\BYMA\                        per-user terminal
--
-- **The equity-terminal layer.** Distinct from:
--   - iter 113 winargfix          FIX wire-protocol session
--   - iter 117 winargcvsa         CVSA central custody
--   - iter 136 winargsiopel       SIOPEL/MAE OTC terminal
--   - iter 109 winargmatbarofex   derivatives (futures)
--   - iter 110 winargfci          FCI mutual-fund layer
--
-- BYMA-specific risk signals:
--   * BYMA Connect API key in cleartext (Connect.api.json) →
--     full account-flow impersonation.
--   * CEDEAR position concentration → offshore-equity
--     exposure outside Argentine venue oversight.
--   * MEP/CCL arbitrage pattern → paired AL30 buy + AL30D
--     sell in the same blotter (Com. A 7916 compliance).
--   * Caución RV tenor > 60 days → BYMA Reglamento Operativo
--     limit.
--   * Concertación outside 11:00-17:00 ART → improper trading.
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes
--   CNV RG 622       Mercado de Capitales (operativa)
--   CNV RG 941       Reportes operaciones sospechosas
--   BCRA Com. A 7916 operaciones cambiarias
--   BCRA Com. A 7724 ciberseguridad SF
--   BYMA Reglamento Operativo
--   MAE Manual de Negociación
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials (Connect API key)
--   T1078    Valid Accounts (compromised dealer)
--   CWE-200, CWE-359, CWE-532
--   CWE-798 (hardcoded credentials in .json)
--   Ley 25.326 (cliente CUIT in blotter)
--   Ley 27.260 (AAIP data protection)
--
-- Headline finding shapes:
--   has_api_key_in_config       — Connect.api.json carries
--                                api_key/bearer in cleartext.
--   has_cedear_position         — file references CEDEAR
--                                tickers (AAPL/MSFT/etc. in ARS).
--   has_mep_ccl_arbitrage       — paired AL30/AL30D or
--                                GD30/GD30D in the same body.
--   has_caucion_long_tenor      — caución RV entry > 60 days.
--   has_high_concentration      — single ticker > 50% of
--                                trade-blotter notional.
--   is_after_hours              — concertación outside
--                                Mon-Fri 11:00-17:00 ART.
--   is_credential_exposure_risk — readable file + cliente
--                                CUIT + (api-key OR trade body).
--
-- All CUITs reduced to entity-type prefix + last 4 digits.
-- API keys never persisted — only the SHA-256 hash of the
-- detected key fragment is retained.

CREATE TABLE IF NOT EXISTS host_arg_byma (
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
            'byma-edge-config','byma-aries-config',
            'byma-sx-config','byma-connect-api',
            'byma-rv-blotter','byma-cedear-pos',
            'byma-bcv','byma-liquidacion-t2',
            'byma-caucion-rv','byma-market-data-cache',
            'byma-installer','other','unknown'
        )),
    terminal                    TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (terminal IN (
            'edge','aries','sx-bursatil','connect-api',
            'back-office','other','unknown'
        )),
    broker_matricula            TEXT    NOT NULL DEFAULT '',
    operator_cuit_prefix        TEXT    NOT NULL DEFAULT ''
        CHECK (operator_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    operator_cuit_suffix4       TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    trade_count                 INTEGER NOT NULL DEFAULT 0,
    cedear_ticker_count         INTEGER NOT NULL DEFAULT 0,
    sovereign_ticker_count      INTEGER NOT NULL DEFAULT 0,
    distinct_ticker_count       INTEGER NOT NULL DEFAULT 0,
    max_position_ars_cents      INTEGER NOT NULL DEFAULT 0,
    total_position_ars_cents    INTEGER NOT NULL DEFAULT 0,
    max_position_pct            INTEGER NOT NULL DEFAULT 0
        CHECK (max_position_pct BETWEEN 0 AND 100),
    caucion_max_tenor_days      INTEGER NOT NULL DEFAULT 0,
    session_first_seen          TEXT    NOT NULL DEFAULT '',
    session_last_seen           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_api_key_in_config       INTEGER NOT NULL DEFAULT 0 CHECK (has_api_key_in_config IN (0,1)),
    has_cedear_position         INTEGER NOT NULL DEFAULT 0 CHECK (has_cedear_position IN (0,1)),
    has_mep_ccl_arbitrage       INTEGER NOT NULL DEFAULT 0 CHECK (has_mep_ccl_arbitrage IN (0,1)),
    has_caucion_long_tenor      INTEGER NOT NULL DEFAULT 0 CHECK (has_caucion_long_tenor IN (0,1)),
    has_high_concentration      INTEGER NOT NULL DEFAULT 0 CHECK (has_high_concentration IN (0,1)),
    has_concertacion            INTEGER NOT NULL DEFAULT 0 CHECK (has_concertacion IN (0,1)),
    is_after_hours              INTEGER NOT NULL DEFAULT 0 CHECK (is_after_hours IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_byma_api_key
    ON host_arg_byma(file_path) WHERE has_api_key_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_byma_cedear
    ON host_arg_byma(broker_matricula, period_yyyymm) WHERE has_cedear_position = 1;

CREATE INDEX IF NOT EXISTS idx_byma_mep_ccl
    ON host_arg_byma(broker_matricula, period_yyyymm) WHERE has_mep_ccl_arbitrage = 1;

CREATE INDEX IF NOT EXISTS idx_byma_concentration
    ON host_arg_byma(broker_matricula) WHERE has_high_concentration = 1;

CREATE INDEX IF NOT EXISTS idx_byma_caucion
    ON host_arg_byma(broker_matricula, period_yyyymm) WHERE has_caucion_long_tenor = 1;

CREATE INDEX IF NOT EXISTS idx_byma_after_hours
    ON host_arg_byma(broker_matricula, period_yyyymm) WHERE is_after_hours = 1;

CREATE INDEX IF NOT EXISTS idx_byma_cliente
    ON host_arg_byma(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_byma_exposure
    ON host_arg_byma(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_byma_drift
    ON host_arg_byma(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_byma_terminal
    ON host_arg_byma(terminal, artifact_kind);

CREATE INDEX IF NOT EXISTS idx_byma_broker
    ON host_arg_byma(broker_matricula, terminal);
