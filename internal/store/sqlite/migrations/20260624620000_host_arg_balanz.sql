-- host_arg_balanz inventories Balanz Capital retail-broker
-- artifact files cached on Argentine personal-investor,
-- wealth-management, and corporate-treasury workstations.
--
-- Balanz Capital S.A. (CNV-registered ALYC ad. integral
-- N° 210) is one of the largest Argentine retail brokers
-- alongside IOL (Banco Galicia) and Cocos Capital. Balanz
-- is notable for:
--
--   * Caución bursátil market-making (largest counterparty
--     by volume on BYMA REPO/caución book)
--   * Balanz Capital FCI manager (~AR$ 2 T AUM 2025)
--   * Sovereign-debt brokerage (Letras LECAP/BONCER/Bontes,
--     ON corporates)
--   * CEDEAR market-making (foreign-stock receipts)
--   * Balanz Trader Pro desktop terminal (Windows/macOS)
--   * pyBalanz REST + WS API for quants
--
-- **The Balanz-specific layer.** Distinct from:
--   - iter 151 winargiolinvertironline  IOL (Galicia)
--   - iter 152 winargcocoscapital       Cocos (fintech)
--   - iter 150 winargpyhomebroker       portal scrape
--   - iter 109 winargmatbarofex         futures positions
--   - iter 139 winargprimary            Primary REST/WS
--
-- Workstation cache footprint:
--
--   C:\Balanz\TraderPro\config\settings.xml   terminal cfg
--   C:\Balanz\TraderPro\positions.json        positions
--   C:\Balanz\TraderPro\orders.json           orders cache
--   C:\Balanz\TraderPro\caucion_cache.json    caución book
--   C:\Balanz\TraderPro\fci_balanz.json       FCI subs
--   %APPDATA%\Balanz\credentials.json         API creds
--   %USERPROFILE%\.balanz\config.yaml         pyBalanz cfg
--
-- Balanz-specific risk signals:
--   * Caución activity > monthly cap = BYMA REPO market-
--     maker exposure (CNV monitoring threshold)
--   * Letras LECAP/BONCER positions = sovereign-debt
--     concentration (Ley 27.611 transparency)
--   * CEDEAR positions = foreign-exchange exposure
--     (BCRA Com. A 7916 dollarization scrutiny)
--   * ON corporates = non-sovereign credit risk
--   * Cleartext password in settings.xml = T1552
--   * Cliente CUIT in positions/orders = Ley 25.326 PII
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes (ALYC)
--   CNV RG 622       Operativa
--   CNV RG 1023      Ciberresiliencia
--   BCRA Com. A 7916 operaciones cambiarias
--   BCRA Com. A 8005 Letras
--   Ley 27.611       Mercado Federal de Capitales
--   Ley 25.326       Protección de Datos Personales
--   UIF Resol. 30    PEP / AML
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_password_in_config       — settings.xml cleartext.
--   has_bearer_token             — API auth bearer leak.
--   has_caucion_activity         — caución book / REPO.
--   has_letras_tesoro            — LECAP / BONCER positions.
--   has_cedear_activity          — CEDEAR positions.
--   has_on_corporate             — ON corporate positions.
--   has_balanz_fci_subscription  — Balanz Capital FCI sub.
--   has_cliente_cuit             — cliente CUIT detected.
--   is_credential_exposure_risk  — readable + (password OR
--                                  bearer OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_balanz (
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
            'balanz-config','balanz-credentials',
            'balanz-positions-cache','balanz-orders-cache',
            'balanz-caucion-cache','balanz-fci-balanz',
            'balanz-on-cache','balanz-cedear-cache',
            'balanz-letras-cache','balanz-strategy-script',
            'balanz-account-export','balanz-installer',
            'other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'retail','wealth','corporate','api','demo',
            'other','unknown'
        )),
    broker_matricula            TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    bearer_token_hash           TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    session_first_seen          TEXT    NOT NULL DEFAULT '',
    session_last_seen           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    portfolio_position_count    INTEGER NOT NULL DEFAULT 0,
    caucion_volume_ars_cents    INTEGER NOT NULL DEFAULT 0,
    cedear_position_count       INTEGER NOT NULL DEFAULT 0,
    letras_position_count       INTEGER NOT NULL DEFAULT 0,
    on_position_count           INTEGER NOT NULL DEFAULT 0,
    fci_subscription_count      INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_bearer_token            INTEGER NOT NULL DEFAULT 0 CHECK (has_bearer_token IN (0,1)),
    has_caucion_activity        INTEGER NOT NULL DEFAULT 0 CHECK (has_caucion_activity IN (0,1)),
    has_letras_tesoro           INTEGER NOT NULL DEFAULT 0 CHECK (has_letras_tesoro IN (0,1)),
    has_cedear_activity         INTEGER NOT NULL DEFAULT 0 CHECK (has_cedear_activity IN (0,1)),
    has_on_corporate            INTEGER NOT NULL DEFAULT 0 CHECK (has_on_corporate IN (0,1)),
    has_balanz_fci_subscription INTEGER NOT NULL DEFAULT 0 CHECK (has_balanz_fci_subscription IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_balanz_password
    ON host_arg_balanz(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_balanz_bearer
    ON host_arg_balanz(file_path) WHERE has_bearer_token = 1;

CREATE INDEX IF NOT EXISTS idx_balanz_caucion
    ON host_arg_balanz(broker_matricula, period_yyyymm) WHERE has_caucion_activity = 1;

CREATE INDEX IF NOT EXISTS idx_balanz_letras
    ON host_arg_balanz(broker_matricula, period_yyyymm) WHERE has_letras_tesoro = 1;

CREATE INDEX IF NOT EXISTS idx_balanz_cedear
    ON host_arg_balanz(broker_matricula, period_yyyymm) WHERE has_cedear_activity = 1;

CREATE INDEX IF NOT EXISTS idx_balanz_on
    ON host_arg_balanz(broker_matricula, period_yyyymm) WHERE has_on_corporate = 1;

CREATE INDEX IF NOT EXISTS idx_balanz_fci
    ON host_arg_balanz(broker_matricula) WHERE has_balanz_fci_subscription = 1;

CREATE INDEX IF NOT EXISTS idx_balanz_cliente
    ON host_arg_balanz(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_balanz_exposure
    ON host_arg_balanz(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_balanz_drift
    ON host_arg_balanz(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_balanz_kind
    ON host_arg_balanz(artifact_kind, account_class);
