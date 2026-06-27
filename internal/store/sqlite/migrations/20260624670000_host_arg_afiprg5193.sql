-- host_arg_afiprg5193 inventories AFIP RG 5193 (securities)
-- + RG 5527 (crypto) broker-side tax-reporting artifact files
-- cached on Argentine ALYC, fintech, FCI-manager, and bank
-- compliance workstations.
--
-- AFIP (now ARCA — Agencia de Recaudación y Control Aduanero
-- as of 2024) regulates broker tax reporting via:
--
--   RG 5193 (2022) — Securities broker daily transaction
--                    reports. Every ALYC reports cliente
--                    operations daily to AFIP.
--   RG 5527 (2024) — Crypto-asset exchange / PSAV reports.
--                    Every fintech with crypto operations
--                    (Lemon/Ripio/Belo/Bitso/Cocos USDT Pay)
--                    reports user transactions.
--   RG 4838 (2020) — Original securities reporting (replaced
--                    by RG 5193).
--   RG 3293 (2012) — Information of Operations (COTI for
--                    high-value investment transactions).
--   F.572 / F.8125 — Internal transfers + foreign assets.
--
-- **The tax-reporting layer.** Distinct from:
--   - iter 107 winargcnvalyc      — CNV ALYC broker side
--   - iter 144 winargcnvrg1023    — CNV cyber resilience
--   - iter 109 winargmatbarofex   — futures positions
--   - iter 157 winargmaeclear     — MAE clearing
--   - iter 158 winargprismaweb    — BYMA clearing
--   - iter 122 winarguifros       — UIF ROS / SAR reports
--
-- Reporter classes (per AFIP RG 5193 art. 3):
--   alyc                   broker-dealer
--   asegurador             insurance company
--   sociedad-bolsa         stock exchange member
--   banking-custodian      bank as custodian
--   fci-manager            FCI Sociedad Gerente
--   fintech                fintech with broker scope
--   cripto-exchange        crypto exchange / PSAV (RG 5527)
--
-- Workstation cache footprint:
--
--   C:\AFIP\RG5193\daily_<yyyymmdd>.txt    daily transactions
--   C:\AFIP\RG5527\crypto_<yyyymmdd>.json  crypto txns
--   C:\AFIP\COTI\inversiones_<dt>.xml      COTI op notice
--   C:\AFIP\Ganancias\retenciones_<dt>.csv income withholding
--   C:\AFIP\Bienes\bienes_<cuit>.xlsx      wealth declarations
--   C:\AFIP\F8125\transfer_<dt>.xml        F.8125 transfer
--   C:\AFIP\Exteriorizacion\<dt>.xml       foreign asset decl
--   %APPDATA%\AFIP\session.tok             AFIP Clave Fiscal
--   %APPDATA%\AFIP\config.xml              Clave Fiscal cfg
--
-- AFIP-specific risk signals:
--   * Cleartext password in config = T1552 + CNV RG 1023
--   * AFIP Clave Fiscal session token leak = sovereign-grade
--     impersonation risk (covers ALL tax + import + customs)
--   * Crypto reporting (RG 5527) = full user wallet exposure
--   * Bienes personales = full client wealth declaration
--   * High-value threshold (> $200 K USD = ~AR$ 200 M ARS)
--     triggers F.8125 mandatory reporting (CNV/UIF tap)
--   * Cross-border transfer = AFIP RG 3293 + BCRA exchange
--     control tap (BCRA Com. A 7916 dollar restriction)
--   * Natural-person PII bundle (DNI + CUIT + full name +
--     address + bank account) = direct Ley 25.326 breach
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   Ley 25.246       Encubrimiento (AML)
--   Ley 25.326       Protección de Datos Personales
--   AFIP RG 5193     Régimen de información - Valores
--   AFIP RG 5527     Régimen de información - Criptoactivos
--   AFIP RG 3293     COTI - Operaciones Inversiones
--   AFIP RG 4838     (replaced by RG 5193)
--   BCRA Com. A 7916 Operaciones Cambiarias
--   UIF Resol. 30    PEP / AML KYC
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1213.003 Code Repositories (AFIP config)
--   CWE-200, CWE-359, CWE-532, CWE-798, CWE-256
--
-- Headline finding shapes:
--   has_password_in_config       — config cleartext.
--   has_afip_session_token       — AFIP Clave Fiscal token.
--   has_crypto_reporting         — RG 5527 crypto present.
--   has_ganancias_withholding    — income tax retention.
--   has_bienes_personales        — wealth tax data present.
--   has_high_value_threshold     — txn > $200 K USD.
--   has_cross_border_transfer    — F.8125 transfer.
--   has_pii_natural_person       — DNI+CUIT+name bundle.
--   has_cliente_cuit             — cliente CUIT detected.
--   is_credential_exposure_risk  — readable + (password OR
--                                  AFIP token OR cliente CUIT
--                                  OR PII bundle).

CREATE TABLE IF NOT EXISTS host_arg_afiprg5193 (
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
            'afip-rg5193-daily','afip-rg5527-crypto',
            'afip-coti-inversiones','afip-ganancias-retenciones',
            'afip-bienes-personales','afip-f8125-transfer',
            'afip-exteriorizacion','afip-session-token',
            'afip-config','afip-installer',
            'other','unknown'
        )),
    reporter_class              TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (reporter_class IN (
            'alyc','asegurador','sociedad-bolsa',
            'banking-custodian','fci-manager','fintech',
            'cripto-exchange','other','unknown'
        )),
    reporter_cuit_prefix        TEXT    NOT NULL DEFAULT ''
        CHECK (reporter_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    reporter_cuit_suffix4       TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    afip_token_hash             TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    transaction_count           INTEGER NOT NULL DEFAULT 0,
    crypto_transaction_count    INTEGER NOT NULL DEFAULT 0,
    total_volume_ars_cents      INTEGER NOT NULL DEFAULT 0,
    total_volume_usd_cents      INTEGER NOT NULL DEFAULT 0,
    distinct_cliente_count      INTEGER NOT NULL DEFAULT 0,
    high_value_count            INTEGER NOT NULL DEFAULT 0,
    cross_border_count          INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_afip_session_token      INTEGER NOT NULL DEFAULT 0 CHECK (has_afip_session_token IN (0,1)),
    has_crypto_reporting        INTEGER NOT NULL DEFAULT 0 CHECK (has_crypto_reporting IN (0,1)),
    has_ganancias_withholding   INTEGER NOT NULL DEFAULT 0 CHECK (has_ganancias_withholding IN (0,1)),
    has_bienes_personales       INTEGER NOT NULL DEFAULT 0 CHECK (has_bienes_personales IN (0,1)),
    has_high_value_threshold    INTEGER NOT NULL DEFAULT 0 CHECK (has_high_value_threshold IN (0,1)),
    has_cross_border_transfer   INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_border_transfer IN (0,1)),
    has_pii_natural_person      INTEGER NOT NULL DEFAULT 0 CHECK (has_pii_natural_person IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_afiprg5193_password
    ON host_arg_afiprg5193(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_afiprg5193_token
    ON host_arg_afiprg5193(file_path) WHERE has_afip_session_token = 1;

CREATE INDEX IF NOT EXISTS idx_afiprg5193_crypto
    ON host_arg_afiprg5193(reporter_cuit_prefix, reporter_cuit_suffix4, period_yyyymm) WHERE has_crypto_reporting = 1;

CREATE INDEX IF NOT EXISTS idx_afiprg5193_ganancias
    ON host_arg_afiprg5193(reporter_cuit_prefix, reporter_cuit_suffix4, period_yyyymm) WHERE has_ganancias_withholding = 1;

CREATE INDEX IF NOT EXISTS idx_afiprg5193_bienes
    ON host_arg_afiprg5193(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_bienes_personales = 1;

CREATE INDEX IF NOT EXISTS idx_afiprg5193_high_value
    ON host_arg_afiprg5193(reporter_cuit_prefix, period_yyyymm, high_value_count) WHERE has_high_value_threshold = 1;

CREATE INDEX IF NOT EXISTS idx_afiprg5193_cross_border
    ON host_arg_afiprg5193(reporter_cuit_prefix, period_yyyymm, cross_border_count) WHERE has_cross_border_transfer = 1;

CREATE INDEX IF NOT EXISTS idx_afiprg5193_pii
    ON host_arg_afiprg5193(file_path) WHERE has_pii_natural_person = 1;

CREATE INDEX IF NOT EXISTS idx_afiprg5193_cliente
    ON host_arg_afiprg5193(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_afiprg5193_exposure
    ON host_arg_afiprg5193(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_afiprg5193_drift
    ON host_arg_afiprg5193(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_afiprg5193_kind
    ON host_arg_afiprg5193(artifact_kind, reporter_class);
