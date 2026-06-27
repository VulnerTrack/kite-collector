-- host_arg_sintesis inventories Sintesis Sistemas FCI back-
-- office artifact files cached on Argentine sociedad-gerente,
-- sociedad-depositaria, ops-administrator, and FCI compliance-
-- officer workstations.
--
-- Sintesis Sistemas is the **leading AR FCI back-office
-- software vendor** (no global equivalent — it is essentially
-- the de-facto AR FCI accounting / NAV-calculation system).
-- Its core modules are:
--
--   - Sintesis ALV (Administrador de Valores)
--     FCI accounting engine: cuotaparte ledger, NAV calc,
--     valuation inputs, daily VC (valor de cuotaparte).
--   - Sintesis SGI (Sistema de Gestión Integral)
--     Full back-office: suscripción / rescate processing,
--     BCRA / CNV reporting, pago de rescate, AML.
--
-- Sintesis distinctive surfaces:
--
--   - .sdb / .mdb        proprietary Access-style FCI DB.
--   - <fci>_<dt>.nav     daily NAV (valor de cuotaparte).
--   - cuotaparte_<dt>.csv per-cuotapartista holdings ledger.
--   - suscripcion_<dt>.csv subscription requests.
--   - rescate_<dt>.csv    redemption requests.
--   - bcra_a5273_<dt>.txt BCRA FCI composition report.
--   - cnv_hr_<dt>.xml     CNV Hecho Relevante AIF submit.
--   - valuacion_<dt>.csv  asset-valuation input.
--   - pago_rescate_<dt>.txt BCRA settlement file.
--   - sintesis.cfg        global cfg (DB conn string).
--
-- **The AR FCI back-office software layer.** Distinct from:
--
--   - iter 110 winargfci         — FCI mutual-fund market
--                                  layer (CNV side).
--   - iter 112 winargcvsa        — CVSA custody (depository).
--   - iter 158 winargprismaweb   — BYMA equity clearing.
--   - iter 174 winargbcrasiscen  — BCRA SISCEN (securities
--                                  transaction reporting).
--   - iter 164 winargallaria     — Allaria FCI manager (one
--                                  of Sintesis's clients).
--
-- Workstation cache footprint (typical):
--
--   C:\Sintesis\                          install root
--   C:\Sintesis\ALV\                      ALV module
--   C:\Sintesis\SGI\                      SGI module
--   C:\Sintesis\Data\<fci>.sdb            per-FCI database
--   C:\Sintesis\Reportes\<YYYY>\          per-year reports
--   C:\Sintesis\NAV\<YYYYMMDD>\<fci>.nav  daily NAV
--   C:\Sintesis\Cuotapartes\              cuotaparte ledgers
--   C:\Sintesis\BCRA\a5273_<dt>.txt       BCRA composition
--   C:\Sintesis\CNV\hr_<dt>.xml           CNV Hecho Relevante
--   C:\Sintesis\sintesis.cfg              global cfg
--   %APPDATA%\Sintesis\                   user data
--   ~/.sintesis/                          cross-platform
--
-- Sintesis-specific risk signals:
--
--   * Cleartext password / DB connection-string in
--     sintesis.cfg = T1552 + CNV RG 1023.
--   * .sdb / .mdb DB file readable = full FCI ledger dump
--     (cuotapartistas, holdings, AML, valuation) — high-tier
--     PII + market-sensitive data.
--   * Daily NAV pre-publication = potential insider-info
--     surface (CNV RG 622 art. 117 secreto bursátil).
--   * Cuotaparte ledger export with > 10 cuotapartistas =
--     full subscriber roster (Ley 25.326 PII bundle).
--   * Suscripción / rescate file = client cash-flow intent
--     (UIF Resol. 30 PEP screening trigger if > USD 50 K).
--   * BCRA A5273 report = FCI investment composition (BCRA
--     regulatory-info; pre-submission exposure = compliance
--     timing concern).
--   * CNV HR (Hecho Relevante) draft = unfiled material info
--     (CNV RG 622 art. 105 + art. 117 if pre-publication).
--   * Pago de rescate settlement file = BCRA SIPAP settlement
--     authority (T1565 data manipulation surface).
--   * High AUM > USD 10 M = AFIP RG 5193 + BCRA cross-checks.
--   * Foreign-resident cuotapartista (55-prefix CUIT) =
--     AFIP F.8125 + BCRA Com. A 7916 monitoring.
--   * Concentrated cuotaparte (single holder > 50 %) =
--     CNV RG 622 art. 36 risk-disclosure flag.
--
-- Regulatory base:
--
--   Ley 24.083       Fondos Comunes de Inversión
--   Ley 26.831       Mercado de Capitales
--   Ley 25.326       Datos Personales
--   Ley 25.246       PLA/FT
--   CNV RG 622 Tit.VIII FCI régimen general
--   CNV RG 622 art.105 Hecho Relevante
--   CNV RG 622 art.117 Secreto bursátil
--   CNV RG 731       Régimen de Agentes
--   CNV RG 1023      Ciberresiliencia
--   BCRA Com. A 5273 FCI Régimen Informativo
--   BCRA Com. A 7916 Operaciones cambiarias
--   BCRA Com. A 8005 Ciberseguridad financiera
--   AFIP RG 5193     Securities tax reporting
--   UIF Resol. 30    PEP / AML KYC
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1565    Data Manipulation
--   T1530    Data from Cloud Storage Object
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config        — cfg cleartext.
--   has_db_credentials            — DB connection string.
--   has_nav_calc_data             — daily NAV (valor cuota).
--   has_cuotaparte_ledger         — per-subscriber ledger.
--   has_suscripcion_record        — subscription request.
--   has_rescate_record            — redemption request.
--   has_bcra_a5273_report         — BCRA FCI composition.
--   has_cnv_hr_filing             — CNV Hecho Relevante.
--   has_pago_rescate              — BCRA settlement file.
--   has_high_aum                  — FCI > USD 10 M.
--   has_cliente_cuit_export       — full subscriber roster.
--   has_foreign_resident          — non-AR cuotapartista.
--   has_concentrated_cuotaparte   — single > 50 % holder.
--   has_pii_bundle                — ≥2 of (DNI, CUIT, name).
--   is_credential_exposure_risk   — readable + (password OR
--                                   DB creds OR cuotaparte
--                                   ledger OR HR draft OR
--                                   cliente CUIT bundle).

CREATE TABLE IF NOT EXISTS host_arg_sintesis (
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
            'sintesis-config','sintesis-credentials',
            'sintesis-fci-database',
            'sintesis-nav-calc','sintesis-cuotaparte-ledger',
            'sintesis-suscripcion','sintesis-rescate',
            'sintesis-bcra-a5273','sintesis-cnv-hr',
            'sintesis-valuation-file','sintesis-pago-rescate',
            'sintesis-installer','other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'sociedad-gerente','sociedad-depositaria',
            'compliance-officer','ops-administrator',
            'api','demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'fci-money-market','fci-renta-fija',
            'fci-renta-variable','fci-mixto',
            'fci-pyme','fci-infrastructure',
            'multi-fci','other','unknown'
        )),
    fci_code                    TEXT    NOT NULL DEFAULT '',
    sociedad_gerente_cuit       TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    cliente_dni_hash            TEXT    NOT NULL DEFAULT '',
    db_conn_hash                TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    reporting_date              TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    cuotapartista_count         INTEGER NOT NULL DEFAULT 0,
    distinct_fcis_count         INTEGER NOT NULL DEFAULT 0,
    nav_ars_cents               INTEGER NOT NULL DEFAULT 0,
    aum_usd_cents               INTEGER NOT NULL DEFAULT 0,
    suscripcion_count           INTEGER NOT NULL DEFAULT 0,
    rescate_count               INTEGER NOT NULL DEFAULT 0,
    max_holder_pct              INTEGER NOT NULL DEFAULT 0,
    pii_signal_count            INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_db_credentials          INTEGER NOT NULL DEFAULT 0 CHECK (has_db_credentials IN (0,1)),
    has_nav_calc_data           INTEGER NOT NULL DEFAULT 0 CHECK (has_nav_calc_data IN (0,1)),
    has_cuotaparte_ledger       INTEGER NOT NULL DEFAULT 0 CHECK (has_cuotaparte_ledger IN (0,1)),
    has_suscripcion_record      INTEGER NOT NULL DEFAULT 0 CHECK (has_suscripcion_record IN (0,1)),
    has_rescate_record          INTEGER NOT NULL DEFAULT 0 CHECK (has_rescate_record IN (0,1)),
    has_bcra_a5273_report       INTEGER NOT NULL DEFAULT 0 CHECK (has_bcra_a5273_report IN (0,1)),
    has_cnv_hr_filing           INTEGER NOT NULL DEFAULT 0 CHECK (has_cnv_hr_filing IN (0,1)),
    has_pago_rescate            INTEGER NOT NULL DEFAULT 0 CHECK (has_pago_rescate IN (0,1)),
    has_high_aum                INTEGER NOT NULL DEFAULT 0 CHECK (has_high_aum IN (0,1)),
    has_cliente_cuit_export     INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit_export IN (0,1)),
    has_foreign_resident        INTEGER NOT NULL DEFAULT 0 CHECK (has_foreign_resident IN (0,1)),
    has_concentrated_cuotaparte INTEGER NOT NULL DEFAULT 0 CHECK (has_concentrated_cuotaparte IN (0,1)),
    has_pii_bundle              INTEGER NOT NULL DEFAULT 0 CHECK (has_pii_bundle IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_sintesis_password
    ON host_arg_sintesis(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_sintesis_db_creds
    ON host_arg_sintesis(file_path) WHERE has_db_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_sintesis_nav
    ON host_arg_sintesis(fci_code, reporting_date) WHERE has_nav_calc_data = 1;

CREATE INDEX IF NOT EXISTS idx_sintesis_cuotaparte
    ON host_arg_sintesis(fci_code, reporting_date) WHERE has_cuotaparte_ledger = 1;

CREATE INDEX IF NOT EXISTS idx_sintesis_suscripcion
    ON host_arg_sintesis(fci_code, reporting_date) WHERE has_suscripcion_record = 1;

CREATE INDEX IF NOT EXISTS idx_sintesis_rescate
    ON host_arg_sintesis(fci_code, reporting_date) WHERE has_rescate_record = 1;

CREATE INDEX IF NOT EXISTS idx_sintesis_bcra_a5273
    ON host_arg_sintesis(sociedad_gerente_cuit, reporting_date) WHERE has_bcra_a5273_report = 1;

CREATE INDEX IF NOT EXISTS idx_sintesis_cnv_hr
    ON host_arg_sintesis(fci_code, reporting_date) WHERE has_cnv_hr_filing = 1;

CREATE INDEX IF NOT EXISTS idx_sintesis_pago_rescate
    ON host_arg_sintesis(fci_code, reporting_date) WHERE has_pago_rescate = 1;

CREATE INDEX IF NOT EXISTS idx_sintesis_high_aum
    ON host_arg_sintesis(fci_code, aum_usd_cents) WHERE has_high_aum = 1;

CREATE INDEX IF NOT EXISTS idx_sintesis_foreign
    ON host_arg_sintesis(fci_code, reporting_date) WHERE has_foreign_resident = 1;

CREATE INDEX IF NOT EXISTS idx_sintesis_concentrated
    ON host_arg_sintesis(fci_code, max_holder_pct) WHERE has_concentrated_cuotaparte = 1;

CREATE INDEX IF NOT EXISTS idx_sintesis_pii
    ON host_arg_sintesis(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_pii_bundle = 1;

CREATE INDEX IF NOT EXISTS idx_sintesis_exposure
    ON host_arg_sintesis(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_sintesis_drift
    ON host_arg_sintesis(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_sintesis_kind
    ON host_arg_sintesis(artifact_kind, account_class);
