-- host_afip_monotributo inventories AFIP Monotributo
-- (Régimen Simplificado para Pequeños Contribuyentes —
-- Ley 26.565, RG 4309 / RG 5544) files cached on
-- accountant / studio / contribuyente workstations.
--
-- Monotributo covers ~4 M Argentine taxpayers — every
-- file leaks the monotributista CUIT (always natural-
-- person prefix 20/23/24/27) plus their activity sector
-- (CIIU 2008) and declared income tier (categoría A–K).
--
-- Files cached on workstations:
--
--   recategorizacion_<period>_<cuit>.xml   semi-annual
--                                          category recalc
--   pago_monotributo_<period>.txt          monthly voucher
--   exclusion_monotributo_<period>.xml     exclusión notif
--                                          (graduation event)
--   categoria_<cuit>.xml                   categoría vigente
--   F184_<cuit>_<period>.xml               DDJJ adhesión
--   ingreso_anual_<period>_<cuit>.xml      annual income
--   credencial_monotributo.pdf             credential card
--
-- **The simplified-tax-regime layer.** Distinct from:
--   - iter 89  winafipwsfev1   CAE invoices (general régimen)
--   - iter 100 winafipexport   export factura E
--   - iter 114 winafipsicore   retenciones (cross-cutting)
--   - iter 116 winafipciti     CITI Compras/Ventas (IVA)
--
-- Why it matters:
--   * Monotributo CUIT is always natural-person — name-
--     linkable via AFIP padrón → direct PII.
--   * Categoría reveals declared annual income bucket:
--     Cat A ≤ ~5 M ARS, Cat K ≥ ~80 M ARS (2025 valores).
--   * Exclusión = the contribuyente exceeded thresholds
--     and is now in general régimen — graduation /
--     bankruptcy event signal.
--   * CIIU 2008 code reveals sector — combined with income
--     tier it is a powerful AML/CRS fingerprint.
--
-- Regulatory base:
--   Ley 26.565   — Régimen Simplificado
--   AFIP RG 4309 — Procedimiento monotributo
--   AFIP RG 5544 — Recategorización + multas
--   AFIP RG 4626 — Domicilio fiscal electrónico
--   AFIP Disposición 1/2024 — Tablas categoría
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 (monotributista natural-person CUIT)
--
-- Headline finding shapes:
--   has_high_category          — categoría J/K (top tiers).
--   has_exclusion              — exclusión event in file.
--   has_recent_recategorization — recategorización within
--                                 last 90 days.
--   is_credential_exposure_risk — readable file +
--                                 monotributista CUIT +
--                                 (income OR categoría).
--
-- CUIT reduced to entity-type prefix + last 4 digits.

CREATE TABLE IF NOT EXISTS host_afip_monotributo (
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
            'recategorizacion','pago-mensual',
            'exclusion-notif','categoria-vigente',
            'f184-adhesion','ingreso-anual',
            'credencial-card','other','unknown'
        )),
    monotributista_cuit_prefix  TEXT    NOT NULL DEFAULT ''
        CHECK (monotributista_cuit_prefix IN ('','20','23','24','27')),
    monotributista_cuit_suffix4 TEXT    NOT NULL DEFAULT '',
    categoria                   TEXT    NOT NULL DEFAULT ''
        CHECK (categoria IN ('','a','b','c','d','e','f','g','h','i','j','k')),
    ingreso_anual_ars_cents     INTEGER NOT NULL DEFAULT 0,
    ciiu_activity_code          TEXT    NOT NULL DEFAULT '',
    ciiu_sector_letter          TEXT    NOT NULL DEFAULT ''
        CHECK (ciiu_sector_letter IN ('','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s')),
    recategorizacion_date       TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_high_category           INTEGER NOT NULL DEFAULT 0 CHECK (has_high_category IN (0,1)),
    has_exclusion               INTEGER NOT NULL DEFAULT 0 CHECK (has_exclusion IN (0,1)),
    has_recent_recategorization INTEGER NOT NULL DEFAULT 0 CHECK (has_recent_recategorization IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_mono_high_cat
    ON host_afip_monotributo(monotributista_cuit_prefix, monotributista_cuit_suffix4) WHERE has_high_category = 1;

CREATE INDEX IF NOT EXISTS idx_mono_exclusion
    ON host_afip_monotributo(period_yyyymm) WHERE has_exclusion = 1;

CREATE INDEX IF NOT EXISTS idx_mono_recent_recat
    ON host_afip_monotributo(monotributista_cuit_prefix, monotributista_cuit_suffix4) WHERE has_recent_recategorization = 1;

CREATE INDEX IF NOT EXISTS idx_mono_exposure
    ON host_afip_monotributo(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_mono_drift
    ON host_afip_monotributo(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_mono_contrib
    ON host_afip_monotributo(monotributista_cuit_prefix, monotributista_cuit_suffix4);

CREATE INDEX IF NOT EXISTS idx_mono_sector
    ON host_afip_monotributo(ciiu_sector_letter, categoria);
