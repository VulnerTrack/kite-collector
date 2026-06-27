-- host_afip_siradig inventories AFIP SIRADIG F572 (Régimen
-- de Retención del Impuesto a las Ganancias 4ta categoría —
-- RG 4003 / RG 4396) files cached on payroll, contador, and
-- employee workstations.
--
-- Every employee subject to ganancias withholding submits
-- monthly/semi-annual SIRADIG declarations. The per-empleado
-- file carries the densest natural-person PII set in the
-- AFIP catalog:
--
--   SIRADIG_<cuit>_<period>.xml           main form
--   F572_<cuit>_<period>.xml              monthly DDJJ
--   siradig_dependientes_<period>.xml     children + cónyuge
--   siradig_alquiler_<period>.xml         rent + landlord CUIT
--   siradig_credito_hipotecario_<period>  mortgage + bank CUIT
--   siradig_gastos_medicos_<period>.xml   medical expenses
--   siradig_donaciones_<period>.xml       donaciones
--   siradig_gastos_educativos_<period>    education expenses
--
-- **The 4ta-categoría natural-person declaration layer.**
-- Distinct from:
--   - iter 89  winafipwsfev1     CAE invoices
--   - iter 114 winafipsicore     SICORE / SIRE retención agent
--   - iter 116 winafipciti       CITI Compras/Ventas
--   - iter 117 winafipmonotributo Monotributo simplified
--
-- Why this is sensitive:
--   * Empleado CUIT is always natural person (Ley 25.326).
--   * Dependientes file = full family-tree CUITs (children,
--     cónyuge) — material for civil-state inference.
--   * Alquiler / mortgage carries landlord/bank CUIT + ARS
--     monthly amount — domicile + economic surface.
--   * Gastos médicos may include obra social padrón data.
--
-- Regulatory base:
--   AFIP RG 4003 — Retención ganancias 4ta cat
--   AFIP RG 4396 — Régimen complementario
--   Ley 20.628  — Impuesto a las Ganancias
--   Ley 27.430  — Reforma Tributaria
--   Ley 25.326  — Protección de Datos Personales
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information (PII roster)
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 (empleado + dependiente CUIT)
--
-- Headline finding shapes:
--   has_dependientes_pii       — dependientes_count > 0.
--   has_conyuge                — cónyuge CUIT present.
--   has_alquiler               — alquiler file or landlord CUIT.
--   has_high_deduction         — total deductions > 30 % MNI.
--                                MNI heuristic: 5 M ARS (2025).
--   is_credential_exposure_risk — readable file + empleado
--                                CUIT + (dependientes OR
--                                alquiler OR high-deduction).
--
-- All CUITs reduced to entity-type prefix + last 4 digits.

CREATE TABLE IF NOT EXISTS host_afip_siradig (
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
            'siradig-f572','f572-monthly',
            'dependientes','alquiler',
            'credito-hipotecario','gastos-medicos',
            'donaciones','gastos-educativos',
            'other','unknown'
        )),
    empleado_cuit_prefix        TEXT    NOT NULL DEFAULT ''
        CHECK (empleado_cuit_prefix IN ('','20','23','24','27')),
    empleado_cuit_suffix4       TEXT    NOT NULL DEFAULT '',
    empleador_cuit_prefix       TEXT    NOT NULL DEFAULT ''
        CHECK (empleador_cuit_prefix IN ('','30','33','34')),
    empleador_cuit_suffix4      TEXT    NOT NULL DEFAULT '',
    dependientes_count          INTEGER NOT NULL DEFAULT 0,
    conyuge_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (conyuge_cuit_prefix IN ('','20','23','24','27')),
    conyuge_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    alquiler_ars_cents          INTEGER NOT NULL DEFAULT 0,
    landlord_cuit_prefix        TEXT    NOT NULL DEFAULT ''
        CHECK (landlord_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    landlord_cuit_suffix4       TEXT    NOT NULL DEFAULT '',
    deducciones_total_ars_cents INTEGER NOT NULL DEFAULT 0,
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_dependientes_pii        INTEGER NOT NULL DEFAULT 0 CHECK (has_dependientes_pii IN (0,1)),
    has_conyuge                 INTEGER NOT NULL DEFAULT 0 CHECK (has_conyuge IN (0,1)),
    has_alquiler                INTEGER NOT NULL DEFAULT 0 CHECK (has_alquiler IN (0,1)),
    has_high_deduction          INTEGER NOT NULL DEFAULT 0 CHECK (has_high_deduction IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_siradig_dependientes
    ON host_afip_siradig(empleado_cuit_prefix, empleado_cuit_suffix4) WHERE has_dependientes_pii = 1;

CREATE INDEX IF NOT EXISTS idx_siradig_conyuge
    ON host_afip_siradig(empleado_cuit_prefix, empleado_cuit_suffix4) WHERE has_conyuge = 1;

CREATE INDEX IF NOT EXISTS idx_siradig_alquiler
    ON host_afip_siradig(landlord_cuit_prefix, landlord_cuit_suffix4) WHERE has_alquiler = 1;

CREATE INDEX IF NOT EXISTS idx_siradig_high_ded
    ON host_afip_siradig(empleado_cuit_prefix, empleado_cuit_suffix4, period_yyyymm) WHERE has_high_deduction = 1;

CREATE INDEX IF NOT EXISTS idx_siradig_exposure
    ON host_afip_siradig(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_siradig_drift
    ON host_afip_siradig(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_siradig_empleado
    ON host_afip_siradig(empleado_cuit_prefix, empleado_cuit_suffix4, period_yyyymm);

CREATE INDEX IF NOT EXISTS idx_siradig_empleador
    ON host_afip_siradig(empleador_cuit_prefix, empleador_cuit_suffix4, period_yyyymm);
