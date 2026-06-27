-- host_afip_suss inventories AFIP SUSS / SICOSS F931
-- (Sistema Único de la Seguridad Social — RG 3.834,
-- 5.430) cargas-sociales DDJJ files cached on payroll,
-- contador, and RRHH workstations.
--
-- Every Argentine employer files F931 monthly listing every
-- CUIL on payroll with remuneración, obra social code, and
-- convenio colectivo. A leaked F931 = full employee roster
-- + salary list + obra social PII — high-impact disclosure.
--
-- Files cached on workstations:
--
--   F931_<period>_<cuit>.xml          monthly DDJJ
--   SICOSS_<period>_<cuit>.txt        SICOSS aplicativo dump
--   nomina_empleados_<period>.csv     full employee roster
--   sicoss_aporte_<period>.csv        aporte detail per CUIL
--   ddjj_obrasocial_<period>.xml      obra social adhesion
--   sicoss_relacion_laboral_<id>.xml  relación laboral
--
-- **The payroll cargas-sociales layer.** Distinct from:
--   - iter 89  winafipwsfev1     CAE invoices
--   - iter 114 winafipsicore     SICORE retención agent
--   - iter 116 winafipciti       CITI Compras/Ventas (IVA)
--   - iter 117 winafipmonotributo Monotributo simplified
--   - iter 119 winafipsiradig    SIRADIG empleado-side
--
-- Why this matters:
--   * Every CUIL on the file is name-linkable via ANSES /
--     AFIP padrón → direct PII (Ley 25.326).
--   * Remuneración bruta enables salary-tier inference.
--   * Obra social code reveals workforce sector + private
--     vs sindicato health-plan election.
--   * Convenio colectivo identifies the employer's industry.
--
-- Regulatory base:
--   AFIP RG 3.834 — SICOSS / F931 régimen general
--   AFIP RG 5.430 — Régimen actual cargas sociales
--   Ley 24.241   — Sistema Integrado Previsional Argentino
--   Ley 24.557   — Riesgos del Trabajo
--   Ley 23.660   — Obras sociales
--   Ley 25.326   — Protección de Datos Personales
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information (payroll dump)
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 (CUIL natural-person)
--
-- Headline finding shapes:
--   has_large_payroll         — empleados_count > 100 OR
--                               total_remuneracion > 500 M ARS.
--   has_high_remuneration     — max remuneración > 5x MNI.
--   has_obrasocial_data       — obra social code on file.
--   is_credential_exposure_risk — readable file + empleador
--                               + empleados detail.
--
-- All CUITs reduced to entity-type prefix + last 4 digits.

CREATE TABLE IF NOT EXISTS host_afip_suss (
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
            'f931-jubilatoria','sicoss-aplicativo',
            'nomina-empleados','aporte-detalle',
            'ddjj-obrasocial','relacion-laboral',
            'other','unknown'
        )),
    empleador_cuit_prefix       TEXT    NOT NULL DEFAULT ''
        CHECK (empleador_cuit_prefix IN ('','30','33','34')),
    empleador_cuit_suffix4      TEXT    NOT NULL DEFAULT '',
    empleados_count             INTEGER NOT NULL DEFAULT 0,
    max_remuneracion_ars_cents  INTEGER NOT NULL DEFAULT 0,
    total_remuneracion_ars_cents INTEGER NOT NULL DEFAULT 0,
    obrasocial_codes_count      INTEGER NOT NULL DEFAULT 0,
    convenio_colectivo          TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_large_payroll           INTEGER NOT NULL DEFAULT 0 CHECK (has_large_payroll IN (0,1)),
    has_high_remuneration       INTEGER NOT NULL DEFAULT 0 CHECK (has_high_remuneration IN (0,1)),
    has_obrasocial_data         INTEGER NOT NULL DEFAULT 0 CHECK (has_obrasocial_data IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_suss_large_payroll
    ON host_afip_suss(empleador_cuit_prefix, empleador_cuit_suffix4, period_yyyymm) WHERE has_large_payroll = 1;

CREATE INDEX IF NOT EXISTS idx_suss_high_rem
    ON host_afip_suss(empleador_cuit_prefix, empleador_cuit_suffix4) WHERE has_high_remuneration = 1;

CREATE INDEX IF NOT EXISTS idx_suss_obrasocial
    ON host_afip_suss(empleador_cuit_prefix, empleador_cuit_suffix4) WHERE has_obrasocial_data = 1;

CREATE INDEX IF NOT EXISTS idx_suss_exposure
    ON host_afip_suss(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_suss_drift
    ON host_afip_suss(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_suss_empleador
    ON host_afip_suss(empleador_cuit_prefix, empleador_cuit_suffix4, period_yyyymm);

CREATE INDEX IF NOT EXISTS idx_suss_convenio
    ON host_afip_suss(convenio_colectivo, period_yyyymm);
