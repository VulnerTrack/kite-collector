-- host_anses_cache inventories Argentine ANSES (Administración
-- Nacional de la Seguridad Social) consultation cache + audit-
-- log files on KYC / payroll / NGO / banking workstations.
--
-- ANSES holds the natural-person social-security identity:
--
--   CUIL → {aportes y contribuciones, grupo familiar,
--           dependientes, AUH (Asignación Universal por Hijo),
--           jubilación / pensiones, planes sociales,
--           Mi-Anses portal data}
--
-- Banks, NGOs, payroll providers (cf. iter 91 SIAP F.931,
-- iter 92 Tango Sueldos) query ANSES for employee CUIL
-- verification, dependent count, AUH status (means-tested),
-- jubilación / pension status (credit applications).
--
-- **Pairs with iter 103 RENAPER on the natural-person
-- identity axis.** RENAPER = civil registry; ANSES = social-
-- security identity + benefit eligibility. Together they
-- form the bottom of the natural-person identity chain.
--
-- Sensitivity tiers:
--
--   - Child dependents in grupo familiar → Ley 26.061
--     (child PII protection)
--   - AUH / means-tested status → socioeconomic-sensitive
--     PII (Ley 25.326 + 27.275 access-to-info exception)
--   - Jubilados / pensionados → financially-vulnerable cohort
--
-- Regulatory base:
--   Ley 24.241 — Sistema Integrado de Jubilaciones
--   Ley 26.061 — Protección Integral NNyA
--   Ley 25.326 — Protección de Datos Personales
--   ANSES Res. 9-E/2017 — Protocolo de consulta
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   CWE-200, CWE-359, CWE-732
--
-- Headline finding shapes:
--   has_grupo_familiar      — file lists dependent persons
--                              (family group).
--   has_minor_dependent     — at least one dependent's fecha
--                              de nacimiento puts age < 18.
--                              Ley 26.061 child tier.
--   has_auh_status          — AUH / Asignación Universal /
--                              plan social field present.
--                              Means-tested socioeconomic PII.
--   has_jubilacion_status   — jubilación / pension field
--                              present.
--   is_audit_log            — transactional log of CUIL
--                              consultations.
--   is_credential_exposure_risk — readable file + ANY
--                              consultation kind = natural-
--                              person social-security breach.
--
-- CUILs NEVER stored verbatim — only entity-type prefix
-- (20/23/24/27 for personas físicas) + last 4 digits.
-- Names, addresses, child dependents' DNIs NEVER stored.

CREATE TABLE IF NOT EXISTS host_anses_cache (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    consultation_kind           TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (consultation_kind IN (
            'cuil-individual','cuil-batch','audit-log',
            'aportes-historial','grupo-familiar','auh-status',
            'jubilacion-status','padron','other','unknown'
        )),
    target_cuil_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (target_cuil_prefix IN ('','20','23','24','27')),
    target_cuil_suffix4         TEXT    NOT NULL DEFAULT '',
    consultation_count          INTEGER NOT NULL DEFAULT 0,
    dependent_count             INTEGER NOT NULL DEFAULT 0,
    earliest_consultation       TEXT    NOT NULL DEFAULT '',
    latest_consultation         TEXT    NOT NULL DEFAULT '',
    fecha_acceso                TEXT    NOT NULL DEFAULT '',
    has_grupo_familiar          INTEGER NOT NULL DEFAULT 0 CHECK (has_grupo_familiar IN (0,1)),
    has_minor_dependent         INTEGER NOT NULL DEFAULT 0 CHECK (has_minor_dependent IN (0,1)),
    has_auh_status              INTEGER NOT NULL DEFAULT 0 CHECK (has_auh_status IN (0,1)),
    has_jubilacion_status       INTEGER NOT NULL DEFAULT 0 CHECK (has_jubilacion_status IN (0,1)),
    has_aportes_historial       INTEGER NOT NULL DEFAULT 0 CHECK (has_aportes_historial IN (0,1)),
    is_audit_log                INTEGER NOT NULL DEFAULT 0 CHECK (is_audit_log IN (0,1)),
    is_batch                    INTEGER NOT NULL DEFAULT 0 CHECK (is_batch IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_anses_grupo_familiar
    ON host_anses_cache(file_path) WHERE has_grupo_familiar = 1;

CREATE INDEX IF NOT EXISTS idx_anses_minor
    ON host_anses_cache(file_path) WHERE has_minor_dependent = 1;

CREATE INDEX IF NOT EXISTS idx_anses_auh
    ON host_anses_cache(file_path) WHERE has_auh_status = 1;

CREATE INDEX IF NOT EXISTS idx_anses_audit
    ON host_anses_cache(file_path) WHERE is_audit_log = 1;

CREATE INDEX IF NOT EXISTS idx_anses_exposure
    ON host_anses_cache(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_anses_drift
    ON host_anses_cache(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_anses_entity
    ON host_anses_cache(target_cuil_prefix, target_cuil_suffix4);
