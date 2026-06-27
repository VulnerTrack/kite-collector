-- host_renaper_cache inventories Argentine RENAPER (Registro
-- Nacional de las Personas) consultation cache + audit-log
-- files on KYC / compliance / onboarding workstations.
--
-- RENAPER is the national civil registry. Every empresa doing
-- KYC, banking onboarding, mobile-phone signup, e-signature,
-- or AML / UBO verification (cf. iter 98) queries RENAPER for
-- natural-person identity:
--
--   DNI → {nombre, apellido, fecha_nacimiento, sexo,
--          nacionalidad, estado_civil, domicilio, foto,
--          biometría (huellas)}
--
-- SDKs cache the responses on disk AND emit transactional
-- audit logs so the empresa can prove who they queried (for
-- AFIP / UIF / RENAPER auditing).
--
-- **The most-sensitive PII class in the catalogue.**
-- RENAPER data exposure is direct natural-person identity
-- breach with criminal exposure under:
--
--   Ley 25.326 — Protección de Datos Personales
--   Ley 26.951 — Registro Nacional "No Llame" / acceso indebido
--   Ley 26.061 — Protección Integral de Derechos de Niñas,
--                Niños y Adolescentes (child data tier)
--   Decreto 1501/2009 — DNI digital
--   RENAPER Disp. SDN-2017/3 — protocolos consulta
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1565.001 Stored Data Manipulation
--   CWE-200, CWE-359, CWE-732
--   GDPR Art. 9 equivalent (biometric)
--
-- Headline finding shapes:
--   has_photo                — fotografía DNI cached on disk.
--                              Highest Ley 25.326 tier.
--   has_biometric            — huella dactilar / iris / firma
--                              digital cached. Ley 26.951
--                              biometric-data protection.
--   consultation_count       — for batch / audit log files,
--                              number of distinct queries.
--                              Materially raises blast radius
--                              when log + cached files coexist.
--   is_audit_log             — file is a transactional log
--                              (per-query records).
--   is_credential_exposure_risk — readable file + ANY consultation
--                              kind. The audit pipeline treats
--                              this as the highest-severity flag
--                              in the entire collector suite.
--
-- DNIs are NEVER stored verbatim — only the trailing 4 digits.
-- Names, addresses, photos, biometrics are NEVER stored —
-- only presence booleans.

CREATE TABLE IF NOT EXISTS host_renaper_cache (
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
            'dni-individual','dni-batch','audit-log',
            'photo-cache','biometric','other','unknown'
        )),
    target_dni_suffix4          TEXT    NOT NULL DEFAULT '',
    consultation_count          INTEGER NOT NULL DEFAULT 0,
    earliest_consultation       TEXT    NOT NULL DEFAULT '',
    latest_consultation         TEXT    NOT NULL DEFAULT '',
    fecha_acceso                TEXT    NOT NULL DEFAULT '',
    has_photo                   INTEGER NOT NULL DEFAULT 0 CHECK (has_photo IN (0,1)),
    has_biometric               INTEGER NOT NULL DEFAULT 0 CHECK (has_biometric IN (0,1)),
    has_domicilio               INTEGER NOT NULL DEFAULT 0 CHECK (has_domicilio IN (0,1)),
    is_audit_log                INTEGER NOT NULL DEFAULT 0 CHECK (is_audit_log IN (0,1)),
    is_batch                    INTEGER NOT NULL DEFAULT 0 CHECK (is_batch IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_renaper_photo
    ON host_renaper_cache(file_path) WHERE has_photo = 1;

CREATE INDEX IF NOT EXISTS idx_renaper_biometric
    ON host_renaper_cache(file_path) WHERE has_biometric = 1;

CREATE INDEX IF NOT EXISTS idx_renaper_batch
    ON host_renaper_cache(consultation_count) WHERE is_batch = 1;

CREATE INDEX IF NOT EXISTS idx_renaper_audit
    ON host_renaper_cache(file_path) WHERE is_audit_log = 1;

CREATE INDEX IF NOT EXISTS idx_renaper_exposure
    ON host_renaper_cache(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_renaper_drift
    ON host_renaper_cache(file_path, file_hash);
