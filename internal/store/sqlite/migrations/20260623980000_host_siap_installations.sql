-- host_siap_installations inventories Argentine S.I.Ap
-- (Sistema Integrado de Aplicaciones AFIP) deployments on
-- Windows accounting workstations. SIAP is the legacy 32-bit
-- Foxpro VFP9 application stack every contador uses to file
-- the formal AFIP forms that aren't covered by the modern
-- web-only "Mis Aplicaciones" portal: F.931 (sueldos),
-- Ganancias Personas Físicas, Mis Aportes, Bienes Personales,
-- Convenio Multilateral CM05, F.184 (autónomos), etc.
--
-- The deployment shape is well-known and identical across
-- every host:
--
--   C:\Archivos de programa\S.I.Ap\
--     Aplicaciones\<APP-NAME>\
--       <CUIT-SUBDIR>\
--         *.dat  *.dbf  *.cdx  *.idx  *.fpt
--
-- Each per-CUIT subdir holds the local Foxpro tables for one
-- legal entity. Workstations belonging to estudios contables
-- (service bureaus) carry dozens of CUIT subdirs — the
-- multi-tenancy itself is the discovery signal.
--
-- Capital-flow / Tax context:
--   T1083    File and Directory Discovery — pre-attack enum
--   T1213    Data from Information Repositories — local
--            Foxpro tables hold payroll PII, employee CUIL,
--            withholding history, asset declarations
--   CWE-200, CWE-359, CWE-732 (PII exposure on disk)
--   AFIP RG 3744 — Régimen Informativo F.931
--   Ley 25.326 — Protección de Datos Personales
--
-- Headline finding shapes:
--   is_legacy_siap        — directory matches the SIAP shape.
--                          SIAP is EOL-class software; AFIP is
--                          actively migrating users off.
--   has_multiple_cuit_subdirs — application directory holds
--                          MORE than one CUIT subdir. Indicates
--                          a service-bureau host, dramatically
--                          expanding blast radius.
--   is_payroll_data       — application is F.931 or another
--                          payroll-class app (HR PII).
--   is_recently_modified  — at least one data file modified in
--                          the last 90 days (active vs
--                          abandoned install).
--   is_credential_exposure_risk — readable data dir + payroll
--                          or asset-declaration app.
--
-- CUIT is NEVER stored verbatim — only the entity-type prefix
-- (20/23/24/27/30/33/34) and the last 4 digits.

CREATE TABLE IF NOT EXISTS host_siap_installations (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    install_root                TEXT    NOT NULL,
    application_dir             TEXT    NOT NULL,
    cuit_dir                    TEXT    NOT NULL DEFAULT '',
    dir_mode                    INTEGER NOT NULL DEFAULT 0,
    dir_owner_uid               INTEGER NOT NULL DEFAULT 0,
    application_name            TEXT    NOT NULL DEFAULT '',
    application_category        TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (application_category IN (
            'payroll','income-tax','autonomos','conv-multilateral',
            'bienes-personales','mis-aportes','iva','retenciones',
            'other','unknown'
        )),
    cuit_entity_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (cuit_entity_prefix IN ('','20','23','24','27','30','33','34')),
    cuit_suffix4                TEXT    NOT NULL DEFAULT '',
    data_files_count            INTEGER NOT NULL DEFAULT 0,
    dat_files_count             INTEGER NOT NULL DEFAULT 0,
    dbf_files_count             INTEGER NOT NULL DEFAULT 0,
    last_modified               TEXT    NOT NULL DEFAULT '',
    is_legacy_siap              INTEGER NOT NULL DEFAULT 0 CHECK (is_legacy_siap IN (0,1)),
    has_multiple_cuit_subdirs   INTEGER NOT NULL DEFAULT 0 CHECK (has_multiple_cuit_subdirs IN (0,1)),
    is_payroll_data             INTEGER NOT NULL DEFAULT 0 CHECK (is_payroll_data IN (0,1)),
    is_recently_modified        INTEGER NOT NULL DEFAULT 0 CHECK (is_recently_modified IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_siap_payroll
    ON host_siap_installations(application_name) WHERE is_payroll_data = 1;

CREATE INDEX IF NOT EXISTS idx_siap_multi_tenant
    ON host_siap_installations(application_dir) WHERE has_multiple_cuit_subdirs = 1;

CREATE INDEX IF NOT EXISTS idx_siap_exposure
    ON host_siap_installations(application_dir) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_siap_entity
    ON host_siap_installations(cuit_entity_prefix, cuit_suffix4);
