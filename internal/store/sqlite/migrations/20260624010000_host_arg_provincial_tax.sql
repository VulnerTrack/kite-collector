-- host_arg_provincial_tax inventories Argentine provincial
-- tax agency local-cache files on Windows accounting
-- workstations. Beyond AFIP-national, every empresa files
-- province-level Ingresos Brutos + retención/percepción
-- regimes with one or more of:
--
--   ARBA   — Buenos Aires
--   AGIP   — Ciudad Autónoma de Buenos Aires
--   API    — Santa Fe
--   DGR-Cordoba, DGR-Mendoza, DGR-Misiones, etc.
--
-- The agencies expose flat-file exports the local accounting
-- software produces and re-uploads:
--
--   CITI Ventas / CITI Compras  — IVA libros (RG 1361)
--   SICORE Retenciones          — RG 830 detail
--   Padrón IIBB                  — alícuotas per CUIT
--   Alícuotas CSV                — provincial rate tables
--   CM05 Convenio Multilateral   — inter-provincial allocation
--
-- These files carry recipient CUITs, importes, and retention
-- amounts — PII under Ley 25.326 + sensitive tax data.
--
-- Capital-flow & PII context:
--   T1083    File and Directory Discovery
--   T1213    Data from Information Repositories
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326, AFIP RG 830/1361, ARBA DN 1/2004
--
-- Headline finding shapes:
--   is_high_value_file   — file size > 1 MiB (operative
--                          retention export, not a header stub).
--   is_world_readable / is_group_readable
--   is_credential_exposure_risk — readable file + sensitive
--                          file_kind (retention or IIBB padrón).

CREATE TABLE IF NOT EXISTS host_arg_provincial_tax (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    agency                      TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (agency IN (
            'arba','agip','api','dgr-cordoba','dgr-mendoza',
            'dgr-misiones','afip','other','unknown'
        )),
    file_kind                   TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (file_kind IN (
            'citi-ventas','citi-compras','sicore-retenciones',
            'sicore-percepciones','padron-iibb','alicuotas',
            'cm05','iibb-declaracion','other','unknown'
        )),
    cuit_entity_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (cuit_entity_prefix IN ('','20','23','24','27','30','33','34')),
    cuit_suffix4                TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    record_count                INTEGER NOT NULL DEFAULT 0,
    last_modified               TEXT    NOT NULL DEFAULT '',
    is_high_value_file          INTEGER NOT NULL DEFAULT 0 CHECK (is_high_value_file IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_arg_prov_agency
    ON host_arg_provincial_tax(agency, file_kind);

CREATE INDEX IF NOT EXISTS idx_arg_prov_exposure
    ON host_arg_provincial_tax(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_arg_prov_drift
    ON host_arg_provincial_tax(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_arg_prov_entity
    ON host_arg_provincial_tax(cuit_entity_prefix, cuit_suffix4);
