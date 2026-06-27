-- host_tango_empresas inventories per-empresa data dirs of
-- Argentine commercial ERP packages on Windows accounting
-- workstations. The dominant vendors:
--
--   - Tango Gestión   (Axoft)       — `C:\Tango\`,    `C:\Axoft\`
--   - Bejerman / TANGO Astor        — `C:\Bejerman\`, `C:\Astor\`
--
-- Both follow the same shape:
--
--   <install>\Empresas\<EMPRESA-NAME>\
--     Sueldos\        (HR / payroll PII)
--     Ventas\         (sales)
--     Compras\        (purchases)
--     Contabilidad\   (general ledger)
--     Stock\          (inventory)
--     Tesoreria\      (treasury / banking)
--     Activos\        (fixed assets)
--     *.tdb *.fpt *.cdx *.idx  (proprietary Tango DBase tables)
--
-- Multi-empresa hosts (the norm for estudios contables and
-- corporate groups) carry dozens of subdirs under `Empresas\`,
-- each a separate legal entity's books — the multi-tenancy
-- itself is the discovery signal.
--
-- Capital-entity & PII context:
--   T1083    File and Directory Discovery
--   T1213    Data from Information Repositories
--   CWE-200, CWE-359, CWE-732 (PII / financial-data exposure)
--   Ley 25.326 — Protección de Datos Personales (Sueldos)
--   AFIP RG 3744, RG 1361 — registro de operaciones
--
-- Headline finding shapes:
--   has_multiple_empresas  — install holds >1 empresa subdir.
--   has_sueldos_module     — Sueldos\ subdir present; the
--                            empresa runs payroll through the
--                            ERP, surfacing HR PII.
--   is_recently_modified   — at least one Tango data file
--                            modified in last 90 days.
--   is_credential_exposure_risk — empresa dir readable AND
--                            has Sueldos or Tesoreria module
--                            (HR PII or banking data).
--
-- CUIT (when discoverable from Empresas.cnf / Empresas.ini)
-- is NEVER stored verbatim — only entity-type prefix + last 4.

CREATE TABLE IF NOT EXISTS host_tango_empresas (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    install_root                TEXT    NOT NULL,
    empresa_dir                 TEXT    NOT NULL,
    empresa_name                TEXT    NOT NULL DEFAULT '',
    denominacion                TEXT    NOT NULL DEFAULT '',
    vendor                      TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (vendor IN ('tango','bejerman','axoft','astor','other','unknown')),
    cuit_entity_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (cuit_entity_prefix IN ('','20','23','24','27','30','33','34')),
    cuit_suffix4                TEXT    NOT NULL DEFAULT '',
    dir_mode                    INTEGER NOT NULL DEFAULT 0,
    dir_owner_uid               INTEGER NOT NULL DEFAULT 0,
    data_files_count            INTEGER NOT NULL DEFAULT 0,
    module_count                INTEGER NOT NULL DEFAULT 0,
    last_modified               TEXT    NOT NULL DEFAULT '',
    has_sueldos_module          INTEGER NOT NULL DEFAULT 0 CHECK (has_sueldos_module IN (0,1)),
    has_ventas_module           INTEGER NOT NULL DEFAULT 0 CHECK (has_ventas_module IN (0,1)),
    has_compras_module          INTEGER NOT NULL DEFAULT 0 CHECK (has_compras_module IN (0,1)),
    has_contabilidad_module     INTEGER NOT NULL DEFAULT 0 CHECK (has_contabilidad_module IN (0,1)),
    has_stock_module            INTEGER NOT NULL DEFAULT 0 CHECK (has_stock_module IN (0,1)),
    has_tesoreria_module        INTEGER NOT NULL DEFAULT 0 CHECK (has_tesoreria_module IN (0,1)),
    has_activos_module          INTEGER NOT NULL DEFAULT 0 CHECK (has_activos_module IN (0,1)),
    has_multiple_empresas       INTEGER NOT NULL DEFAULT 0 CHECK (has_multiple_empresas IN (0,1)),
    is_recently_modified        INTEGER NOT NULL DEFAULT 0 CHECK (is_recently_modified IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_tango_sueldos
    ON host_tango_empresas(empresa_dir) WHERE has_sueldos_module = 1;

CREATE INDEX IF NOT EXISTS idx_tango_multi_tenant
    ON host_tango_empresas(install_root) WHERE has_multiple_empresas = 1;

CREATE INDEX IF NOT EXISTS idx_tango_exposure
    ON host_tango_empresas(empresa_dir) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_tango_entity
    ON host_tango_empresas(cuit_entity_prefix, cuit_suffix4);
