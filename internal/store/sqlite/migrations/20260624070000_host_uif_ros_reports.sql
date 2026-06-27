-- host_uif_ros_reports inventories Argentine UIF (Unidad de
-- Información Financiera) ROS / RFT / DMS report files cached
-- on accounting / compliance / risk workstations. UIF is the
-- Argentine FIU; every sujeto obligado (bancos, escribanos,
-- contadores, fintechs, inmobiliarias, casinos, etc.) must
-- file:
--
--   ROS — Reporte de Operación Sospechosa (Ley 25.246 art.21)
--   RFT — Reporte de Financiamiento del Terrorismo
--   DMS — Declaración Mensual Sistemática (umbral)
--
-- via the "Sistema en Línea UIF". Drafts and submitted copies
-- land on workstations as XML / JSON / fixed-width TXT.
--
-- **HIGHEST-STAKES file class in the catalogue.** Ley 25.246
-- art. 22 makes any disclosure of ROS/RFT contents to the
-- target (or to any third party other than UIF) a federal
-- crime ("tipping off"). A world-readable ROS file is not
-- just a PII leak — it is a substantive Ley 25.246
-- art. 22 breach with criminal exposure for the sujeto
-- obligado.
--
-- Regulatory base:
--   Ley 25.246 (Encubrimiento y Lavado de Activos)
--   UIF Res. 21/2018 — sectores bancarios
--   UIF Res. 30-E/2017 — sujetos obligados (alcance)
--   UIF Res. 154/2018 — RFT terrorismo
--   GAFI / FATF Recomendaciones 20-23
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1565.001 Data Manipulation: Stored Data (ROS tampering)
--   CWE-200, CWE-359, CWE-732
--   "tipping off" criminal exposure (Ley 25.246 art. 22)
--
-- Headline finding shapes:
--   is_terrorism_financing  — file is RFT-class (terrorist
--                             financing report).
--   is_high_value           — monto > 50 M ARS (Res. 30-E/2017
--                             umbral ampliado).
--   is_pep_related          — narrative or flag references
--                             "PEP" / "Persona Expuesta
--                             Políticamente".
--   is_borrador             — file is an unfiled DRAFT;
--                             investigative state visible
--                             on disk.
--   is_credential_exposure_risk — readable file + ANY
--                             tipo_reporte; Ley 25.246 art. 22
--                             "tipping off" criminal risk.
--
-- Target + sujeto obligado CUITs NEVER stored verbatim — only
-- entity-type prefix + last 4 digits. Narrative content is
-- NEVER stored — only its length.

CREATE TABLE IF NOT EXISTS host_uif_ros_reports (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    tipo_reporte                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (tipo_reporte IN (
            'ros','rft','dms','reporte-anual','other','unknown'
        )),
    estado                      TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (estado IN (
            'borrador','presentado','en-revision','rectificado','unknown'
        )),
    target_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (target_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    target_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    sujeto_obligado_cuit_prefix TEXT    NOT NULL DEFAULT ''
        CHECK (sujeto_obligado_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    sujeto_obligado_cuit_suffix4 TEXT   NOT NULL DEFAULT '',
    monto_ars_cents             INTEGER NOT NULL DEFAULT 0,
    fecha_reporte               TEXT    NOT NULL DEFAULT '',
    descripcion_length          INTEGER NOT NULL DEFAULT 0,
    is_terrorism_financing      INTEGER NOT NULL DEFAULT 0 CHECK (is_terrorism_financing IN (0,1)),
    is_high_value               INTEGER NOT NULL DEFAULT 0 CHECK (is_high_value IN (0,1)),
    is_pep_related              INTEGER NOT NULL DEFAULT 0 CHECK (is_pep_related IN (0,1)),
    is_borrador                 INTEGER NOT NULL DEFAULT 0 CHECK (is_borrador IN (0,1)),
    has_descripcion             INTEGER NOT NULL DEFAULT 0 CHECK (has_descripcion IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_uif_rft
    ON host_uif_ros_reports(target_cuit_prefix, target_cuit_suffix4) WHERE is_terrorism_financing = 1;

CREATE INDEX IF NOT EXISTS idx_uif_high_value
    ON host_uif_ros_reports(target_cuit_prefix, target_cuit_suffix4) WHERE is_high_value = 1;

CREATE INDEX IF NOT EXISTS idx_uif_pep
    ON host_uif_ros_reports(target_cuit_prefix, target_cuit_suffix4) WHERE is_pep_related = 1;

CREATE INDEX IF NOT EXISTS idx_uif_borrador
    ON host_uif_ros_reports(target_cuit_prefix, target_cuit_suffix4) WHERE is_borrador = 1;

CREATE INDEX IF NOT EXISTS idx_uif_exposure
    ON host_uif_ros_reports(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_uif_drift
    ON host_uif_ros_reports(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_uif_entity
    ON host_uif_ros_reports(target_cuit_prefix, target_cuit_suffix4);
