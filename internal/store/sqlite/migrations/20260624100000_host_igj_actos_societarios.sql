-- host_igj_actos_societarios inventories Argentine IGJ
-- (Inspección General de Justicia — federal registro público
-- de comercio for CABA) actos-societarios files cached on
-- lawyer / escribano / compliance workstations.
--
-- IGJ governs every sociedad registrada en CABA: SA, SRL,
-- asociaciones, fundaciones. The catalogue of registrable
-- actos:
--
--   acta constitutiva       (incorporation deed)
--   estatuto social          (bylaws)
--   reforma de estatuto      (bylaw amendment)
--   designación de directorio (board appointment)
--   asamblea ordinaria       (annual general meeting)
--   asamblea extraordinaria  (special meeting)
--   reorganización societaria (M&A — fusión/escisión)
--   disolución               (dissolution)
--   liquidación              (winding-up)
--   balance / EECC           (annual financial statements)
--
-- **The provincial-registral complement to capital-entity
-- discovery.** Covers all CABA sociedades, not just CNV-listed
-- (which iter 90 + 97 already address).
--
-- Regulatory base:
--   Ley 19.550 — Sociedades Comerciales (LGS)
--   IGJ Res. Gral. 7/2015 (Texto Ordenado)
--   IGJ Res. Gral. 8/2015 (presentaciones electrónicas)
--   Ley 26.685 — Expediente Electrónico
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 — protección PII (representantes legales)
--
-- Headline finding shapes:
--   has_directorio_change  — file is a board-appointment /
--                            designación; signals control
--                            change.
--   has_capital_change     — reform involves capital
--                            modification (aumento /
--                            reducción).
--   has_disolucion         — disolución / liquidación; entity
--                            sunset.
--   is_reorganizacion      — fusión / escisión / absorción
--                            (M&A registered).
--   is_recent              — file modified within 90 days.
--   is_credential_exposure_risk — readable file + PII
--                            (representante legal CUIT or
--                            denominación present).
--
-- CUITs reduced to entity-type prefix + last 4. Representante
-- legal CUIT (natural person 20/23/24/27) treated as PII.

CREATE TABLE IF NOT EXISTS host_igj_actos_societarios (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    acto_kind                   TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (acto_kind IN (
            'acta-constitutiva','estatuto-social','reforma-estatuto',
            'designacion-directorio','asamblea-ordinaria',
            'asamblea-extraordinaria','reorganizacion','disolucion',
            'liquidacion','balance','other','unknown'
        )),
    estado                      TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (estado IN (
            'tramite','inscripto','observado','rechazado','desistido','unknown'
        )),
    sociedad_cuit_prefix        TEXT    NOT NULL DEFAULT ''
        CHECK (sociedad_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    sociedad_cuit_suffix4       TEXT    NOT NULL DEFAULT '',
    sociedad_denominacion       TEXT    NOT NULL DEFAULT '',
    igj_correlativo             TEXT    NOT NULL DEFAULT '',
    igj_legajo                  TEXT    NOT NULL DEFAULT '',
    tipo_societario             TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (tipo_societario IN ('sa','srl','sas','asociacion','fundacion','cooperativa','other','unknown')),
    fecha_acto                  TEXT    NOT NULL DEFAULT '',
    fecha_inscripcion           TEXT    NOT NULL DEFAULT '',
    has_capital_change          INTEGER NOT NULL DEFAULT 0 CHECK (has_capital_change IN (0,1)),
    has_directorio_change       INTEGER NOT NULL DEFAULT 0 CHECK (has_directorio_change IN (0,1)),
    has_disolucion              INTEGER NOT NULL DEFAULT 0 CHECK (has_disolucion IN (0,1)),
    is_reorganizacion           INTEGER NOT NULL DEFAULT 0 CHECK (is_reorganizacion IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_igj_directorio
    ON host_igj_actos_societarios(sociedad_cuit_prefix, sociedad_cuit_suffix4) WHERE has_directorio_change = 1;

CREATE INDEX IF NOT EXISTS idx_igj_capital
    ON host_igj_actos_societarios(sociedad_cuit_prefix, sociedad_cuit_suffix4) WHERE has_capital_change = 1;

CREATE INDEX IF NOT EXISTS idx_igj_disolucion
    ON host_igj_actos_societarios(sociedad_cuit_prefix, sociedad_cuit_suffix4) WHERE has_disolucion = 1;

CREATE INDEX IF NOT EXISTS idx_igj_reorg
    ON host_igj_actos_societarios(sociedad_cuit_prefix, sociedad_cuit_suffix4) WHERE is_reorganizacion = 1;

CREATE INDEX IF NOT EXISTS idx_igj_exposure
    ON host_igj_actos_societarios(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_igj_drift
    ON host_igj_actos_societarios(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_igj_entity
    ON host_igj_actos_societarios(sociedad_cuit_prefix, sociedad_cuit_suffix4);
