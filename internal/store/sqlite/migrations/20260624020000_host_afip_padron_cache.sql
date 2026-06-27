-- host_afip_padron_cache inventories AFIP "Padrón Único de
-- Contribuyentes" web-service response caches on Argentine
-- accounting workstations. Every SDK (pyafipws, Afip.php,
-- afipsdk-js, contabilidad-Tango, accounting plugins) calls
-- ws_sr_padron_a4 / a5 / a10 / a13 to resolve CUIT →
-- {razón social, domicilio fiscal, situación IVA, actividades
-- CLAE, estado}, and caches the XML/JSON response on disk to
-- avoid re-hitting AFIP.
--
-- This cache is the workstation's **contribuyente-research
-- record**: who they look up reveals counterparty universe +
-- due-diligence focus. For AML / KYC investigations the cache
-- is gold — CLAE codes flag intermediación financiera (6499 /
-- 6492), juegos de azar (9200 / 9329), criptomonedas (6499
-- with attribute), and other regulated activities.
--
-- Capital-entity & PII context:
--   T1592    Gather Victim Org Information
--   T1213    Data from Information Repositories
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 (Protección de Datos Personales)
--   UIF Res. 30-E/2017 (PEP / sectores regulados)
--
-- Headline finding shapes:
--   is_responsable_inscripto / is_monotributista / is_exento
--   is_baja                   — `estadoCUIT="BAJA"`; defunct.
--   has_risky_actividades     — at least one CLAE code in the
--                              curated AML-high-risk set.
--   is_credential_exposure_risk — readable file + populated
--                              denominación or CLAE (PII).
--
-- Target CUIT is NEVER stored verbatim — only entity-type
-- prefix (20/23/24/27/30/33/34) and the last 4 digits.

CREATE TABLE IF NOT EXISTS host_afip_padron_cache (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    query_kind                  TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (query_kind IN ('padron-a4','padron-a5','padron-a10','padron-a13','contribuyente-other','unknown')),
    target_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (target_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    target_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    denominacion                TEXT    NOT NULL DEFAULT '',
    situacion_iva               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (situacion_iva IN (
            'responsable-inscripto','monotributista','exento',
            'no-alcanzado','no-inscripto','unknown'
        )),
    estado_cuit                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (estado_cuit IN ('activo','baja','inactivo','suspendido','unknown')),
    domicilio_provincia         TEXT    NOT NULL DEFAULT '',
    actividades_count           INTEGER NOT NULL DEFAULT 0,
    primary_actividad_clae      TEXT    NOT NULL DEFAULT '',
    is_responsable_inscripto    INTEGER NOT NULL DEFAULT 0 CHECK (is_responsable_inscripto IN (0,1)),
    is_monotributista           INTEGER NOT NULL DEFAULT 0 CHECK (is_monotributista IN (0,1)),
    is_exento                   INTEGER NOT NULL DEFAULT 0 CHECK (is_exento IN (0,1)),
    is_baja                     INTEGER NOT NULL DEFAULT 0 CHECK (is_baja IN (0,1)),
    has_risky_actividades       INTEGER NOT NULL DEFAULT 0 CHECK (has_risky_actividades IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_afip_padron_risky
    ON host_afip_padron_cache(target_cuit_prefix, target_cuit_suffix4) WHERE has_risky_actividades = 1;

CREATE INDEX IF NOT EXISTS idx_afip_padron_baja
    ON host_afip_padron_cache(target_cuit_prefix, target_cuit_suffix4) WHERE is_baja = 1;

CREATE INDEX IF NOT EXISTS idx_afip_padron_exposure
    ON host_afip_padron_cache(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_afip_padron_drift
    ON host_afip_padron_cache(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_afip_padron_entity
    ON host_afip_padron_cache(target_cuit_prefix, target_cuit_suffix4);
