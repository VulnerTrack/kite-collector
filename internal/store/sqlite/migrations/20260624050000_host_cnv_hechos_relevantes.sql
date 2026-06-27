-- host_cnv_hechos_relevantes inventories Argentine CNV
-- "Hechos Relevantes" material-event filings cached on
-- analyst / risk / asset-management workstations. Every
-- public sociedad anónima cotizante must file, via CNV's
-- AIF portal, each material event affecting the entity —
-- approvals, dividends, capital changes, M&A, defaults,
-- changes of control, management changes, calificaciones de
-- riesgo, OPAs and tender offers.
--
-- This is the **capital-entity event stream** that complements
-- the periodic XBRL financial statements (iter 90): periodic
-- filings show position, hechos relevantes show change.
--
-- Capital-entity event context:
--   T1592    Gather Victim Org Information (event recon)
--   T1213    Data from Information Repositories
--   CWE-200, CWE-359, CWE-732
--   Ley 26.831 (Mercado de Capitales)
--   CNV RG 622/2013, RG 622/2024 (régimen informativo AIF)
--   BCRA / CNV cross-reporting (defaults, sanctions)
--
-- Headline finding shapes:
--   is_high_impact_event   — tipo_hecho in {'default','mna',
--                            'cambio-control','cesacion-pagos',
--                            'oferta-publica-adquisicion'}.
--                            Immediate-attention capital event.
--   is_recent              — file modified within 90 days.
--   is_credential_exposure_risk — readable file + filing-PII
--                            (issuer CUIT + denominación present).
--
-- Issuer CUIT (sociedades anónimas — public by definition for
-- 30/33 prefixes) is still reduced to entity-type prefix +
-- last 4 digits for consistency with sibling collectors.
-- Vinculado (related-entity) CUIT same treatment.

CREATE TABLE IF NOT EXISTS host_cnv_hechos_relevantes (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    filing_kind                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (filing_kind IN (
            'hecho-relevante','comunicacion','info-financiera',
            'anuncio','other','unknown'
        )),
    tipo_hecho                  TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (tipo_hecho IN (
            'aprobacion-eecc','dividendos','capital-aumento',
            'capital-reduccion','oferta-publica','mna','default',
            'cesacion-pagos','cambio-control','cambio-management',
            'calificacion-riesgo','oferta-canje','asamblea',
            'sancion','other','unknown'
        )),
    relevancia                  TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (relevancia IN ('alta','media','baja','unknown')),
    issuer_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (issuer_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    issuer_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    issuer_ticker               TEXT    NOT NULL DEFAULT '',
    issuer_denominacion         TEXT    NOT NULL DEFAULT '',
    vinculado_cuit_prefix       TEXT    NOT NULL DEFAULT ''
        CHECK (vinculado_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    vinculado_cuit_suffix4      TEXT    NOT NULL DEFAULT '',
    fecha_hecho                 TEXT    NOT NULL DEFAULT '',
    is_high_impact_event        INTEGER NOT NULL DEFAULT 0 CHECK (is_high_impact_event IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_cnv_hr_high_impact
    ON host_cnv_hechos_relevantes(issuer_cuit_prefix, issuer_cuit_suffix4) WHERE is_high_impact_event = 1;

CREATE INDEX IF NOT EXISTS idx_cnv_hr_recent
    ON host_cnv_hechos_relevantes(fecha_hecho) WHERE is_recent = 1;

CREATE INDEX IF NOT EXISTS idx_cnv_hr_exposure
    ON host_cnv_hechos_relevantes(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_cnv_hr_drift
    ON host_cnv_hechos_relevantes(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_cnv_hr_issuer
    ON host_cnv_hechos_relevantes(issuer_cuit_prefix, issuer_cuit_suffix4);

CREATE INDEX IF NOT EXISTS idx_cnv_hr_ticker
    ON host_cnv_hechos_relevantes(issuer_ticker);
