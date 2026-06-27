-- host_arg_xbrl_filings inventories Argentine financial-
-- statement XBRL filings cached on accounting / analyst
-- workstations. CNV (Comisión Nacional de Valores) operates
-- the AIF (Autopista de la Información Financiera) where
-- every public sociedad anónima cotizante files its `estados
-- contables` as XBRL instance documents. IGJ (Inspección
-- General de Justicia) accepts similar filings from non-
-- listed entities.
--
-- This is the **Capital Entity** companion to the AFIP Tax-
-- side collectors. Where AFIP collectors surface invoice
-- issuance per CUIT, XBRL filings surface the *entities* the
-- workstation's owner has financial-data relationships with.
--
-- Capital-flow & beneficial-ownership context:
--   T1592    Gather Victim Org Information — pre-attack
--            reconnaissance staged via leaked filings
--   T1078.004 Cloud Accounts — multi-entity analyst workstations
--   CWE-200, CWE-359, CWE-732 (financial-PII exposure on disk)
--   CNV RG 622/2013 — Régimen Informativo XBRL para AIF
--   IGJ Res. Gral. 7/2015 — Estados Contables
--
-- Headline finding shapes:
--   is_consolidated_statement — XBRL exposes consolidated facts
--                              (subsidiaries, group structure).
--   is_foreign_currency_facts — at least one fact reported in
--                              a non-ARS currency (USD/EUR/BRL),
--                              capital-flight signal.
--   is_cnv_publicly_listed    — schemaRef points at a CNV-AIF
--                              taxonomy, i.e. the entity is on
--                              the BYMA / BCBA listing.
--   is_credential_exposure_risk — financial PII + readable file.
--
-- The CUIT is NEVER stored verbatim — only the entity-type
-- prefix (20/23/24/27/30/33/34) and the trailing 4 digits.

CREATE TABLE IF NOT EXISTS host_arg_xbrl_filings (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    filing_kind                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (filing_kind IN ('xbrl-instance','xbrl-schema','xbrl-linkbase','xbrl-zip','unknown')),
    taxonomy_label              TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (taxonomy_label IN ('cnv-aif','igj','ifrs','ar-ifrs','us-gaap','other','unknown')),
    entity_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (entity_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    entity_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    entity_denominacion         TEXT    NOT NULL DEFAULT '',
    period_start                TEXT    NOT NULL DEFAULT '',
    period_end                  TEXT    NOT NULL DEFAULT '',
    reporting_currency          TEXT    NOT NULL DEFAULT '',
    fact_count                  INTEGER NOT NULL DEFAULT 0,
    is_consolidated_statement   INTEGER NOT NULL DEFAULT 0 CHECK (is_consolidated_statement IN (0,1)),
    is_foreign_currency_facts   INTEGER NOT NULL DEFAULT 0 CHECK (is_foreign_currency_facts IN (0,1)),
    is_cnv_publicly_listed      INTEGER NOT NULL DEFAULT 0 CHECK (is_cnv_publicly_listed IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_arg_xbrl_listed
    ON host_arg_xbrl_filings(entity_cuit_prefix, entity_cuit_suffix4) WHERE is_cnv_publicly_listed = 1;

CREATE INDEX IF NOT EXISTS idx_arg_xbrl_foreign
    ON host_arg_xbrl_filings(period_end) WHERE is_foreign_currency_facts = 1;

CREATE INDEX IF NOT EXISTS idx_arg_xbrl_consolidated
    ON host_arg_xbrl_filings(period_end) WHERE is_consolidated_statement = 1;

CREATE INDEX IF NOT EXISTS idx_arg_xbrl_exposure
    ON host_arg_xbrl_filings(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_arg_xbrl_drift
    ON host_arg_xbrl_filings(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_arg_xbrl_entity
    ON host_arg_xbrl_filings(entity_cuit_prefix, entity_cuit_suffix4);
