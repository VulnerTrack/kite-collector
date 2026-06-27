-- host_cnv_alyc_disclosures inventories Argentine CNV
-- ALYC (Agente de Liquidación y Compensación) + ALYC-AN
-- broker-dealer monthly regulatory disclosures cached on
-- broker, custodian, risk, and analyst workstations.
--
-- CNV requires every ALYC / ALYC-AN to file (via AIF) monthly
-- regulatory artifacts:
--
--   RI Tenencias por Cliente      — custody balances per client
--   RI Operaciones por Especie    — transactions per security
--   Estados Patrimoniales         — broker capital adequacy
--   Custodia Mensual              — total AUM snapshot
--   R-IIR                         — Régimen Informativo
--                                    Intermediarios y Registrantes
--
-- **The broker-dealer regulatory-intermediary layer.**
-- Complements:
--   iter 90 winargxbrl  — CNV XBRL issuer position
--   iter 97 winargcnvhr — CNV Hechos Relevantes events
--
-- This layer captures the intermediaries between investors
-- and listed entities — broker custody and order-flow data.
--
-- Regulatory base:
--   Ley 26.831 — Mercado de Capitales
--   CNV RG 622/2013, RG 731/2018 (texto ordenado agentes)
--   CNV RG 731 Anexo II — Régimen Informativo Mensual
--   GAFI / FATF Recomendaciones (intermediarios financieros)
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information (client lists)
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 — protección PII (cliente CUITs)
--
-- Headline finding shapes:
--   has_foreign_currency_custody — at least one custody balance
--                                  in USD/EUR. Capital-flight
--                                  signal in broker context.
--   has_high_concentration       — single client > 50 % AUM
--                                  (KYC/AML attention).
--   client_count                 — distinct cliente CUITs in the
--                                  disclosure. Materially raises
--                                  blast radius when readable.
--   is_credential_exposure_risk  — readable file + cliente
--                                  CUIT list = Ley 25.326 + CNV
--                                  RG 731 confidentiality breach.

CREATE TABLE IF NOT EXISTS host_cnv_alyc_disclosures (
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
            'ri-tenencias','ri-operaciones','estados-patrimoniales',
            'custodia-mensual','regimen-iir','other','unknown'
        )),
    alyc_matricula              TEXT    NOT NULL DEFAULT '',
    alyc_cuit_prefix            TEXT    NOT NULL DEFAULT ''
        CHECK (alyc_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    alyc_cuit_suffix4           TEXT    NOT NULL DEFAULT '',
    alyc_denominacion           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    client_count                INTEGER NOT NULL DEFAULT 0,
    specie_count                INTEGER NOT NULL DEFAULT 0,
    total_aum_ars_cents         INTEGER NOT NULL DEFAULT 0,
    max_client_pct              INTEGER NOT NULL DEFAULT 0
        CHECK (max_client_pct BETWEEN 0 AND 100),
    has_foreign_currency_custody INTEGER NOT NULL DEFAULT 0 CHECK (has_foreign_currency_custody IN (0,1)),
    has_high_concentration       INTEGER NOT NULL DEFAULT 0 CHECK (has_high_concentration IN (0,1)),
    is_recent                    INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable            INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable            INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk  INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_alyc_foreign
    ON host_cnv_alyc_disclosures(period_yyyymm) WHERE has_foreign_currency_custody = 1;

CREATE INDEX IF NOT EXISTS idx_alyc_concentration
    ON host_cnv_alyc_disclosures(alyc_cuit_prefix, alyc_cuit_suffix4) WHERE has_high_concentration = 1;

CREATE INDEX IF NOT EXISTS idx_alyc_exposure
    ON host_cnv_alyc_disclosures(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_alyc_drift
    ON host_cnv_alyc_disclosures(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_alyc_entity
    ON host_cnv_alyc_disclosures(alyc_cuit_prefix, alyc_cuit_suffix4);

CREATE INDEX IF NOT EXISTS idx_alyc_matricula
    ON host_cnv_alyc_disclosures(alyc_matricula);
