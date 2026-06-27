-- host_arg_perfil_inversor inventories CNV RG 731 Art. 21
-- "Perfil del Inversor" client investment-suitability profile
-- files cached on Argentine ALYC broker-dealer + AAG (Agente
-- Asesor Global) workstations.
--
-- CNV RG 731 Art. 21 + Resol. Concertada 1.1 mandate that
-- every cliente of a regulated agente get a documented
-- investment-suitability profile classifying them as:
--
--   conservadora        capital-preservation (FCI / depósito)
--   moderada            risk-balance (mix RV + RF)
--   agresiva            growth-oriented (equity + futures OK)
--   sofisticada         high-risk-tolerance (derivatives,
--                       leveraged products)
--   inversor calificado net worth > USD 750k + CV experience
--
-- The profile must be re-validated annually (Art. 21 § d).
-- Trading instruments not aligned with the profile = product-
-- suitability violation (CNV monitors).
--
-- Workstation cache footprint:
--
--   C:\Compliance\PerfilInversor\<cuit>.pdf
--   C:\Mercap\KYC\perfil_<cuit>.xml
--   C:\Documents\Perfil\cuestionario_<cuit>.json
--   C:\ALYC\Perfil\declaracion_<cuit>.xml
--   C:\Documents\Perfil\categoria_<cuit>.json
--   C:\Documents\Perfil\update_log_<cuit>.csv
--
-- **The investment-suitability layer.** Distinct from:
--   - iter 138 winarguifros    UIF / AML KYC (different reg)
--   - iter 117 winargcvsa      central custody
--   - iter 107 winargcnvalyc   ALYC business disclosure
--   - iter 144 winargcnvrg1023 cybersec compliance
--   - iter 145 winargmercap    back-office software
--
-- Perfil-specific risk signals:
--   * Profile > 12 months without revision = CNV RG 731
--     Art. 21 § d non-compliance.
--   * Conservative profile + derivatives in portfolio =
--     product-suitability violation.
--   * Aggressive category assigned without risk-tolerance
--     test = improper categorization.
--   * Missing client signature = profile invalid.
--   * High-risk profile assigned to a cliente with declared
--     low income / low net worth = mismatch.
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes Art. 21
--   CNV Resol. 1.1   Conducta de Mercado
--   CNV RG 622       Operativa
--   UIF Resol. 30-E  KYC (parallel rule)
--   Ley 25.326       protección datos personales
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information
--   CWE-200, CWE-359
--   Ley 25.326 (cliente PII + financial data)
--
-- Headline finding shapes:
--   has_outdated_profile        — > 12 months since revision.
--   has_missing_signature       — signature missing flag.
--   has_category_mismatch       — conservative + derivative.
--   has_aggressive_no_test      — agresiva without test.
--   has_high_risk_low_income    — high-risk + low income.
--   has_no_kyc_link             — perfil without KYC ref.
--   has_cliente_cuit            — cliente CUIT detected.
--   is_credential_exposure_risk — readable file + cliente
--                                 CUIT + (profile body OR
--                                 financial-data body).

CREATE TABLE IF NOT EXISTS host_arg_perfil_inversor (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    artifact_kind               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (artifact_kind IN (
            'perfil-pdf','perfil-questionnaire',
            'perfil-declaration','perfil-category',
            'perfil-update-log','perfil-revision',
            'perfil-installer','other','unknown'
        )),
    risk_category               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (risk_category IN (
            'conservadora','moderada','agresiva',
            'sofisticada','inversor-calificado',
            'other','unknown'
        )),
    agente_class                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (agente_class IN (
            'alyc','aag','acotg','acodi',
            'other','unknown'
        )),
    broker_matricula            TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    last_review_date            TEXT    NOT NULL DEFAULT '',
    next_review_date            TEXT    NOT NULL DEFAULT '',
    declared_annual_income_cents INTEGER NOT NULL DEFAULT 0,
    declared_net_worth_cents    INTEGER NOT NULL DEFAULT 0,
    instrument_class_list       TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_outdated_profile        INTEGER NOT NULL DEFAULT 0 CHECK (has_outdated_profile IN (0,1)),
    has_missing_signature       INTEGER NOT NULL DEFAULT 0 CHECK (has_missing_signature IN (0,1)),
    has_category_mismatch       INTEGER NOT NULL DEFAULT 0 CHECK (has_category_mismatch IN (0,1)),
    has_aggressive_no_test      INTEGER NOT NULL DEFAULT 0 CHECK (has_aggressive_no_test IN (0,1)),
    has_high_risk_low_income    INTEGER NOT NULL DEFAULT 0 CHECK (has_high_risk_low_income IN (0,1)),
    has_no_kyc_link             INTEGER NOT NULL DEFAULT 0 CHECK (has_no_kyc_link IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_perfil_outdated
    ON host_arg_perfil_inversor(broker_matricula) WHERE has_outdated_profile = 1;

CREATE INDEX IF NOT EXISTS idx_perfil_nosign
    ON host_arg_perfil_inversor(file_path) WHERE has_missing_signature = 1;

CREATE INDEX IF NOT EXISTS idx_perfil_mismatch
    ON host_arg_perfil_inversor(broker_matricula) WHERE has_category_mismatch = 1;

CREATE INDEX IF NOT EXISTS idx_perfil_agg_notest
    ON host_arg_perfil_inversor(broker_matricula) WHERE has_aggressive_no_test = 1;

CREATE INDEX IF NOT EXISTS idx_perfil_income
    ON host_arg_perfil_inversor(broker_matricula) WHERE has_high_risk_low_income = 1;

CREATE INDEX IF NOT EXISTS idx_perfil_nokyc
    ON host_arg_perfil_inversor(file_path) WHERE has_no_kyc_link = 1;

CREATE INDEX IF NOT EXISTS idx_perfil_cliente
    ON host_arg_perfil_inversor(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_perfil_exposure
    ON host_arg_perfil_inversor(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_perfil_drift
    ON host_arg_perfil_inversor(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_perfil_category
    ON host_arg_perfil_inversor(risk_category, period_yyyymm);

CREATE INDEX IF NOT EXISTS idx_perfil_agente
    ON host_arg_perfil_inversor(agente_class, broker_matricula);
