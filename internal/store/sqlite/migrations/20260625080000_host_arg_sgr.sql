-- host_arg_sgr inventories AR Sociedad-de-Garantía-Recíproca
-- (SGR) artifact files cached on credit-officer, recovery-officer,
-- compliance-officer, sepyme-liaison, and gerente workstations at
-- the ~40 active AR SGRs (Garantizar, Acindar Pymes, Aval Federal,
-- Vínculos SGR, Affidavit, Don Mario, Confiable, Garantizar
-- Sustentable, Avaluar, Crecer SGR, etc.) that guarantee SME debt
-- instruments traded on BYMA / MAV (Cheques de Pago Diferido CPD,
-- pagarés bursátiles, ON PyME).
--
-- Regulated under:
--
--   - Ley 24.467 (1995)         SGR statute (capítulo II).
--   - Ley 25.300 (2000)         SGR reforma — Fondo de Riesgo.
--   - SEPyMe Res. 21/2010       Régimen general SGR.
--   - SEPyMe Res. 84/2018       Apalancamiento Fondo de Riesgo
--                               ≤ 10× (relación garantías
--                               vigentes / patrimonio neto + FR).
--   - SEPyMe Res. 383/2019      Composición Fondo de Riesgo.
--   - BCRA Com. A 7916          Riesgo crediticio + capital.
--   - CNV RG 622 art.7          SGR listadas en BYMA / MAV.
--   - UIF Res. 21/2018          PLA/FT — beneficiarios SME.
--   - AFIP RG 5193              Bienes Personales socios protectores.
--   - Ley 27.401                Responsabilidad penal personas
--                               jurídicas (SGR + socio protector).
--
-- Distinct from prior iters because the shape is **mutual-
-- guarantee-society back-office** (SGR-credit perspective):
--
--   - vs iter 198 winargsoc          — defensive SOC.
--   - vs iter 191 winargperito       — audit firm (auditor only).
--   - vs iter 190 winargcalificadora — rating opinion vs guarantee.
--   - vs iter 189 winargfideicomiso  — securitization trust vs SGR.
--   - vs iter 187 winargssn          — insurance vs mutual guarantee.
--   - vs iter 186 winargcrs          — cross-border tax filings.
--
-- An SGR artifact leak is doubly-dangerous because:
--
--   * Guarantee grant document reveals SME beneficiary CUIT +
--     credit-line amount (= insider info on SME borrowing).
--   * SME beneficiary roster + Fondo-de-Riesgo composition reveals
--     concentration → reverse-engineer guarantee policy.
--   * Recovery proceeding reveals SME default-in-progress (=
--     non-public adverse credit event for related listed SME ON).
--   * Counter-guarantee inventory reveals SME shareholder assets
--     pledged (= attack vector for adversaries of SME).
--   * Apalancamiento ratio = SGR breach-of-cap evidence.
--   * SEPyMe filing = self-reported compliance posture.
--   * Socio-protector list = high-net-worth identification (Bienes
--     Personales targeting, kidnap risk).
--
-- SGR distinctive features:
--
--   - Garantizar SGR (largest, BAPRO-backed)
--   - Acindar Pymes SGR (steel-industry-anchored)
--   - Aval Federal SGR (federal-state network)
--   - Vínculos SGR
--   - Affidavit SGR
--   - Don Mario SGR (agribusiness)
--   - Confiable SGR
--   - Garantizar Sustentable SGR (ESG-aligned)
--   - Avaluar SGR
--   - Crecer SGR
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\SGR\<year>\
--     guarantee_grant_<sme>_<yyyymmdd>.pdf       aval otorgado
--     pyme_roster_<yyyymm>.csv                   lista PyMEs
--     risk_fund_statement_<yyyymm>.xlsx          Fondo de Riesgo
--     cpd_guarantee_<cuit>_<yyyymmdd>.pdf        CPD avalado
--     onpyme_guarantee_<cuit>_<yyyy>.pdf         ON PyME avalado
--     sepyme_filing_<yyyy>q<n>.xml               SEPyMe trimestral
--     leverage_ratio_<yyyymm>.csv                apalancamiento
--     recovery_proceeding_<sme>.pdf              recobro
--     counter_guarantee_<sme>.pdf                contragarantía
--     solvency_report_<yyyy>.pdf                 solvencia
--     financial_statement_<yyyy>.xlsx            EE.FF. SGR
--     shareholder_list_<yyyy>.csv                socios partícipes
--     board_resolution_<yyyymmdd>.pdf            acta de directorio
--     sgr_config.ini                             SGR app config
--
-- Regulatory base:
--
--   Ley 24.467          SGR statute (1995)
--   Ley 25.300          SGR reform (2000)
--   SEPyMe Res. 21/2010 Régimen general
--   SEPyMe Res. 84/2018 Apalancamiento ≤ 10×
--   SEPyMe Res. 383/2019 Fondo de Riesgo composition
--   BCRA Com. A 7916    Riesgo crediticio
--   CNV RG 622 art.7    SGR listadas
--   UIF Res. 21/2018    PLA/FT
--   AFIP RG 5193        Bienes Personales
--   Ley 27.401          Corporate criminal liability
--   Ley 25.246          PLA/FT
--
-- MITRE / CWE / Industry Standards:
--
--   T1213    Data from Info Repositories (SGR vault)
--   T1552    Unsecured Credentials
--   T1005    Data from Local System (CPD vault)
--   T1530    Data from Cloud Storage (Garantizar Online)
--   ISO 27001        ISMS
--   IFRS for SMEs    Reporting standard
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config           — cleartext.
--   has_guarantee_grant              — aval otorgado.
--   has_pyme_roster                  — SME beneficiary list.
--   has_risk_fund_statement          — Fondo de Riesgo.
--   has_cpd_guarantee                — CPD avalado.
--   has_onpyme_guarantee             — ON PyME avalado.
--   has_sepyme_filing                — SEPyMe trimestral.
--   has_leverage_ratio               — apalancamiento.
--   has_recovery_proceeding          — recobro.
--   has_counter_guarantee            — contragarantía.
--   has_solvency_report              — solvencia.
--   has_financial_statement          — EE.FF. SGR.
--   has_shareholder_list             — socios partícipes.
--   has_board_resolution             — acta de directorio.
--   has_sgr_cuit                     — SGR entity CUIT.
--   has_sme_cuit                     — SME beneficiary CUIT.
--   has_apalancamiento_breach        — leverage > 10× cap.
--   is_credential_exposure_risk      — readable + (password OR
--                                      API token).
--   is_sme_pii_risk                  — readable + (PyME roster OR
--                                      guarantee grant OR
--                                      counter-guarantee).
--   is_apalancamiento_breach_risk    — readable + leverage > 10×.
--   is_recovery_proceeding_leak      — readable + (recovery OR
--                                      counter-guarantee).

CREATE TABLE IF NOT EXISTS host_arg_sgr (
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
            'sgr-guarantee-grant','sgr-pyme-roster',
            'sgr-risk-fund-statement','sgr-cpd-guarantee',
            'sgr-onpyme-guarantee','sgr-sepyme-filing',
            'sgr-leverage-ratio','sgr-recovery-proceeding',
            'sgr-counter-guarantee','sgr-solvency-report',
            'sgr-financial-statement','sgr-shareholder-list',
            'sgr-board-resolution',
            'sgr-config','sgr-credentials',
            'sgr-installer','other','unknown'
        )),
    sgr_shop                    TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (sgr_shop IN (
            'garantizar','acindar-pymes','aval-federal',
            'vinculos','affidavit','don-mario','confiable',
            'garantizar-sustentable','avaluar','crecer',
            'fondo-garantia-buenos-aires',
            'custom','none','unknown'
        )),
    sgr_role                    TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (sgr_role IN (
            'socio-participe','socio-protector',
            'gerente','credit-officer','recovery-officer',
            'compliance-officer','sepyme-liaison',
            'auditor','cco','board-member',
            'api','other','unknown'
        )),
    counter_guarantee_type      TEXT    NOT NULL DEFAULT ''
        CHECK (counter_guarantee_type IN (
            '','pledge','mortgage','third-party-fianza',
            'term-deposit','securities','none','unknown'
        )),
    guarantee_status            TEXT    NOT NULL DEFAULT ''
        CHECK (guarantee_status IN (
            '','vigente','ejecutada','recuperada',
            'prescripta','anulada','none','unknown'
        )),
    instrument_type             TEXT    NOT NULL DEFAULT ''
        CHECK (instrument_type IN (
            '','cpd','onpyme','pagare-bursatil',
            'fideicomiso-pyme','prestamo-bancario',
            'custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    sgr_cuit_prefix             TEXT    NOT NULL DEFAULT ''
        CHECK (sgr_cuit_prefix IN ('','30','33','34')),
    sgr_cuit_suffix4            TEXT    NOT NULL DEFAULT '',
    sme_cuit_prefix             TEXT    NOT NULL DEFAULT ''
        CHECK (sme_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    sme_cuit_suffix4            TEXT    NOT NULL DEFAULT '',
    pyme_count                  INTEGER NOT NULL DEFAULT 0,
    active_guarantee_count      INTEGER NOT NULL DEFAULT 0,
    risk_fund_size_ars          INTEGER NOT NULL DEFAULT 0,
    guarantees_outstanding_ars  INTEGER NOT NULL DEFAULT 0,
    apalancamiento_ratio_pct    INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_guarantee_grant         INTEGER NOT NULL DEFAULT 0 CHECK (has_guarantee_grant IN (0,1)),
    has_pyme_roster             INTEGER NOT NULL DEFAULT 0 CHECK (has_pyme_roster IN (0,1)),
    has_risk_fund_statement     INTEGER NOT NULL DEFAULT 0 CHECK (has_risk_fund_statement IN (0,1)),
    has_cpd_guarantee           INTEGER NOT NULL DEFAULT 0 CHECK (has_cpd_guarantee IN (0,1)),
    has_onpyme_guarantee        INTEGER NOT NULL DEFAULT 0 CHECK (has_onpyme_guarantee IN (0,1)),
    has_sepyme_filing           INTEGER NOT NULL DEFAULT 0 CHECK (has_sepyme_filing IN (0,1)),
    has_leverage_ratio          INTEGER NOT NULL DEFAULT 0 CHECK (has_leverage_ratio IN (0,1)),
    has_recovery_proceeding     INTEGER NOT NULL DEFAULT 0 CHECK (has_recovery_proceeding IN (0,1)),
    has_counter_guarantee       INTEGER NOT NULL DEFAULT 0 CHECK (has_counter_guarantee IN (0,1)),
    has_solvency_report         INTEGER NOT NULL DEFAULT 0 CHECK (has_solvency_report IN (0,1)),
    has_financial_statement     INTEGER NOT NULL DEFAULT 0 CHECK (has_financial_statement IN (0,1)),
    has_shareholder_list        INTEGER NOT NULL DEFAULT 0 CHECK (has_shareholder_list IN (0,1)),
    has_board_resolution        INTEGER NOT NULL DEFAULT 0 CHECK (has_board_resolution IN (0,1)),
    has_sgr_cuit                INTEGER NOT NULL DEFAULT 0 CHECK (has_sgr_cuit IN (0,1)),
    has_sme_cuit                INTEGER NOT NULL DEFAULT 0 CHECK (has_sme_cuit IN (0,1)),
    has_apalancamiento_breach   INTEGER NOT NULL DEFAULT 0 CHECK (has_apalancamiento_breach IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_sme_pii_risk             INTEGER NOT NULL DEFAULT 0 CHECK (is_sme_pii_risk IN (0,1)),
    is_apalancamiento_breach_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_apalancamiento_breach_risk IN (0,1)),
    is_recovery_proceeding_leak INTEGER NOT NULL DEFAULT 0 CHECK (is_recovery_proceeding_leak IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_sgr_password
    ON host_arg_sgr(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_grant
    ON host_arg_sgr(reporting_period, active_guarantee_count) WHERE has_guarantee_grant = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_pyme
    ON host_arg_sgr(reporting_period, pyme_count) WHERE has_pyme_roster = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_rf
    ON host_arg_sgr(reporting_period, risk_fund_size_ars) WHERE has_risk_fund_statement = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_cpd
    ON host_arg_sgr(reporting_period) WHERE has_cpd_guarantee = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_onpyme
    ON host_arg_sgr(reporting_period) WHERE has_onpyme_guarantee = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_sepyme
    ON host_arg_sgr(reporting_period) WHERE has_sepyme_filing = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_lev
    ON host_arg_sgr(reporting_period, apalancamiento_ratio_pct) WHERE has_leverage_ratio = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_recovery
    ON host_arg_sgr(file_path) WHERE has_recovery_proceeding = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_cg
    ON host_arg_sgr(counter_guarantee_type) WHERE has_counter_guarantee = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_solv
    ON host_arg_sgr(reporting_period) WHERE has_solvency_report = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_fs
    ON host_arg_sgr(reporting_period) WHERE has_financial_statement = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_shareholders
    ON host_arg_sgr(file_path) WHERE has_shareholder_list = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_board
    ON host_arg_sgr(reporting_period) WHERE has_board_resolution = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_entity_cuit
    ON host_arg_sgr(sgr_cuit_prefix, sgr_cuit_suffix4) WHERE has_sgr_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_sme_cuit
    ON host_arg_sgr(sme_cuit_prefix, sme_cuit_suffix4) WHERE has_sme_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_breach
    ON host_arg_sgr(apalancamiento_ratio_pct) WHERE has_apalancamiento_breach = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_cred_exp
    ON host_arg_sgr(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_sme_pii
    ON host_arg_sgr(file_path) WHERE is_sme_pii_risk = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_lev_breach
    ON host_arg_sgr(file_path) WHERE is_apalancamiento_breach_risk = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_recovery_leak
    ON host_arg_sgr(file_path) WHERE is_recovery_proceeding_leak = 1;

CREATE INDEX IF NOT EXISTS idx_sgr_drift
    ON host_arg_sgr(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_sgr_kind
    ON host_arg_sgr(artifact_kind, sgr_shop);
