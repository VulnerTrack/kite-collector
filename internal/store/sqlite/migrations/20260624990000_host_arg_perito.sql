-- host_arg_perito inventories AR external auditor (perito
-- calificador / auditor externo) working-paper artifact files
-- cached on Argentine audit-firm partner, manager, senior, and
-- staff auditor workstations.
--
-- AR external auditors (PwC Argentina, Deloitte Argentina, EY
-- Argentina, KPMG Argentina, BDO Argentina, Grant Thornton
-- Argentina, Crowe Argentina) audit every CNV-listed company,
-- Fideicomiso Financiero (iter 189), ALYC (iter 185), insurer
-- (iter 187), bank, and FCI under CNV RG 622 art.61 (auditor
-- independence) + FACPCE Resolución Técnica 7 (auditing
-- standards) + Ley 20.488 (Ley de Ejercicio Profesional Ciencias
-- Económicas).
--
-- Distinct from prior iters because the shape is **audit-firm
-- back-office** — auditor verifies historical financials, not
-- forward creditworthiness like calificadora:
--
--   - vs iter 190 winargcalificadora — rating agency.
--   - vs iter 189 winargfideicomiso  — issuer side (FF).
--   - vs iter 187 winargssn          — private insurer investor.
--   - vs iter 185 winargcohen        — broker-dealer ALYC.
--
-- Working papers are a uniquely sensitive category because:
--
--   * Pre-publication audit findings = insider information (CNV
--     RG 622 art.50; audit opinion affects share price).
--   * Internal control deficiency reports = systemic-risk
--     leakage (operational weakness disclosure could be
--     exploited).
--   * Audit fee schedule = conflict-of-interest evidence (the
--     issuer-pays model + per-firm dependency).
--   * Confirmation responses contain ALL bank balances, ALL
--     brokerage holdings, ALL legal-counsel pending litigation
--     descriptions — a full cross-reference of every prior
--     collector's data, signed by the issuer's counterparties.
--   * Letter of representations contains management's signed
--     attestation of all known fraud / illegal acts (Ley 25.246
--     PLA/FT trigger).
--   * Engagement letter contains fee structure + scope (M&A
--     advisory side-engagement = inherent COI).
--
-- Auditor distinctive features:
--
--   - Issuer-pays model identical to calificadora but different
--     concerns (calificadora rates creditworthiness ex-ante;
--     auditor verifies financials ex-post).
--   - Engagement team hierarchy: partner > senior manager >
--     manager > senior > staff > intern.
--   - Quality reviewer (independent partner) per ISA 220 + IFAC
--     ISQC 1.
--   - 5-year partner rotation per CNV RG 622 art.61 + IFAC.
--   - SOC 1 Type II for IT general controls (when relevant to
--     financial reporting).
--   - PCAOB inspection if listed-company audits a US-cross-listed
--     issuer (AR ADR issuers like Galicia, YPF, MELI).
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\Auditor\<client>\<year>\
--     papeles_de_trabajo.pdf                            workpapers
--     engagement_letter.pdf                             engagement
--     internal_control_assessment.pdf                   ICA
--     confirmation_bank_<bank>.pdf                      bank confirm
--     confirmation_brokerage_<broker>.pdf               brokerage
--     confirmation_legal_<firm>.pdf                     legal
--     letter_representations.pdf                        management rep
--     internal_control_deficiency.pdf                   ICDR
--     audit_fee_schedule.csv                            fees
--     audit_committee_minutes.pdf                       AC minutes
--     management_letter.pdf                             mgmt letter
--     audit_plan.pdf                                    plan
--     subsequent_events.pdf                             SE review
--     analytical_review.xlsx                            analytical
--     tax_provision_workpaper.xlsx                      tax provision
--     going_concern_opinion.pdf                         going concern
--     soc1_<vendor>.pdf                                 SOC reliance
--   %USERPROFILE%\Documents\Auditor\                    docs root
--
-- Perito-specific risk signals:
--
--   * Cleartext password in auditor-tool config = T1552 + CNV
--     RG 622 art.61 (auditor independence implies confidentiality).
--   * Working paper with `RESERVADO` / `CONFIDENCIAL` / `DRAFT`
--     marker = pre-publication audit finding (CNV RG 622 art.50;
--     audit opinion is market-moving).
--   * Internal control deficiency report = operational-risk
--     leakage (the entity's IT/process weaknesses).
--   * Confirmation response signed by bank/brokerage =
--     full balance disclosure of the audited entity.
--   * Going-concern opinion in DRAFT = pending audit-modification
--     (= pending negative material disclosure).
--   * Letter of representations with management fraud attestation
--     = high-impact if leaked (legal-action evidence).
--   * Audit fee + tax-advisory + consulting fee schedule for same
--     client = independence breach (CNV RG 622 art.61 prohibits
--     non-audit services > X% of audit fee).
--   * Engagement-team list with cliente_emisor_cuit cross-ref =
--     conflict-of-interest mapping (5-year partner rotation).
--   * SOC 1 Type II report from IT service org = third-party
--     risk dependence (CWE-200 across IT vendor).
--
-- Regulatory base:
--
--   Ley 26.831       Mercado de Capitales (AR)
--   Ley 20.488       Ejercicio Profesional Ciencias Económicas
--   CNV RG 622 art.61 Auditor independence
--   CNV RG 622 art.50 Insider information
--   CNV RG 731       Régimen de Agentes (auditor licensing)
--   CNV RG 1023      Ciberresiliencia
--   FACPCE RT 7      Auditing standards (AR)
--   FACPCE RT 8      Review engagement
--   FACPCE RT 33     Auditor independence (per IFAC)
--   FACPCE RT 50     ISA convergence
--   Ley 25.246       PLA/FT
--   Ley 25.326       Datos Personales
--
-- US-side regs (if AR auditor audits US-cross-listed issuer):
--
--   PCAOB AS Section 1100-2900  Auditing standards
--   SOX § 404                   Internal control attestation
--   IFAC ISA 700, 705           Auditor opinion
--   IFAC ISQC 1                 Quality control
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories (workpaper vault)
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (auditor portal)
--   T1005    Data from Local System (confirmation PDFs)
--   T1199    Trusted Relationship (issuer ↔ auditor chain)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config         — cleartext.
--   has_workpaper                  — working paper.
--   has_engagement_letter          — engagement letter.
--   has_internal_control_assessment — ICA.
--   has_confirmation_bank          — bank confirmation.
--   has_confirmation_brokerage     — brokerage confirmation.
--   has_confirmation_legal         — legal counsel confirmation.
--   has_letter_representations     — management rep letter.
--   has_internal_control_deficiency — ICDR.
--   has_audit_fee_schedule         — fee schedule.
--   has_audit_committee_minutes    — AC minutes.
--   has_management_letter          — mgmt letter.
--   has_audit_plan                 — audit plan.
--   has_going_concern_opinion      — going-concern opinion.
--   has_soc_reliance_report        — SOC 1/2 reliance.
--   has_draft_marker               — DRAFT / RESERVADO / CONFIDENCIAL.
--   has_independence_breach        — non-audit-services breach.
--   has_subsequent_events_review   — SE review.
--   has_cross_listed_us_issuer     — PCAOB-relevant issuer.
--   has_cliente_emisor_cuit        — issuer CUIT.
--   has_auditor_cuil               — auditor CUIL.
--   is_credential_exposure_risk    — readable + (password OR
--                                    workpaper OR confirmation OR
--                                    letter rep OR cliente CUIT).
--   is_pre_publication_finding_risk — readable + (draft marker OR
--                                    going concern OR ICDR).
--   is_counterparty_disclosure_risk — readable + confirmation
--                                    bank/brokerage/legal.

CREATE TABLE IF NOT EXISTS host_arg_perito (
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
            'per-workpaper','per-engagement-letter',
            'per-internal-control-assessment',
            'per-confirmation-bank','per-confirmation-brokerage',
            'per-confirmation-legal','per-letter-representations',
            'per-internal-control-deficiency',
            'per-audit-fee-schedule','per-audit-committee-minutes',
            'per-management-letter','per-audit-plan',
            'per-going-concern-opinion','per-soc-reliance-report',
            'per-subsequent-events-review',
            'per-config','per-credentials',
            'per-installer','other','unknown'
        )),
    audit_firm                  TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (audit_firm IN (
            'pwc-argentina','deloitte-argentina',
            'ey-argentina','kpmg-argentina',
            'bdo-argentina','grant-thornton-argentina',
            'crowe-argentina','baker-tilly-argentina',
            'local-mid-tier','custom','none','unknown'
        )),
    engagement_role             TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (engagement_role IN (
            'partner','senior-manager','manager',
            'senior-auditor','staff-auditor',
            'quality-reviewer','compliance-officer',
            'engagement-team-leader','tax-specialist',
            'it-audit-specialist','api','other','unknown'
        )),
    client_class                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (client_class IN (
            'cnv-listed-company','fideicomiso-financiero',
            'alyc-broker-dealer','insurance-company',
            'bank','fci-mutual-fund','pyme',
            'cross-listed-us-issuer',
            'multi-client','other','unknown'
        )),
    audit_phase                 TEXT    NOT NULL DEFAULT ''
        CHECK (audit_phase IN (
            '','planning','interim','year-end',
            'reporting','subsequent-events',
            'quality-review','custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    cliente_emisor_cuit_prefix  TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_emisor_cuit_prefix IN ('','30','33','34')),
    cliente_emisor_cuit_suffix4 TEXT    NOT NULL DEFAULT '',
    auditor_cuil_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (auditor_cuil_prefix IN ('','20','23','24','27')),
    auditor_cuil_suffix4        TEXT    NOT NULL DEFAULT '',
    client_name_hash            TEXT    NOT NULL DEFAULT '',
    engagement_id               TEXT    NOT NULL DEFAULT '',
    confirmation_count          INTEGER NOT NULL DEFAULT 0,
    deficiency_count            INTEGER NOT NULL DEFAULT 0,
    audit_fee_ars_millions      INTEGER NOT NULL DEFAULT 0,
    non_audit_fee_ars_millions  INTEGER NOT NULL DEFAULT 0,
    workpaper_count             INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_workpaper               INTEGER NOT NULL DEFAULT 0 CHECK (has_workpaper IN (0,1)),
    has_engagement_letter       INTEGER NOT NULL DEFAULT 0 CHECK (has_engagement_letter IN (0,1)),
    has_internal_control_assessment INTEGER NOT NULL DEFAULT 0 CHECK (has_internal_control_assessment IN (0,1)),
    has_confirmation_bank       INTEGER NOT NULL DEFAULT 0 CHECK (has_confirmation_bank IN (0,1)),
    has_confirmation_brokerage  INTEGER NOT NULL DEFAULT 0 CHECK (has_confirmation_brokerage IN (0,1)),
    has_confirmation_legal      INTEGER NOT NULL DEFAULT 0 CHECK (has_confirmation_legal IN (0,1)),
    has_letter_representations  INTEGER NOT NULL DEFAULT 0 CHECK (has_letter_representations IN (0,1)),
    has_internal_control_deficiency INTEGER NOT NULL DEFAULT 0 CHECK (has_internal_control_deficiency IN (0,1)),
    has_audit_fee_schedule      INTEGER NOT NULL DEFAULT 0 CHECK (has_audit_fee_schedule IN (0,1)),
    has_audit_committee_minutes INTEGER NOT NULL DEFAULT 0 CHECK (has_audit_committee_minutes IN (0,1)),
    has_management_letter       INTEGER NOT NULL DEFAULT 0 CHECK (has_management_letter IN (0,1)),
    has_audit_plan              INTEGER NOT NULL DEFAULT 0 CHECK (has_audit_plan IN (0,1)),
    has_going_concern_opinion   INTEGER NOT NULL DEFAULT 0 CHECK (has_going_concern_opinion IN (0,1)),
    has_soc_reliance_report     INTEGER NOT NULL DEFAULT 0 CHECK (has_soc_reliance_report IN (0,1)),
    has_subsequent_events_review INTEGER NOT NULL DEFAULT 0 CHECK (has_subsequent_events_review IN (0,1)),
    has_draft_marker            INTEGER NOT NULL DEFAULT 0 CHECK (has_draft_marker IN (0,1)),
    has_independence_breach     INTEGER NOT NULL DEFAULT 0 CHECK (has_independence_breach IN (0,1)),
    has_cross_listed_us_issuer  INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_listed_us_issuer IN (0,1)),
    has_cliente_emisor_cuit     INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_emisor_cuit IN (0,1)),
    has_auditor_cuil            INTEGER NOT NULL DEFAULT 0 CHECK (has_auditor_cuil IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_pre_publication_finding_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_pre_publication_finding_risk IN (0,1)),
    is_counterparty_disclosure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_counterparty_disclosure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_per_password
    ON host_arg_perito(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_per_workpaper
    ON host_arg_perito(engagement_id, reporting_period) WHERE has_workpaper = 1;

CREATE INDEX IF NOT EXISTS idx_per_engagement
    ON host_arg_perito(audit_firm, engagement_id) WHERE has_engagement_letter = 1;

CREATE INDEX IF NOT EXISTS idx_per_ica
    ON host_arg_perito(engagement_id, reporting_period) WHERE has_internal_control_assessment = 1;

CREATE INDEX IF NOT EXISTS idx_per_confirm_bank
    ON host_arg_perito(engagement_id, confirmation_count) WHERE has_confirmation_bank = 1;

CREATE INDEX IF NOT EXISTS idx_per_confirm_brokerage
    ON host_arg_perito(engagement_id, confirmation_count) WHERE has_confirmation_brokerage = 1;

CREATE INDEX IF NOT EXISTS idx_per_confirm_legal
    ON host_arg_perito(engagement_id, confirmation_count) WHERE has_confirmation_legal = 1;

CREATE INDEX IF NOT EXISTS idx_per_letter_rep
    ON host_arg_perito(engagement_id, reporting_period) WHERE has_letter_representations = 1;

CREATE INDEX IF NOT EXISTS idx_per_icdr
    ON host_arg_perito(engagement_id, deficiency_count) WHERE has_internal_control_deficiency = 1;

CREATE INDEX IF NOT EXISTS idx_per_fees
    ON host_arg_perito(audit_firm, audit_fee_ars_millions) WHERE has_audit_fee_schedule = 1;

CREATE INDEX IF NOT EXISTS idx_per_ac_minutes
    ON host_arg_perito(engagement_id, reporting_period) WHERE has_audit_committee_minutes = 1;

CREATE INDEX IF NOT EXISTS idx_per_going_concern
    ON host_arg_perito(engagement_id, reporting_period) WHERE has_going_concern_opinion = 1;

CREATE INDEX IF NOT EXISTS idx_per_draft
    ON host_arg_perito(engagement_id) WHERE has_draft_marker = 1;

CREATE INDEX IF NOT EXISTS idx_per_independence
    ON host_arg_perito(audit_firm, engagement_id) WHERE has_independence_breach = 1;

CREATE INDEX IF NOT EXISTS idx_per_us_listed
    ON host_arg_perito(engagement_id, reporting_period) WHERE has_cross_listed_us_issuer = 1;

CREATE INDEX IF NOT EXISTS idx_per_emisor
    ON host_arg_perito(cliente_emisor_cuit_prefix, cliente_emisor_cuit_suffix4) WHERE has_cliente_emisor_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_per_auditor
    ON host_arg_perito(auditor_cuil_prefix, auditor_cuil_suffix4) WHERE has_auditor_cuil = 1;

CREATE INDEX IF NOT EXISTS idx_per_exposure
    ON host_arg_perito(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_per_pre_pub
    ON host_arg_perito(file_path) WHERE is_pre_publication_finding_risk = 1;

CREATE INDEX IF NOT EXISTS idx_per_counterparty
    ON host_arg_perito(file_path) WHERE is_counterparty_disclosure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_per_drift
    ON host_arg_perito(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_per_kind
    ON host_arg_perito(artifact_kind, audit_firm);
