-- host_arg_abogado inventories AR securities-law-firm (estudio
-- jurídico de mercado de capitales) artifact files cached on
-- Argentine partner, senior associate, associate, paralegal, and
-- legal-tech workstations.
--
-- Top AR securities-law firms (Marval O'Farrell Mairal, Bruchou &
-- Funes de Rioja, PAGBAM = Pérez Alati Grondona Benites & Arntsen,
-- Allende & Brea, Estudio Beccar Varela, Tanoira Cassagne,
-- Mitrani Caballero & Ruiz Moreno, Cabanellas Etchebarne Kelly)
-- issue formal legal opinions, true-sale opinions for FF (iter
-- 189), 10b-5 disclosure letters for cross-listed issuers (iter
-- 191), engagement letters, prospecto legal reviews, covenant
-- compliance memos, restructuring plans, CNV enforcement defense.
--
-- Distinct from prior iters because the shape is **attorney-
-- client-privileged legal back-office** (lawyer perspective):
--
--   - vs iter 192 winargma           — M&A advisor back-office.
--   - vs iter 191 winargperito       — audit-firm back-office.
--   - vs iter 190 winargcalificadora — rating agency.
--   - vs iter 189 winargfideicomiso  — issuer side (FF).
--
-- A securities-lawyer leak compromises:
--
--   - Attorney-client privilege (Ley 23.187 art.6 inc.f; CCyCN
--     art.1735 et seq.).
--   - Pre-disclosure CNV regulatory advice (CNV RG 622 art.50
--     insider info).
--   - Billable-hours tracking = competitive intelligence on deal
--     velocity, client relationships, fee structure.
--   - True-sale opinions = legal-isolation analysis (FF
--     securitization SPV structure).
--   - Covenant compliance memos = early-warning of bondholder
--     default / acceleration risk.
--   - Restructuring plan filings = pre-bankruptcy negotiation
--     positions (Ley 24.522 art.66 Concurso Preventivo).
--
-- Securities-law-firm distinctive features:
--
--   - Attorney-client privilege markers (PRIVILEGED, ATTORNEY-
--     CLIENT, ATTORNEY WORK PRODUCT, WORK PRODUCT, SUBJECT TO
--     LEGAL PRIVILEGE).
--   - Engagement letter with hourly rate + retainer schedule.
--   - Billable-hours CSV (per-attorney per-client per-task).
--   - Formal legal opinion structure (heading + opining party +
--     scope of review + caveats + signature block).
--   - True-sale opinion: specifically for FF SPV legal isolation
--     (UCC-1 analog / Ley 24.441 art.16).
--   - 10b-5 letter: SEC Rule 10b-5 disclosure adequacy letter
--     (for AR ADR issuers — iter 191 PCAOB cross-ref).
--   - No-action letter: CNV / SEC informal guidance.
--   - Restructuring plan (Ley 24.522 Concurso Preventivo +
--     Acuerdo Preventivo Extrajudicial).
--   - Enforcement-defense memo (CNV sanción procedure response).
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\LegalSuite\<matter>\
--     legal_opinion_<topic>.pdf                       opinion
--     true_sale_opinion.pdf                           true sale
--     10b5_letter.pdf                                 10b-5
--     no_action_letter.pdf                            no-action
--     engagement_letter.pdf                           engagement
--     billable_hours_<period>.csv                     hours
--     prospecto_legal_review.pdf                      prospecto rev
--     covenant_compliance_memo.pdf                    covenant
--     bondholder_consent.pdf                          consent solic
--     restructuring_plan.pdf                          restructuring
--     enforcement_defense.pdf                         CNV defense
--     privileged_communication.eml                    privileged comm
--     class_action_defense.pdf                        class action
--   %USERPROFILE%\Documents\Legal\                    docs root
--
-- Abogado-specific risk signals:
--
--   * Cleartext password in legal-tool config = T1552 + Ley
--     23.187 art.6 inc.f (attorney confidentiality).
--   * Privileged-communication marker present = attorney-client
--     privileged content (Ley 23.187 + CCyCN art.1735 et seq.).
--   * True-sale opinion in DRAFT = pre-issuance legal analysis
--     (FF SPV structure pre-disclosure).
--   * 10b-5 letter in DRAFT = US securities-law adequacy review
--     pre-publication (SEC Rule 10b-5 / SOX).
--   * Restructuring plan in DRAFT = pre-bankruptcy negotiation
--     position (Ley 24.522 art.66 insider regime applies if
--     debtor is CNV-listed).
--   * Billable-hours CSV with multiple clients = cross-client
--     time tracking (competitive intel; possible conflict of
--     interest disclosure breach).
--   * Engagement letter with hourly rate = fee structure (M&A-
--     fee benchmarking).
--   * Covenant compliance memo flagging breach = pre-default
--     warning to bondholders.
--   * Enforcement-defense memo = pending CNV sanción analysis
--     (regulatory action pre-public).
--   * Bondholder consent solicitation = pending capital-structure
--     change before formal announcement.
--
-- Regulatory base:
--
--   Ley 26.831       Mercado de Capitales (AR)
--   Ley 26.831 art.99  Hecho relevante
--   Ley 26.831 art.117 Insider trading prohibition
--   Ley 24.522       Concursos y Quiebras
--   Ley 24.441       Fideicomiso Civil (true sale)
--   Ley 23.187       Ejercicio Profesional Abogados
--   CCyCN art.1735   Secreto profesional
--   CNV RG 622 art.50 Insider information
--   CNV RG 622 art.42 Transparencia
--   CNV RG 731       Régimen de Agentes
--   CNV RG 1023      Ciberresiliencia
--   Ley 25.246       PLA/FT (legal-counsel obligation)
--   Ley 25.326       Datos Personales (client PII)
--
-- US-side regs (if AR-US cross-border deal):
--
--   SEC Rule 10b-5         Anti-fraud
--   SEC Reg D / S          Private placement
--   SOX § 307              Attorney conduct rules
--   ABA Model Rule 1.6     Confidentiality
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories (privileged vault)
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (legal-portal credentials)
--   T1005    Data from Local System (opinion PDFs)
--   T1199    Trusted Relationship (advisor ↔ client chain)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config        — cleartext.
--   has_legal_opinion             — formal legal opinion.
--   has_true_sale_opinion         — FF SPV legal isolation.
--   has_10b5_letter               — SEC Rule 10b-5 letter.
--   has_no_action_letter          — CNV / SEC informal guidance.
--   has_engagement_letter         — engagement letter.
--   has_billable_hours            — billable-hours CSV.
--   has_prospecto_legal_review    — prospecto markup.
--   has_covenant_compliance_memo  — covenant memo.
--   has_bondholder_consent        — consent solicitation.
--   has_restructuring_plan        — Ley 24.522 plan.
--   has_enforcement_defense       — CNV sanción response.
--   has_privileged_communication  — privileged email/memo.
--   has_class_action_defense      — class-action defense.
--   has_privileged_marker         — ATTORNEY-CLIENT marker.
--   has_pre_publication_draft     — DRAFT marker.
--   has_covenant_breach           — covenant memo with breach.
--   has_cross_border_matter       — cross-jurisdictional.
--   has_cliente_emisor_cuit       — client emisor CUIT.
--   has_lawyer_cuil               — lawyer CUIL.
--   is_credential_exposure_risk   — readable + (password OR
--                                   opinion OR billable hours OR
--                                   privileged OR cliente CUIT).
--   is_privileged_information_risk — readable + (privileged
--                                   marker OR privileged comm OR
--                                   draft + opinion).
--   is_insider_information_risk   — readable + (10b-5 draft OR
--                                   true-sale draft OR restructuring
--                                   draft OR covenant breach OR
--                                   bondholder consent OR
--                                   enforcement defense).

CREATE TABLE IF NOT EXISTS host_arg_abogado (
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
            'abg-legal-opinion','abg-true-sale-opinion',
            'abg-10b5-letter','abg-no-action-letter',
            'abg-engagement-letter','abg-billable-hours',
            'abg-prospecto-legal-review',
            'abg-covenant-compliance-memo',
            'abg-bondholder-consent','abg-restructuring-plan',
            'abg-enforcement-defense',
            'abg-privileged-communication',
            'abg-class-action-defense',
            'abg-config','abg-credentials',
            'abg-installer','other','unknown'
        )),
    law_firm                    TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (law_firm IN (
            'marval-ofarrell-mairal','bruchou-funes-de-rioja',
            'pagbam','allende-brea',
            'beccar-varela','tanoira-cassagne',
            'mitrani-caballero-ruiz-moreno',
            'cabanellas-etchebarne-kelly',
            'estudio-pereyra-sentenac',
            'local-mid-tier','solo-practitioner',
            'custom','none','unknown'
        )),
    legal_role                  TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (legal_role IN (
            'partner','senior-associate','associate',
            'paralegal','of-counsel','knowledge-management',
            'compliance-officer','billing-clerk',
            'legal-tech-administrator','api',
            'other','unknown'
        )),
    matter_class                TEXT    NOT NULL DEFAULT ''
        CHECK (matter_class IN (
            '','ma-transactional','capital-markets-issuance',
            'securitization-ff','restructuring',
            'enforcement-defense','class-action',
            'general-corporate','tax-advisory',
            'cross-border','custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    cliente_emisor_cuit_prefix  TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_emisor_cuit_prefix IN ('','30','33','34')),
    cliente_emisor_cuit_suffix4 TEXT    NOT NULL DEFAULT '',
    lawyer_cuil_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (lawyer_cuil_prefix IN ('','20','23','24','27')),
    lawyer_cuil_suffix4         TEXT    NOT NULL DEFAULT '',
    matter_name_hash            TEXT    NOT NULL DEFAULT '',
    matter_id                   TEXT    NOT NULL DEFAULT '',
    bar_number                  TEXT    NOT NULL DEFAULT '',
    billable_hours_count        INTEGER NOT NULL DEFAULT 0,
    hourly_rate_ars             INTEGER NOT NULL DEFAULT 0,
    retainer_ars_millions       INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_legal_opinion           INTEGER NOT NULL DEFAULT 0 CHECK (has_legal_opinion IN (0,1)),
    has_true_sale_opinion       INTEGER NOT NULL DEFAULT 0 CHECK (has_true_sale_opinion IN (0,1)),
    has_10b5_letter             INTEGER NOT NULL DEFAULT 0 CHECK (has_10b5_letter IN (0,1)),
    has_no_action_letter        INTEGER NOT NULL DEFAULT 0 CHECK (has_no_action_letter IN (0,1)),
    has_engagement_letter       INTEGER NOT NULL DEFAULT 0 CHECK (has_engagement_letter IN (0,1)),
    has_billable_hours          INTEGER NOT NULL DEFAULT 0 CHECK (has_billable_hours IN (0,1)),
    has_prospecto_legal_review  INTEGER NOT NULL DEFAULT 0 CHECK (has_prospecto_legal_review IN (0,1)),
    has_covenant_compliance_memo INTEGER NOT NULL DEFAULT 0 CHECK (has_covenant_compliance_memo IN (0,1)),
    has_bondholder_consent      INTEGER NOT NULL DEFAULT 0 CHECK (has_bondholder_consent IN (0,1)),
    has_restructuring_plan      INTEGER NOT NULL DEFAULT 0 CHECK (has_restructuring_plan IN (0,1)),
    has_enforcement_defense     INTEGER NOT NULL DEFAULT 0 CHECK (has_enforcement_defense IN (0,1)),
    has_privileged_communication INTEGER NOT NULL DEFAULT 0 CHECK (has_privileged_communication IN (0,1)),
    has_class_action_defense    INTEGER NOT NULL DEFAULT 0 CHECK (has_class_action_defense IN (0,1)),
    has_privileged_marker       INTEGER NOT NULL DEFAULT 0 CHECK (has_privileged_marker IN (0,1)),
    has_pre_publication_draft   INTEGER NOT NULL DEFAULT 0 CHECK (has_pre_publication_draft IN (0,1)),
    has_covenant_breach         INTEGER NOT NULL DEFAULT 0 CHECK (has_covenant_breach IN (0,1)),
    has_cross_border_matter     INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_border_matter IN (0,1)),
    has_cliente_emisor_cuit     INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_emisor_cuit IN (0,1)),
    has_lawyer_cuil             INTEGER NOT NULL DEFAULT 0 CHECK (has_lawyer_cuil IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_privileged_information_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_privileged_information_risk IN (0,1)),
    is_insider_information_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_insider_information_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_abg_password
    ON host_arg_abogado(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_abg_opinion
    ON host_arg_abogado(matter_id, reporting_period) WHERE has_legal_opinion = 1;

CREATE INDEX IF NOT EXISTS idx_abg_true_sale
    ON host_arg_abogado(matter_id, reporting_period) WHERE has_true_sale_opinion = 1;

CREATE INDEX IF NOT EXISTS idx_abg_10b5
    ON host_arg_abogado(matter_id, reporting_period) WHERE has_10b5_letter = 1;

CREATE INDEX IF NOT EXISTS idx_abg_engagement
    ON host_arg_abogado(law_firm, matter_id) WHERE has_engagement_letter = 1;

CREATE INDEX IF NOT EXISTS idx_abg_billable
    ON host_arg_abogado(law_firm, billable_hours_count) WHERE has_billable_hours = 1;

CREATE INDEX IF NOT EXISTS idx_abg_prospecto
    ON host_arg_abogado(matter_id, reporting_period) WHERE has_prospecto_legal_review = 1;

CREATE INDEX IF NOT EXISTS idx_abg_covenant
    ON host_arg_abogado(matter_id, reporting_period) WHERE has_covenant_compliance_memo = 1;

CREATE INDEX IF NOT EXISTS idx_abg_consent
    ON host_arg_abogado(matter_id) WHERE has_bondholder_consent = 1;

CREATE INDEX IF NOT EXISTS idx_abg_restructuring
    ON host_arg_abogado(matter_id, reporting_period) WHERE has_restructuring_plan = 1;

CREATE INDEX IF NOT EXISTS idx_abg_enforcement
    ON host_arg_abogado(matter_id, reporting_period) WHERE has_enforcement_defense = 1;

CREATE INDEX IF NOT EXISTS idx_abg_privileged_comm
    ON host_arg_abogado(file_path) WHERE has_privileged_communication = 1;

CREATE INDEX IF NOT EXISTS idx_abg_class_action
    ON host_arg_abogado(matter_id) WHERE has_class_action_defense = 1;

CREATE INDEX IF NOT EXISTS idx_abg_covenant_breach
    ON host_arg_abogado(matter_id) WHERE has_covenant_breach = 1;

CREATE INDEX IF NOT EXISTS idx_abg_cross_border
    ON host_arg_abogado(matter_id) WHERE has_cross_border_matter = 1;

CREATE INDEX IF NOT EXISTS idx_abg_emisor
    ON host_arg_abogado(cliente_emisor_cuit_prefix, cliente_emisor_cuit_suffix4) WHERE has_cliente_emisor_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_abg_lawyer
    ON host_arg_abogado(lawyer_cuil_prefix, lawyer_cuil_suffix4) WHERE has_lawyer_cuil = 1;

CREATE INDEX IF NOT EXISTS idx_abg_exposure
    ON host_arg_abogado(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_abg_privileged
    ON host_arg_abogado(file_path) WHERE is_privileged_information_risk = 1;

CREATE INDEX IF NOT EXISTS idx_abg_insider
    ON host_arg_abogado(file_path) WHERE is_insider_information_risk = 1;

CREATE INDEX IF NOT EXISTS idx_abg_drift
    ON host_arg_abogado(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_abg_kind
    ON host_arg_abogado(artifact_kind, law_firm);
