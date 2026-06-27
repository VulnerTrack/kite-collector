-- host_arg_ir inventories AR issuer Investor Relations (IR)
-- artifact files cached on Argentine CNV-listed-issuer IR
-- director, IR manager, IR analyst, communications-lead, CFO,
-- board secretary, and compliance-officer workstations.
--
-- IR at CNV-listed AR companies (YPF, Galicia, BBVA, Pampa,
-- Tenaris, Loma Negra, Telecom, MELI ADR, IRSA, Cresud) sits on
-- the **other side** of every prior iter — they originate the
-- hecho relevante drafts that feed M&A advisors (iter 192), the
-- insider lists that feed audit-firm working papers (iter 191),
-- the earnings disclosures that feed rating agencies (iter 190),
-- the press releases that move FGS holdings (iter 188), and the
-- financial statements that go into auditor confirmations
-- (iter 191).
--
-- Distinct from prior iters because the shape is **issuer-side
-- communication back-office** (IR perspective):
--
--   - vs iter 193 winargabogado      — securities-law-firm.
--   - vs iter 192 winargma           — M&A advisor.
--   - vs iter 191 winargperito       — audit-firm.
--   - vs iter 190 winargcalificadora — rating agency.
--   - vs iter 188 winargfgs          — sovereign-wealth-fund.
--
-- An IR leak compromises the entire issuer-disclosure chain:
--
--   - Hecho relevante draft = pre-CNV publication of material
--     information (Ley 26.831 art.99 + CNV RG 622 art.50).
--   - Insider list = legal-mandate roster of insiders (Ley
--     26.831 art.103) — leakage = privacy-law breach (Ley
--     25.326) + insider-trading enablement (art.117).
--   - Earnings call script + Q&A = pre-publication guidance
--     (analyst-day prep, sensitivity analysis).
--   - Press release draft = pre-CNV "hecho relevante" or
--     periodic disclosure.
--   - Roadshow materials = forward-looking statements + non-
--     public projections.
--   - Conference call recording = recorded executive
--     statements before formal transcription.
--   - Sustainability / ESG report draft = pre-publication
--     ESG disclosure (CNV RG 800 — 2021 ESG-disclosure regime).
--
-- IR distinctive features:
--
--   - "Insider list" is a legally-mandated roster under Ley
--     26.831 art.103, refreshed on every material event +
--     audited by CNV inspectors. Insider includes officers,
--     directors, attorneys, auditors, M&A advisors, rating
--     analysts who saw the inside information.
--   - "Hecho relevante" (material event disclosure) is the AR
--     equivalent of SEC 8-K but with broader scope (any event
--     that "may affect" trading).
--   - Q4 earnings cycle = peak insider-list maintenance burden.
--   - Analyst-day prep includes "non-public projections" — even
--     ranges count as MNPI under CNV RG 622 art.50.
--   - "Conflict-disclosure" letter from officers / directors =
--     mandatory under CNV RG 622 art.42.
--   - ESG reporting under CNV RG 800 (2021) added new
--     disclosure surface (Scope 1/2/3 emissions, governance).
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\IR\<period>\
--     hecho_relevante_<dt>.pdf                         HR draft
--     insider_list_<period>.csv                        insider list
--     earnings_call_script_q<n>.pdf                    earnings script
--     earnings_call_qa_q<n>.pdf                        Q&A
--     press_release_<topic>.pdf                        press release
--     analyst_report_<analyst>.pdf                     analyst report
--     analyst_coverage_<period>.csv                    coverage list
--     roadshow_<city>.pdf                              roadshow
--     conference_call_<dt>.mp3                         recording
--     sustainability_report_<year>.pdf                 ESG report
--     esg_disclosure_<year>.pdf                        ESG disclosure
--     memoria_anual_<year>.pdf                         annual report
--     estados_contables_<period>.pdf                   financials
--     conflict_disclosure_<officer>.pdf                COI letter
--   %USERPROFILE%\Documents\IR\                       docs root
--
-- IR-specific risk signals:
--
--   * Cleartext password in IR-tool config = T1552 + CNV RG
--     1023.
--   * Hecho relevante in DRAFT = pre-CNV publication (CNV RG
--     622 art.50 + Ley 26.831 art.99/117).
--   * Insider list CSV with > 50 individuals = full insider
--     roster (Ley 26.831 art.103 — PII vault of officers,
--     directors, M&A advisors, auditors, rating analysts).
--   * Earnings call script in DRAFT = pre-publication guidance
--     (MNPI under CNV RG 622 art.50).
--   * Earnings Q&A in DRAFT with sensitivity questions = pre-
--     publication exec answers (MNPI).
--   * Press release in DRAFT = pre-publication hecho relevante.
--   * Roadshow material with non-public projections = forward-
--     looking MNPI.
--   * Conference call recording before formal transcription =
--     unedited exec statements.
--   * Sustainability report in DRAFT = pre-publication CNV RG
--     800 (Scope 1/2/3 emissions disclosure).
--   * Memoria anual in DRAFT = pre-publication annual report.
--   * Conflict disclosure letter = officer / director
--     conflict-of-interest record.
--
-- Regulatory base:
--
--   Ley 26.831       Mercado de Capitales (AR)
--   Ley 26.831 art.99  Hecho relevante
--   Ley 26.831 art.103 Insider list maintenance
--   Ley 26.831 art.117 Insider trading prohibition
--   CNV RG 622 art.42 Transparencia accionaria
--   CNV RG 622 art.50 Insider information
--   CNV RG 622 art.62 Auditor independence (cross-ref)
--   CNV RG 731       Régimen de Agentes
--   CNV RG 800       ESG disclosure (2021)
--   CNV RG 1023      Ciberresiliencia
--   AFIP RG 5193     Securities tax reporting
--   Ley 25.246       PLA/FT (corporate AML)
--   Ley 25.326       Datos Personales (insider list PII)
--
-- US-side regs (cross-listed AR ADR issuers):
--
--   SEC 17 CFR § 240.10b-5  Anti-fraud
--   SEC Reg FD              Fair Disclosure (selective MNPI)
--   SEC Form 6-K            Foreign-private-issuer periodic
--   SEC Form 20-F           Annual report
--   SOX § 302 / 404         Internal-control attestation
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories (IR vault)
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (CNV Autopista portal credentials)
--   T1005    Data from Local System (hecho relevante PDFs)
--   T1199    Trusted Relationship (issuer ↔ advisor chain)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config         — cleartext.
--   has_hecho_relevante_draft      — pre-CNV HR draft.
--   has_insider_list               — insider roster.
--   has_earnings_call_script       — earnings call script.
--   has_earnings_call_qa           — earnings Q&A prep.
--   has_press_release_draft        — press release draft.
--   has_analyst_report             — cached analyst report.
--   has_analyst_coverage_list      — coverage roster.
--   has_roadshow_material          — roadshow deck.
--   has_conference_call_recording  — recording.
--   has_sustainability_report      — ESG report.
--   has_esg_disclosure             — CNV RG 800.
--   has_memoria_anual              — annual report.
--   has_estados_contables_public   — financials.
--   has_conflict_disclosure        — COI letter.
--   has_pre_publication_draft      — DRAFT marker.
--   has_insider_list_large         — > 50 insiders.
--   has_cross_listed_us_issuer     — AR ADR issuer.
--   has_cliente_emisor_cuit        — emisor CUIT.
--   has_insider_cuil               — insider CUIL.
--   is_credential_exposure_risk    — readable + (password OR
--                                    HR draft OR insider list
--                                    OR earnings script OR
--                                    cliente CUIT).
--   is_pre_publication_finding_risk — readable + (HR draft OR
--                                    earnings script draft OR
--                                    press release draft OR
--                                    sustainability draft OR
--                                    memoria draft).
--   is_insider_list_pii_risk       — readable + insider list +
--                                    insider CUIL.

CREATE TABLE IF NOT EXISTS host_arg_ir (
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
            'ir-hecho-relevante-draft','ir-insider-list',
            'ir-earnings-call-script','ir-earnings-call-qa',
            'ir-press-release','ir-analyst-report',
            'ir-analyst-coverage-list','ir-roadshow',
            'ir-conference-call-recording',
            'ir-sustainability-report','ir-esg-disclosure',
            'ir-memoria-anual','ir-estados-contables-public',
            'ir-conflict-disclosure',
            'ir-config','ir-credentials',
            'ir-installer','other','unknown'
        )),
    issuer_class                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (issuer_class IN (
            'panel-lider','panel-general',
            'cedear-issuer','sub-sovereign','sovereign',
            'financial-institution','insurance-company',
            'fideicomiso-financiero','pyme',
            'cross-listed-us-issuer',
            'custom','none','unknown'
        )),
    ir_role                     TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (ir_role IN (
            'ir-director','ir-manager','ir-analyst',
            'communications-lead','ceo','cfo',
            'board-secretary','compliance-officer',
            'general-counsel','api','other','unknown'
        )),
    disclosure_phase            TEXT    NOT NULL DEFAULT ''
        CHECK (disclosure_phase IN (
            '','q1','q2','q3','q4','annual',
            'event-driven','roadshow','custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    cliente_emisor_cuit_prefix  TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_emisor_cuit_prefix IN ('','30','33','34')),
    cliente_emisor_cuit_suffix4 TEXT    NOT NULL DEFAULT '',
    insider_cuil_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (insider_cuil_prefix IN ('','20','23','24','27')),
    insider_cuil_suffix4        TEXT    NOT NULL DEFAULT '',
    issuer_name_hash            TEXT    NOT NULL DEFAULT '',
    cnv_filing_id               TEXT    NOT NULL DEFAULT '',
    insider_count               INTEGER NOT NULL DEFAULT 0,
    analyst_count               INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_hecho_relevante_draft   INTEGER NOT NULL DEFAULT 0 CHECK (has_hecho_relevante_draft IN (0,1)),
    has_insider_list            INTEGER NOT NULL DEFAULT 0 CHECK (has_insider_list IN (0,1)),
    has_earnings_call_script    INTEGER NOT NULL DEFAULT 0 CHECK (has_earnings_call_script IN (0,1)),
    has_earnings_call_qa        INTEGER NOT NULL DEFAULT 0 CHECK (has_earnings_call_qa IN (0,1)),
    has_press_release_draft     INTEGER NOT NULL DEFAULT 0 CHECK (has_press_release_draft IN (0,1)),
    has_analyst_report          INTEGER NOT NULL DEFAULT 0 CHECK (has_analyst_report IN (0,1)),
    has_analyst_coverage_list   INTEGER NOT NULL DEFAULT 0 CHECK (has_analyst_coverage_list IN (0,1)),
    has_roadshow_material       INTEGER NOT NULL DEFAULT 0 CHECK (has_roadshow_material IN (0,1)),
    has_conference_call_recording INTEGER NOT NULL DEFAULT 0 CHECK (has_conference_call_recording IN (0,1)),
    has_sustainability_report   INTEGER NOT NULL DEFAULT 0 CHECK (has_sustainability_report IN (0,1)),
    has_esg_disclosure          INTEGER NOT NULL DEFAULT 0 CHECK (has_esg_disclosure IN (0,1)),
    has_memoria_anual           INTEGER NOT NULL DEFAULT 0 CHECK (has_memoria_anual IN (0,1)),
    has_estados_contables_public INTEGER NOT NULL DEFAULT 0 CHECK (has_estados_contables_public IN (0,1)),
    has_conflict_disclosure     INTEGER NOT NULL DEFAULT 0 CHECK (has_conflict_disclosure IN (0,1)),
    has_pre_publication_draft   INTEGER NOT NULL DEFAULT 0 CHECK (has_pre_publication_draft IN (0,1)),
    has_insider_list_large      INTEGER NOT NULL DEFAULT 0 CHECK (has_insider_list_large IN (0,1)),
    has_cross_listed_us_issuer  INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_listed_us_issuer IN (0,1)),
    has_cliente_emisor_cuit     INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_emisor_cuit IN (0,1)),
    has_insider_cuil            INTEGER NOT NULL DEFAULT 0 CHECK (has_insider_cuil IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_pre_publication_finding_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_pre_publication_finding_risk IN (0,1)),
    is_insider_list_pii_risk    INTEGER NOT NULL DEFAULT 0 CHECK (is_insider_list_pii_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_ir_password
    ON host_arg_ir(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_ir_hecho_relevante
    ON host_arg_ir(cnv_filing_id, reporting_period) WHERE has_hecho_relevante_draft = 1;

CREATE INDEX IF NOT EXISTS idx_ir_insider_list
    ON host_arg_ir(reporting_period, insider_count) WHERE has_insider_list = 1;

CREATE INDEX IF NOT EXISTS idx_ir_earnings_script
    ON host_arg_ir(reporting_period, disclosure_phase) WHERE has_earnings_call_script = 1;

CREATE INDEX IF NOT EXISTS idx_ir_earnings_qa
    ON host_arg_ir(reporting_period, disclosure_phase) WHERE has_earnings_call_qa = 1;

CREATE INDEX IF NOT EXISTS idx_ir_press
    ON host_arg_ir(reporting_period) WHERE has_press_release_draft = 1;

CREATE INDEX IF NOT EXISTS idx_ir_analyst
    ON host_arg_ir(reporting_period, analyst_count) WHERE has_analyst_report = 1;

CREATE INDEX IF NOT EXISTS idx_ir_roadshow
    ON host_arg_ir(reporting_period) WHERE has_roadshow_material = 1;

CREATE INDEX IF NOT EXISTS idx_ir_call
    ON host_arg_ir(reporting_period) WHERE has_conference_call_recording = 1;

CREATE INDEX IF NOT EXISTS idx_ir_sustainability
    ON host_arg_ir(reporting_period) WHERE has_sustainability_report = 1;

CREATE INDEX IF NOT EXISTS idx_ir_esg
    ON host_arg_ir(reporting_period) WHERE has_esg_disclosure = 1;

CREATE INDEX IF NOT EXISTS idx_ir_memoria
    ON host_arg_ir(reporting_period) WHERE has_memoria_anual = 1;

CREATE INDEX IF NOT EXISTS idx_ir_conflict
    ON host_arg_ir(file_path) WHERE has_conflict_disclosure = 1;

CREATE INDEX IF NOT EXISTS idx_ir_insider_large
    ON host_arg_ir(reporting_period, insider_count) WHERE has_insider_list_large = 1;

CREATE INDEX IF NOT EXISTS idx_ir_us_listed
    ON host_arg_ir(reporting_period) WHERE has_cross_listed_us_issuer = 1;

CREATE INDEX IF NOT EXISTS idx_ir_emisor
    ON host_arg_ir(cliente_emisor_cuit_prefix, cliente_emisor_cuit_suffix4) WHERE has_cliente_emisor_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ir_insider_cuil
    ON host_arg_ir(insider_cuil_prefix, insider_cuil_suffix4) WHERE has_insider_cuil = 1;

CREATE INDEX IF NOT EXISTS idx_ir_exposure
    ON host_arg_ir(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ir_pre_pub
    ON host_arg_ir(file_path) WHERE is_pre_publication_finding_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ir_insider_pii
    ON host_arg_ir(file_path) WHERE is_insider_list_pii_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ir_drift
    ON host_arg_ir(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_ir_kind
    ON host_arg_ir(artifact_kind, issuer_class);
