-- host_arg_ma inventories AR M&A advisory / Investment Banking
-- deal-pipeline artifact files cached on Argentine advisor
-- analyst, associate, VP, MD, and operations workstations.
--
-- AR M&A advisors (Banco Galicia ECM, Cohen Investment Banking,
-- BTG Pactual Argentina, Adcap Securities, Allaria Ledesma IB,
-- plus AR desks of JPMorgan, Morgan Stanley, Citi, Itaú BBA)
-- handle every AR sell-side/buy-side mandate. Regulated under
-- CNV RG 622 art.50 (insider information) + Ley 26.831 art.117
-- (insider trading prohibition) + CNV RG 731 (advisor licensing).
--
-- Distinct from prior iters because the shape is **deal-pipeline
-- back-office** (advisor perspective):
--
--   - vs iter 191 winargperito       — audit-firm back-office.
--   - vs iter 190 winargcalificadora — rating agency.
--   - vs iter 189 winargfideicomiso  — issuer side (FF).
--   - vs iter 185 winargcohen        — broker-dealer ALYC.
--
-- An M&A advisor leak is pre-announcement disclosure (= stock-
-- price-moving event for publicly-traded targets/bidders). The
-- shape cross-references every prior issuer collector — target
-- data, bidder identity, audit synergy modeling, rating-impact
-- analysis all flow through the M&A advisor.
--
-- M&A distinctive features:
--
--   - Deal pipeline (active mandates by stage: origination,
--     pitch, exclusivity, execution, closing).
--   - Mandate type: sell-side (advise seller), buy-side (advise
--     buyer), fairness opinion, defense, divestiture.
--   - Data room manifest = list of files in virtual data room
--     (Intralinks, Datasite, RR Donnelley Venue, Firmex).
--   - Bidder roster = competitive process participants with PII.
--   - DCF / LBO / merger model XLSX = valuation IP.
--   - Quality-of-Earnings (QofE) report = adjusted EBITDA work.
--   - SPA (Sale & Purchase Agreement) drafts with side letters.
--   - Disclosure schedules = full target liabilities exposure.
--   - Closing memo = post-close summary with allocation.
--   - Antitrust / regulatory analysis (CNDC / SEC HSR).
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\IB\<project_name>\
--     pitch_deck.pptx                                  pitch
--     nda_<bidder>.pdf                                 NDA
--     im_<phase>.pdf                                   Info Memo
--     dataroom_manifest.csv                            DR manifest
--     bidder_roster.xlsx                               bidders
--     process_letter_<round>.pdf                       process
--     bid_evaluation_<round>.xlsx                      bid eval
--     dcf_model.xlsx                                   DCF
--     lbo_model.xlsx                                   LBO
--     merger_model.xlsx                                merger
--     qofe_report.pdf                                  QofE
--     spa_draft_<v>.docx                               SPA
--     disclosure_schedules.xlsx                        disclosure
--     closing_memo.pdf                                 closing
--     fairness_opinion.pdf                             fairness
--     comparable_companies.xlsx                        comps
--     precedent_transactions.xlsx                      precedent
--     synergy_analysis.xlsx                            synergy
--     antitrust_memo.pdf                               antitrust
--   %USERPROFILE%\Documents\IB\                       docs root
--
-- M&A-specific risk signals:
--
--   * Cleartext password in IB-tool config = T1552 + CNV RG
--     1023 (Ciberresiliencia).
--   * Pitch deck with `DRAFT` / `CONFIDENCIAL` / `PRIVILEGED` =
--     pre-pitch information (target identification = insider
--     info if target is publicly traded).
--   * NDA with bidder CUIT = bidder universe disclosure
--     (competitive intelligence).
--   * Data room manifest = list of every file shared with
--     bidders (T1213 + CWE-200 across target's operations).
--   * Bidder roster XLSX = full competitive process record
--     (Ley 25.326 PII for individuals on bidder team).
--   * Bid evaluation XLSX = competitive bids with prices /
--     terms — disclosing this changes auction dynamics.
--   * DCF / LBO / merger model = valuation IP + scenario inputs
--     (synergy assumptions = strategic intent leak).
--   * Quality-of-Earnings = adjustments to reported EBITDA
--     (revealing accounting choices the audit firm signed off on).
--   * SPA draft with side letters = transaction terms before
--     signing (insider info regime).
--   * Closing memo = post-close allocation + adjustments (still
--     pre-public if held for working-capital true-up period).
--   * Fairness opinion to board = M&A fairness analysis.
--   * Antitrust memo = CNDC / SEC HSR analysis (regulatory
--     timing leak).
--   * Hecho relevante draft = pre-publication CNV disclosure
--     (Ley 26.831 art.99 + RG 622 art.50).
--
-- Regulatory base:
--
--   Ley 26.831       Mercado de Capitales (AR)
--   Ley 26.831 art.99  Hecho relevante
--   Ley 26.831 art.103 Insider list maintenance
--   Ley 26.831 art.117 Insider trading prohibition
--   CNV RG 622 art.42 Transparencia
--   CNV RG 622 art.50 Insider information
--   CNV RG 731       Régimen de Agentes (advisor licensing)
--   CNV RG 1023      Ciberresiliencia
--   Ley 25.156       Defensa de la Competencia (CNDC)
--   Ley 25.246       PLA/FT (M&A AML — proceeds-of-crime check)
--   Ley 25.326       Datos Personales (bidder team PII)
--
-- US-side regs (if AR-US cross-border M&A):
--
--   SEC Reg M-A             Tender offer rules
--   HSR Act § 7A            Antitrust pre-merger notification
--   SEC § 10(b)-5           Insider trading rule
--   SEC Rule 14e-3          Tender offer insider trading
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories (data room vault)
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (Intralinks / Datasite credentials)
--   T1005    Data from Local System (model XLSX, IM PDF)
--   T1199    Trusted Relationship (advisor ↔ target / bidder chain)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config         — cleartext.
--   has_pitch_deck                 — pitch deck.
--   has_nda                        — NDA.
--   has_information_memorandum     — IM.
--   has_dataroom_manifest          — DR manifest.
--   has_bidder_roster              — bidder roster.
--   has_process_letter             — process letter.
--   has_bid_evaluation             — bid evaluation.
--   has_dcf_model                  — DCF model.
--   has_lbo_model                  — LBO model.
--   has_merger_model               — merger model.
--   has_qofe_report                — QofE report.
--   has_spa_draft                  — SPA draft.
--   has_disclosure_schedules       — disclosure schedules.
--   has_closing_memo               — closing memo.
--   has_fairness_opinion           — fairness opinion.
--   has_synergy_analysis           — synergy analysis.
--   has_antitrust_memo             — antitrust analysis.
--   has_hecho_relevante_draft      — pre-publication CNV disclosure.
--   has_pre_announcement_draft     — DRAFT marker present.
--   has_cross_border_target        — non-AR target.
--   has_public_target              — target is CNV-listed.
--   has_target_cuit                — target CUIT.
--   has_bidder_cuit                — bidder CUIT.
--   is_credential_exposure_risk    — readable + (password OR
--                                    pitch OR IM OR DR manifest
--                                    OR bidder roster OR
--                                    cliente CUIT).
--   is_insider_information_risk    — readable + (pre-announcement
--                                    draft OR pitch OR DR OR SPA
--                                    OR bid evaluation OR hecho
--                                    relevante draft).
--   is_valuation_ip_risk           — readable + (DCF OR LBO OR
--                                    merger model OR synergy).

CREATE TABLE IF NOT EXISTS host_arg_ma (
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
            'ma-pitch-deck','ma-nda',
            'ma-information-memorandum','ma-dataroom-manifest',
            'ma-bidder-roster','ma-process-letter',
            'ma-bid-evaluation','ma-dcf-model',
            'ma-lbo-model','ma-merger-model',
            'ma-qofe-report','ma-spa-draft',
            'ma-disclosure-schedules','ma-closing-memo',
            'ma-fairness-opinion','ma-synergy-analysis',
            'ma-antitrust-memo','ma-hecho-relevante-draft',
            'ma-config','ma-credentials',
            'ma-installer','other','unknown'
        )),
    advisor_firm                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (advisor_firm IN (
            'banco-galicia-ecm','cohen-ib',
            'btg-pactual-argentina','adcap-securities-ib',
            'allaria-ledesma-ib','balanz-ib',
            'jpmorgan-argentina','morgan-stanley-argentina',
            'citi-argentina','itau-bba-argentina',
            'bbva-argentina-ib','santander-rio-ib',
            'local-boutique','custom','none','unknown'
        )),
    deal_role                   TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (deal_role IN (
            'analyst','associate','vp','director',
            'managing-director','partner','operations',
            'compliance-officer','data-room-admin',
            'engagement-team-leader','antitrust-counsel',
            'api','other','unknown'
        )),
    mandate_type                TEXT    NOT NULL DEFAULT ''
        CHECK (mandate_type IN (
            '','sell-side','buy-side','fairness-opinion',
            'defense','divestiture','spin-off',
            'capital-raise','restructuring',
            'custom','none','unknown'
        )),
    deal_stage                  TEXT    NOT NULL DEFAULT ''
        CHECK (deal_stage IN (
            '','origination','pitch','exclusivity',
            'execution','closing','post-closing',
            'custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    target_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (target_cuit_prefix IN ('','30','33','34')),
    target_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    bidder_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (bidder_cuit_prefix IN ('','30','33','34')),
    bidder_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    project_name_hash           TEXT    NOT NULL DEFAULT '',
    deal_id                     TEXT    NOT NULL DEFAULT '',
    bidder_count                INTEGER NOT NULL DEFAULT 0,
    dataroom_file_count         INTEGER NOT NULL DEFAULT 0,
    enterprise_value_ars_millions INTEGER NOT NULL DEFAULT 0,
    advisory_fee_ars_millions   INTEGER NOT NULL DEFAULT 0,
    success_fee_bps             INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_pitch_deck              INTEGER NOT NULL DEFAULT 0 CHECK (has_pitch_deck IN (0,1)),
    has_nda                     INTEGER NOT NULL DEFAULT 0 CHECK (has_nda IN (0,1)),
    has_information_memorandum  INTEGER NOT NULL DEFAULT 0 CHECK (has_information_memorandum IN (0,1)),
    has_dataroom_manifest       INTEGER NOT NULL DEFAULT 0 CHECK (has_dataroom_manifest IN (0,1)),
    has_bidder_roster           INTEGER NOT NULL DEFAULT 0 CHECK (has_bidder_roster IN (0,1)),
    has_process_letter          INTEGER NOT NULL DEFAULT 0 CHECK (has_process_letter IN (0,1)),
    has_bid_evaluation          INTEGER NOT NULL DEFAULT 0 CHECK (has_bid_evaluation IN (0,1)),
    has_dcf_model               INTEGER NOT NULL DEFAULT 0 CHECK (has_dcf_model IN (0,1)),
    has_lbo_model               INTEGER NOT NULL DEFAULT 0 CHECK (has_lbo_model IN (0,1)),
    has_merger_model            INTEGER NOT NULL DEFAULT 0 CHECK (has_merger_model IN (0,1)),
    has_qofe_report             INTEGER NOT NULL DEFAULT 0 CHECK (has_qofe_report IN (0,1)),
    has_spa_draft               INTEGER NOT NULL DEFAULT 0 CHECK (has_spa_draft IN (0,1)),
    has_disclosure_schedules    INTEGER NOT NULL DEFAULT 0 CHECK (has_disclosure_schedules IN (0,1)),
    has_closing_memo            INTEGER NOT NULL DEFAULT 0 CHECK (has_closing_memo IN (0,1)),
    has_fairness_opinion        INTEGER NOT NULL DEFAULT 0 CHECK (has_fairness_opinion IN (0,1)),
    has_synergy_analysis        INTEGER NOT NULL DEFAULT 0 CHECK (has_synergy_analysis IN (0,1)),
    has_antitrust_memo          INTEGER NOT NULL DEFAULT 0 CHECK (has_antitrust_memo IN (0,1)),
    has_hecho_relevante_draft   INTEGER NOT NULL DEFAULT 0 CHECK (has_hecho_relevante_draft IN (0,1)),
    has_pre_announcement_draft  INTEGER NOT NULL DEFAULT 0 CHECK (has_pre_announcement_draft IN (0,1)),
    has_cross_border_target     INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_border_target IN (0,1)),
    has_public_target           INTEGER NOT NULL DEFAULT 0 CHECK (has_public_target IN (0,1)),
    has_target_cuit             INTEGER NOT NULL DEFAULT 0 CHECK (has_target_cuit IN (0,1)),
    has_bidder_cuit             INTEGER NOT NULL DEFAULT 0 CHECK (has_bidder_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_insider_information_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_insider_information_risk IN (0,1)),
    is_valuation_ip_risk        INTEGER NOT NULL DEFAULT 0 CHECK (is_valuation_ip_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_ma_password
    ON host_arg_ma(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_ma_pitch
    ON host_arg_ma(deal_id, reporting_period) WHERE has_pitch_deck = 1;

CREATE INDEX IF NOT EXISTS idx_ma_im
    ON host_arg_ma(deal_id, reporting_period) WHERE has_information_memorandum = 1;

CREATE INDEX IF NOT EXISTS idx_ma_dataroom
    ON host_arg_ma(deal_id, dataroom_file_count) WHERE has_dataroom_manifest = 1;

CREATE INDEX IF NOT EXISTS idx_ma_bidders
    ON host_arg_ma(deal_id, bidder_count) WHERE has_bidder_roster = 1;

CREATE INDEX IF NOT EXISTS idx_ma_bid_eval
    ON host_arg_ma(deal_id, reporting_period) WHERE has_bid_evaluation = 1;

CREATE INDEX IF NOT EXISTS idx_ma_dcf
    ON host_arg_ma(deal_id, enterprise_value_ars_millions) WHERE has_dcf_model = 1;

CREATE INDEX IF NOT EXISTS idx_ma_lbo
    ON host_arg_ma(deal_id, enterprise_value_ars_millions) WHERE has_lbo_model = 1;

CREATE INDEX IF NOT EXISTS idx_ma_merger
    ON host_arg_ma(deal_id, enterprise_value_ars_millions) WHERE has_merger_model = 1;

CREATE INDEX IF NOT EXISTS idx_ma_qofe
    ON host_arg_ma(deal_id, reporting_period) WHERE has_qofe_report = 1;

CREATE INDEX IF NOT EXISTS idx_ma_spa
    ON host_arg_ma(deal_id, reporting_period) WHERE has_spa_draft = 1;

CREATE INDEX IF NOT EXISTS idx_ma_closing
    ON host_arg_ma(deal_id, reporting_period) WHERE has_closing_memo = 1;

CREATE INDEX IF NOT EXISTS idx_ma_fairness
    ON host_arg_ma(deal_id) WHERE has_fairness_opinion = 1;

CREATE INDEX IF NOT EXISTS idx_ma_synergy
    ON host_arg_ma(deal_id, enterprise_value_ars_millions) WHERE has_synergy_analysis = 1;

CREATE INDEX IF NOT EXISTS idx_ma_antitrust
    ON host_arg_ma(deal_id, reporting_period) WHERE has_antitrust_memo = 1;

CREATE INDEX IF NOT EXISTS idx_ma_hecho_relevante
    ON host_arg_ma(deal_id) WHERE has_hecho_relevante_draft = 1;

CREATE INDEX IF NOT EXISTS idx_ma_pre_announcement
    ON host_arg_ma(deal_id) WHERE has_pre_announcement_draft = 1;

CREATE INDEX IF NOT EXISTS idx_ma_cross_border
    ON host_arg_ma(deal_id) WHERE has_cross_border_target = 1;

CREATE INDEX IF NOT EXISTS idx_ma_public_target
    ON host_arg_ma(deal_id) WHERE has_public_target = 1;

CREATE INDEX IF NOT EXISTS idx_ma_target
    ON host_arg_ma(target_cuit_prefix, target_cuit_suffix4) WHERE has_target_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ma_bidder
    ON host_arg_ma(bidder_cuit_prefix, bidder_cuit_suffix4) WHERE has_bidder_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ma_exposure
    ON host_arg_ma(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ma_insider
    ON host_arg_ma(file_path) WHERE is_insider_information_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ma_ip
    ON host_arg_ma(file_path) WHERE is_valuation_ip_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ma_drift
    ON host_arg_ma(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_ma_kind
    ON host_arg_ma(artifact_kind, advisor_firm);
