-- host_arg_calificadora inventories AR Calificadoras de Riesgo
-- (rating agency) back-office artifact files cached on Argentine
-- analyst, rating-committee-member, and methodology-team
-- workstations.
--
-- AR rating agencies (FIX SCR Argentina = Fitch local affiliate,
-- Moody's Local Argentina, Evaluadora Latinoamericana, Untref,
-- ACR — Argentine Credit Rating) issue ratings on FF trust certs,
-- AR sovereign bonds, ON corporate bonds, ALYC-issued instruments,
-- and SSN-regulated insurer paper. Regulated under CNV RG 622
-- art.62 + Ley 26.831.
--
-- Distinct from all prior iters because the shape is **rating-
-- agency back-office** (analyst perspective, NOT issuer):
--
--   - vs iter 189 winargfideicomiso — issuer side (FF).
--   - vs iter 188 winargfgs         — sovereign-wealth-fund.
--   - vs iter 187 winargssn         — private insurer investor.
--   - vs iter 185 winargcohen       — broker-dealer ALYC.
--
-- A rating-agency leak cross-references every issuer collector
-- I built — FFs (iter 189), sov bonds (iter 188), ALYC bonds
-- (iter 185), insurance paper (iter 187), MAV PYME bonds. A
-- single watch-list rotation moves every BYMA-listed bond's
-- price. CNV RG 622 art.62 + art.50 (insider info) regimes both
-- apply.
--
-- Calificadora distinctive features:
--
--   - Issuer-pays model = inherent conflict-of-interest documents
--     (CNV RG 622 art.62 mandates disclosure).
--   - Rating committee composition (5+ analysts + chair) with
--     dissenting opinions on record (pre-disclosure of split
--     committee = market signal).
--   - Watch-list status (positive/negative/developing) =
--     market-moving information before final action.
--   - Methodology documents = intellectual property + systemic
--     model risk (a methodology change can re-rate hundreds of
--     issuers simultaneously).
--   - Internal credit models (PD — Probability of Default, LGD —
--     Loss Given Default, EAD — Exposure at Default).
--   - Fee schedule (initial + surveillance + per-tranche).
--   - Cross-issuer comparable analysis = competitive intelligence.
--   - SOC 1 Type II compliance evidence (for rating-process
--     control).
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\Calificadora\<issuer>\
--     calificacion_<series>.pdf                        rating letter
--     metodologia_<asset_class>.pdf                    methodology
--     comite_calificacion_<n>.pdf                      committee minutes
--     monitoreo_<period>.pdf                           monitoring
--     watchlist_<period>.json                          watch list
--     conflicto_interes_<issuer>.pdf                   COI disclosure
--     honorarios_<issuer>.csv                          fee schedule
--     modelo_pd_<asset_class>.xlsx                     PD model
--     modelo_lgd_<asset_class>.xlsx                    LGD model
--     opinion_disidente_<series>.pdf                   dissent
--     cliente_emisor_roster.json                       issuer roster
--     cnv_filing_<period>.xml                          CNV filing
--     soc_<year>.pdf                                   SOC report
--   %USERPROFILE%\Documents\Calificadora\              docs root
--
-- Calificadora-specific risk signals:
--
--   * Cleartext password in calificadora-tool config = T1552 +
--     CNV RG 1023 (Ciberresiliencia).
--   * Watch-list with pending action (POSITIVO/NEGATIVO/
--     DESARROLLO) = market-moving information (CNV RG 622 art.50;
--     watch-list precedes formal rating action by days/weeks).
--   * Rating committee minutes with dissenting opinion = signal
--     of pending downgrade/upgrade (committee split = high
--     probability of next-cycle action).
--   * Methodology document with cross-issuer applicability =
--     systemic model risk (CWE-200 across all issuers using the
--     model).
--   * Internal credit model (PD/LGD/EAD) = intellectual property
--     + ability to reverse-engineer ratings for arbitrage.
--   * Issuer-pays fee schedule + issuer roster = competitive
--     intelligence on calificadora market share + per-issuer
--     dependency.
--   * Dissenting opinion document = analyst-level disagreement
--     (HR risk if released; signal of methodology shift).
--   * Cliente emisor CUIT + rating letter = primary-issuer
--     exposure map (institutional surveillance).
--
-- Regulatory base:
--
--   Ley 26.831       Mercado de Capitales (AR)
--   CNV RG 622 art.62 Calificadoras de Riesgo
--   CNV RG 622 art.50 Insider information
--   CNV RG 622 art.42 Transparencia
--   CNV RG 731       Régimen de Agentes
--   CNV RG 1023      Ciberresiliencia
--   BCRA Com. A 6310 Validez calificación local
--   AFIP RG 5193     Securities tax reporting
--   Ley 25.246       PLA/FT
--   Ley 25.326       Datos Personales
--
-- Global rating-agency regs (parent affiliates):
--
--   IOSCO Code of Conduct Fundamentals for CRAs
--   SEC NRSRO Rule 17g-1 to 17g-9 (US affiliates)
--   ESMA CRA Regulation 1060/2009 (EU affiliates)
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories (rating vault)
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (calificadora portal)
--   T1005    Data from Local System (model XLSX)
--   T1199    Trusted Relationship (issuer ↔ calificadora chain)
--   CWE-200, CWE-359, CWE-532, CWE-798, CWE-915
--
-- Headline finding shapes:
--
--   has_password_in_config       — cleartext.
--   has_rating_letter            — final rating action.
--   has_methodology_doc          — methodology IP.
--   has_committee_minutes        — rating committee minutes.
--   has_monitoring_report        — per-issuer monitoring.
--   has_watchlist                — current watch list.
--   has_conflict_of_interest_doc — COI disclosure.
--   has_fee_schedule             — issuer-pays fee schedule.
--   has_internal_credit_model    — PD/LGD/EAD model XLSX.
--   has_dissenting_opinion       — split-committee dissent.
--   has_issuer_roster            — cliente emisor roster.
--   has_cnv_filing               — CNV filing.
--   has_soc_report               — SOC 1/2 compliance.
--   has_pending_watch_action     — watch-list ≠ "stable".
--   has_methodology_change       — methodology version bump.
--   has_committee_split          — dissenting opinion present.
--   has_cross_issuer_comparable  — comparable analysis.
--   has_cliente_emisor_cuit      — issuer CUIT detected.
--   has_cliente_analyst_cuil     — analyst CUIL detected.
--   is_credential_exposure_risk  — readable + (password OR rating
--                                  OR methodology OR committee OR
--                                  watch OR issuer CUIT).
--   is_market_moving_info_risk   — readable + (pending watch
--                                  action OR committee split OR
--                                  rating letter OR dissent).
--   is_intellectual_property_risk — readable + (methodology OR
--                                  internal credit model).

CREATE TABLE IF NOT EXISTS host_arg_calificadora (
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
            'cal-rating-letter','cal-methodology-doc',
            'cal-committee-minutes','cal-monitoring-report',
            'cal-watchlist','cal-conflict-of-interest-doc',
            'cal-fee-schedule','cal-internal-credit-model',
            'cal-dissenting-opinion','cal-issuer-roster',
            'cal-cnv-filing','cal-soc-report',
            'cal-config','cal-credentials',
            'cal-installer','other','unknown'
        )),
    calificadora_id             TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (calificadora_id IN (
            'fix-scr-argentina','moodys-local-argentina',
            'evaluadora-latinoamericana','untref','acr',
            'standard-and-poors-argentina','custom','none','unknown'
        )),
    analyst_role                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (analyst_role IN (
            'lead-analyst','backup-analyst','committee-chair',
            'committee-member','methodology-officer',
            'compliance-officer','quality-control','crm',
            'api','other','unknown'
        )),
    rating_class                TEXT    NOT NULL DEFAULT ''
        CHECK (rating_class IN (
            '','aaa','aa','a','bbb','bb','b','ccc','cc','c','d',
            'no-rating','withdrawn','custom','none','unknown'
        )),
    watch_status                TEXT    NOT NULL DEFAULT ''
        CHECK (watch_status IN (
            '','positive','negative','developing','stable',
            'under-review','custom','none','unknown'
        )),
    issuer_class                TEXT    NOT NULL DEFAULT ''
        CHECK (issuer_class IN (
            '','sovereign','sub-sovereign','corporate-bond',
            'fideicomiso-financiero','financial-institution',
            'insurance','pyme-on','structured-finance',
            'covered-bond','project-finance',
            'custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    cliente_emisor_cuit_prefix  TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_emisor_cuit_prefix IN ('','30','33','34')),
    cliente_emisor_cuit_suffix4 TEXT    NOT NULL DEFAULT '',
    cliente_analyst_cuil_prefix TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_analyst_cuil_prefix IN ('','20','23','24','27')),
    cliente_analyst_cuil_suffix4 TEXT   NOT NULL DEFAULT '',
    rating_id                   TEXT    NOT NULL DEFAULT '',
    methodology_version         TEXT    NOT NULL DEFAULT '',
    series_id                   TEXT    NOT NULL DEFAULT '',
    issuer_count                INTEGER NOT NULL DEFAULT 0,
    watch_issuer_count          INTEGER NOT NULL DEFAULT 0,
    dissenting_opinion_count    INTEGER NOT NULL DEFAULT 0,
    model_input_param_count     INTEGER NOT NULL DEFAULT 0,
    fee_total_ars_millions      INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_rating_letter           INTEGER NOT NULL DEFAULT 0 CHECK (has_rating_letter IN (0,1)),
    has_methodology_doc         INTEGER NOT NULL DEFAULT 0 CHECK (has_methodology_doc IN (0,1)),
    has_committee_minutes       INTEGER NOT NULL DEFAULT 0 CHECK (has_committee_minutes IN (0,1)),
    has_monitoring_report       INTEGER NOT NULL DEFAULT 0 CHECK (has_monitoring_report IN (0,1)),
    has_watchlist               INTEGER NOT NULL DEFAULT 0 CHECK (has_watchlist IN (0,1)),
    has_conflict_of_interest_doc INTEGER NOT NULL DEFAULT 0 CHECK (has_conflict_of_interest_doc IN (0,1)),
    has_fee_schedule            INTEGER NOT NULL DEFAULT 0 CHECK (has_fee_schedule IN (0,1)),
    has_internal_credit_model   INTEGER NOT NULL DEFAULT 0 CHECK (has_internal_credit_model IN (0,1)),
    has_dissenting_opinion      INTEGER NOT NULL DEFAULT 0 CHECK (has_dissenting_opinion IN (0,1)),
    has_issuer_roster           INTEGER NOT NULL DEFAULT 0 CHECK (has_issuer_roster IN (0,1)),
    has_cnv_filing              INTEGER NOT NULL DEFAULT 0 CHECK (has_cnv_filing IN (0,1)),
    has_soc_report              INTEGER NOT NULL DEFAULT 0 CHECK (has_soc_report IN (0,1)),
    has_pending_watch_action    INTEGER NOT NULL DEFAULT 0 CHECK (has_pending_watch_action IN (0,1)),
    has_methodology_change      INTEGER NOT NULL DEFAULT 0 CHECK (has_methodology_change IN (0,1)),
    has_committee_split         INTEGER NOT NULL DEFAULT 0 CHECK (has_committee_split IN (0,1)),
    has_cross_issuer_comparable INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_issuer_comparable IN (0,1)),
    has_cliente_emisor_cuit     INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_emisor_cuit IN (0,1)),
    has_cliente_analyst_cuil    INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_analyst_cuil IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_market_moving_info_risk  INTEGER NOT NULL DEFAULT 0 CHECK (is_market_moving_info_risk IN (0,1)),
    is_intellectual_property_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_intellectual_property_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_cal_password
    ON host_arg_calificadora(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_cal_rating
    ON host_arg_calificadora(rating_id, reporting_period) WHERE has_rating_letter = 1;

CREATE INDEX IF NOT EXISTS idx_cal_methodology
    ON host_arg_calificadora(methodology_version, issuer_class) WHERE has_methodology_doc = 1;

CREATE INDEX IF NOT EXISTS idx_cal_committee
    ON host_arg_calificadora(rating_id, reporting_period) WHERE has_committee_minutes = 1;

CREATE INDEX IF NOT EXISTS idx_cal_monitoring
    ON host_arg_calificadora(rating_id, reporting_period) WHERE has_monitoring_report = 1;

CREATE INDEX IF NOT EXISTS idx_cal_watchlist
    ON host_arg_calificadora(reporting_period, watch_issuer_count) WHERE has_watchlist = 1;

CREATE INDEX IF NOT EXISTS idx_cal_coi
    ON host_arg_calificadora(calificadora_id, reporting_period) WHERE has_conflict_of_interest_doc = 1;

CREATE INDEX IF NOT EXISTS idx_cal_fee
    ON host_arg_calificadora(calificadora_id, fee_total_ars_millions) WHERE has_fee_schedule = 1;

CREATE INDEX IF NOT EXISTS idx_cal_model
    ON host_arg_calificadora(methodology_version, issuer_class) WHERE has_internal_credit_model = 1;

CREATE INDEX IF NOT EXISTS idx_cal_dissent
    ON host_arg_calificadora(rating_id, dissenting_opinion_count) WHERE has_dissenting_opinion = 1;

CREATE INDEX IF NOT EXISTS idx_cal_roster
    ON host_arg_calificadora(calificadora_id, issuer_count) WHERE has_issuer_roster = 1;

CREATE INDEX IF NOT EXISTS idx_cal_soc
    ON host_arg_calificadora(calificadora_id, reporting_period) WHERE has_soc_report = 1;

CREATE INDEX IF NOT EXISTS idx_cal_pending_watch
    ON host_arg_calificadora(reporting_period, watch_status) WHERE has_pending_watch_action = 1;

CREATE INDEX IF NOT EXISTS idx_cal_methodology_change
    ON host_arg_calificadora(methodology_version) WHERE has_methodology_change = 1;

CREATE INDEX IF NOT EXISTS idx_cal_split
    ON host_arg_calificadora(rating_id) WHERE has_committee_split = 1;

CREATE INDEX IF NOT EXISTS idx_cal_emisor
    ON host_arg_calificadora(cliente_emisor_cuit_prefix, cliente_emisor_cuit_suffix4) WHERE has_cliente_emisor_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_cal_analyst
    ON host_arg_calificadora(cliente_analyst_cuil_prefix, cliente_analyst_cuil_suffix4) WHERE has_cliente_analyst_cuil = 1;

CREATE INDEX IF NOT EXISTS idx_cal_exposure
    ON host_arg_calificadora(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_cal_market_moving
    ON host_arg_calificadora(file_path) WHERE is_market_moving_info_risk = 1;

CREATE INDEX IF NOT EXISTS idx_cal_ip
    ON host_arg_calificadora(file_path) WHERE is_intellectual_property_risk = 1;

CREATE INDEX IF NOT EXISTS idx_cal_drift
    ON host_arg_calificadora(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_cal_kind
    ON host_arg_calificadora(artifact_kind, calificadora_id);
