-- host_arg_ipo inventories AR IPO / Oferta-Pública-Primaria
-- management artifact files cached on bookrunner-officer, ECM
-- (Equity-Capital-Markets), syndicate-desk, prospectus-counsel,
-- listing-agent, and roadshow-coordinator workstations at the
-- bookrunner ALYCs that lead AR equity issuances on BYMA + NYSE/
-- NASDAQ cross-listings (Santander Investment Securities, Galicia
-- Investments, BBVA AR, Macro Securities, BTG Pactual AR,
-- Allaria, Cohen Bursátil, BACS, Balanz Capital).
--
-- Regulated under:
--
--   - Ley 26.831 (2012)          Ley Mercado de Capitales.
--   - Ley 27.260 (2016)          Reforma Mercado de Capitales.
--   - CNV RG 622 art.13          Prospecto de oferta pública.
--   - CNV RG 622 art.18          Requisitos IPO + listing.
--   - CNV RG 622 art.30-bis      Estabilización post-IPO.
--   - CNV RG 622 art.41          Block-trade fuera de mercado.
--   - CNV RG 731 art.6           Best execution para colocación.
--   - CNV RG 1023                Ciberresiliencia.
--   - BCRA Com. A 8005           Ciberseguridad.
--   - AFIP RG 4815               Exenciones IPO.
--   - UIF Res. 21/2018           PLA/FT.
--   - Ley 26.831 art.117         Insider trading (pre-IPO sensible).
--   - Ley 27.401                 Responsabilidad penal jurídica.
--   - SEC Reg. S / Rule 144A     For NYSE/NASDAQ cross-listed AR
--                                IPOs (ADR Level 3, e.g., Loma
--                                Negra, Corporación América).
--   - SEC Reg. M                 Trading restrictions during IPO
--                                stabilization window.
--
-- Distinct from prior iters because the shape is **equity-primary-
-- issuance underwriting back-office** (single-issuer offering, not
-- ongoing trading):
--
--   - vs iter 205 winargvasp       — crypto exchanges.
--   - vs iter 202 winargtrustee    — bondholder trustee.
--   - vs iter 201 winargtesoro     — Tesoro sovereign primary.
--   - vs iter 199 winargoms        — secondary-market OMS.
--   - vs iter 192 winargma         — M&A advisory.
--   - vs iter 185 winargcohen      — ALYC retail trading desk.
--
-- An IPO artifact leak is doubly-dangerous because:
--
--   * Bookbuilding allocation reveals institutional investor
--     demand pre-pricing (= price-discovery MNPI + reverse-
--     engineer pricing logic + adversarial bidding).
--   * Roadshow itinerary + investor mapping reveals which FIIs
--     the issuer is courting (= front-running by tracking
--     roadshow inquiries to specific tickers).
--   * Final-pricing-decision memo reveals discount-to-market
--     before announcement (= MNPI worth millions).
--   * Underwriting agreement reveals indemnification + termination
--     clauses + market-out triggers (= deal collapse signal).
--   * Lockup expiration calendar reveals selling pressure timing
--     for next 90/180/360 days (= short-trade timing intel).
--   * Greenshoe / over-allotment reveals 15 % extra capacity
--     activated → reveals strong-vs-weak demand signal.
--   * Stabilization activity reveals post-IPO price-support
--     trading (= regulator-defined Reg M / RG 622 art.30-bis
--     audit trail; leak = MNPI of artificial price support).
--   * Syndicate fee split reveals bookrunner economics (=
--     compensation intelligence for competing bookrunners).
--   * Insider restriction list reveals officers/directors
--     blocked from trading (= insider universe map).
--   * Comfort letter reveals auditor's financial-statement
--     subsequent-events review (= MNPI of post-prospectus events).
--   * Legal opinion reveals counsel's opinion on enforceability
--     + tax structure + AR-securities-law compliance.
--
-- IPO distinctive features:
--
--   - Lead bookrunner ALYCs:
--       Santander Investment Securities
--       Galicia Investments
--       BBVA Argentina ECM desk
--       Macro Securities
--       BTG Pactual AR ECM
--       Allaria
--       Cohen Bursátil (also retail)
--       BACS Banco de Crédito y Securitización
--       Balanz Capital
--
--   - AR cross-listed examples (NYSE / NASDAQ ADR Level 3):
--       YPF (1993, NYSE)
--       Grupo Galicia (2000, NASDAQ)
--       BBVA Argentina (2018, NYSE)
--       Loma Negra (2017, NYSE)
--       Corporación América Airports (2018, NYSE)
--       Globant (2014, NYSE)
--       MercadoLibre (2007, NASDAQ)
--       Despegar.com (2017, NYSE)
--       TGS (NYSE)
--       Pampa Energía (NYSE)
--       IRSA / Cresud (NASDAQ / NYSE)
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\IPO\<deal>\
--     roadshow_<issuer>_<yyyymm>.csv             roadshow log
--     bookbuilding_<issuer>_<yyyymmdd>.csv       allocation book
--     underwriting_agreement_<issuer>.pdf        UA draft
--     prospectus_<issuer>_<version>.pdf          prospectus
--     lockup_calendar_<issuer>.csv               lockup tracker
--     greenshoe_exercise_<issuer>_<yyyymmdd>.csv over-allotment
--     stabilization_<issuer>_<yyyymmdd>.csv      price support
--     syndicate_fee_split_<issuer>.csv           fee allocation
--     insider_restriction_<issuer>.csv           insider list
--     comfort_letter_<issuer>_<version>.pdf      auditor comfort
--     legal_opinion_<issuer>_<counsel>.pdf       counsel opinion
--     cnv_rg622_filing_<issuer>_<yyyy>q<n>.xml   CNV filing
--     pricing_decision_<issuer>_<yyyymmdd>.pdf   final pricing
--     ipo_config.ini                             app config
--
-- Regulatory base:
--
--   Ley 26.831              Mercado Capitales
--   Ley 27.260              Reforma
--   CNV RG 622 art.13       Prospecto
--   CNV RG 622 art.18       IPO requisitos
--   CNV RG 622 art.30-bis   Estabilización
--   CNV RG 622 art.41       Block-trade
--   CNV RG 731 art.6        Best execution colocación
--   CNV RG 1023             Cyber
--   BCRA Com. A 8005        Cyber
--   AFIP RG 4815            Exenciones IPO
--   UIF Res. 21/2018        PLA/FT
--   Ley 26.831 art.117      Insider
--   Ley 27.401              Resp. penal
--   SEC Reg. S              Cross-listed AR ADR
--   SEC Rule 144A           QIB resale
--   SEC Reg. M              Stabilization restrictions
--
-- MITRE / CWE / Industry Standards:
--
--   T1213    Data from Info Repositories (IPO vault)
--   T1552    Unsecured Credentials
--   T1005    Data from Local System (bookbuilding)
--   ICMA       International Capital Market Association
--   IPMA       International Primary Market Association
--   SEC Form S-1 / F-1   US IPO registration
--   FORM 20-F            Annual report cross-listed
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config           — cleartext.
--   has_roadshow                     — roadshow log.
--   has_bookbuilding                 — bookbuilding allocation.
--   has_underwriting_agreement       — UA draft.
--   has_prospectus_draft             — prospectus.
--   has_lockup_calendar              — lockup tracker.
--   has_greenshoe                    — over-allotment.
--   has_stabilization                — price support.
--   has_syndicate_fee_split          — fee allocation.
--   has_insider_restriction          — insider list.
--   has_comfort_letter               — auditor comfort.
--   has_legal_opinion                — counsel opinion.
--   has_cnv_rg622_filing             — CNV filing.
--   has_pricing_decision             — final pricing.
--   has_issuer_cuit                  — issuer CUIT.
--   has_bookrunner_cuit              — bookrunner ALYC CUIT.
--   has_large_offering_size          — > 5B ARS notional.
--   is_credential_exposure_risk      — readable + password.
--   is_pre_pricing_disclosure_risk   — readable + (bookbuilding
--                                      OR pricing decision OR
--                                      roadshow).
--   is_allocation_leak_risk          — readable + (bookbuilding
--                                      allocation OR syndicate
--                                      fee split).
--   is_lockup_intelligence_leak      — readable + (lockup OR
--                                      insider restriction OR
--                                      greenshoe).

CREATE TABLE IF NOT EXISTS host_arg_ipo (
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
            'ipo-roadshow','ipo-bookbuilding',
            'ipo-underwriting-agreement','ipo-prospectus-draft',
            'ipo-lockup-calendar','ipo-greenshoe',
            'ipo-stabilization','ipo-syndicate-fee-split',
            'ipo-insider-restriction','ipo-comfort-letter',
            'ipo-legal-opinion','ipo-cnv-rg622-filing',
            'ipo-pricing-decision',
            'ipo-config','ipo-credentials',
            'ipo-installer','other','unknown'
        )),
    bookrunner_alyc             TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (bookrunner_alyc IN (
            'santander-investment','galicia-investments',
            'bbva-ar','macro-securities','btg-pactual-ar',
            'allaria','cohen-bursatil','bacs',
            'balanz-capital','itau-ar',
            'custom','none','unknown'
        )),
    bookrunner_role             TEXT    NOT NULL DEFAULT ''
        CHECK (bookrunner_role IN (
            '','lead-bookrunner','joint-bookrunner',
            'co-manager','senior-co-manager',
            'selling-group-member','stabilizing-agent',
            'listing-agent',
            'custom','none','unknown'
        )),
    offering_type               TEXT    NOT NULL DEFAULT ''
        CHECK (offering_type IN (
            '','ipo','spo','follow-on','rights-issue',
            'block-trade','private-placement-pre-ipo',
            'direct-listing','spac-merger','adr-issuance',
            'custom','none','unknown'
        )),
    ipo_role                    TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (ipo_role IN (
            'bookrunner-officer','equity-capital-markets',
            'syndicate-desk','compliance-officer',
            'prospectus-counsel','listing-agent',
            'roadshow-coordinator','back-office',
            'middle-office','cco','api',
            'other','unknown'
        )),
    listing_venue               TEXT    NOT NULL DEFAULT ''
        CHECK (listing_venue IN (
            '','byma','bcba','mae','nyse','nasdaq',
            'lse','bme','ssx','b3',
            'custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    issuer_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (issuer_cuit_prefix IN ('','30','33','34')),
    issuer_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    bookrunner_cuit_prefix      TEXT    NOT NULL DEFAULT ''
        CHECK (bookrunner_cuit_prefix IN ('','30','33','34')),
    bookrunner_cuit_suffix4     TEXT    NOT NULL DEFAULT '',
    deal_codename               TEXT    NOT NULL DEFAULT '',
    investor_count              INTEGER NOT NULL DEFAULT 0,
    allocation_count            INTEGER NOT NULL DEFAULT 0,
    insider_count               INTEGER NOT NULL DEFAULT 0,
    offering_size_ars           INTEGER NOT NULL DEFAULT 0,
    greenshoe_size_ars          INTEGER NOT NULL DEFAULT 0,
    bookrunner_fee_bps          INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_roadshow                INTEGER NOT NULL DEFAULT 0 CHECK (has_roadshow IN (0,1)),
    has_bookbuilding            INTEGER NOT NULL DEFAULT 0 CHECK (has_bookbuilding IN (0,1)),
    has_underwriting_agreement  INTEGER NOT NULL DEFAULT 0 CHECK (has_underwriting_agreement IN (0,1)),
    has_prospectus_draft        INTEGER NOT NULL DEFAULT 0 CHECK (has_prospectus_draft IN (0,1)),
    has_lockup_calendar         INTEGER NOT NULL DEFAULT 0 CHECK (has_lockup_calendar IN (0,1)),
    has_greenshoe               INTEGER NOT NULL DEFAULT 0 CHECK (has_greenshoe IN (0,1)),
    has_stabilization           INTEGER NOT NULL DEFAULT 0 CHECK (has_stabilization IN (0,1)),
    has_syndicate_fee_split     INTEGER NOT NULL DEFAULT 0 CHECK (has_syndicate_fee_split IN (0,1)),
    has_insider_restriction     INTEGER NOT NULL DEFAULT 0 CHECK (has_insider_restriction IN (0,1)),
    has_comfort_letter          INTEGER NOT NULL DEFAULT 0 CHECK (has_comfort_letter IN (0,1)),
    has_legal_opinion           INTEGER NOT NULL DEFAULT 0 CHECK (has_legal_opinion IN (0,1)),
    has_cnv_rg622_filing        INTEGER NOT NULL DEFAULT 0 CHECK (has_cnv_rg622_filing IN (0,1)),
    has_pricing_decision        INTEGER NOT NULL DEFAULT 0 CHECK (has_pricing_decision IN (0,1)),
    has_issuer_cuit             INTEGER NOT NULL DEFAULT 0 CHECK (has_issuer_cuit IN (0,1)),
    has_bookrunner_cuit         INTEGER NOT NULL DEFAULT 0 CHECK (has_bookrunner_cuit IN (0,1)),
    has_large_offering_size     INTEGER NOT NULL DEFAULT 0 CHECK (has_large_offering_size IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_pre_pricing_disclosure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_pre_pricing_disclosure_risk IN (0,1)),
    is_allocation_leak_risk     INTEGER NOT NULL DEFAULT 0 CHECK (is_allocation_leak_risk IN (0,1)),
    is_lockup_intelligence_leak INTEGER NOT NULL DEFAULT 0 CHECK (is_lockup_intelligence_leak IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_ipo_password
    ON host_arg_ipo(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_roadshow
    ON host_arg_ipo(reporting_period, investor_count) WHERE has_roadshow = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_book
    ON host_arg_ipo(reporting_period, allocation_count) WHERE has_bookbuilding = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_ua
    ON host_arg_ipo(file_path) WHERE has_underwriting_agreement = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_prospectus
    ON host_arg_ipo(reporting_period) WHERE has_prospectus_draft = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_lockup
    ON host_arg_ipo(reporting_period) WHERE has_lockup_calendar = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_greenshoe
    ON host_arg_ipo(reporting_period, greenshoe_size_ars) WHERE has_greenshoe = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_stab
    ON host_arg_ipo(reporting_period) WHERE has_stabilization = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_fee
    ON host_arg_ipo(reporting_period, bookrunner_fee_bps) WHERE has_syndicate_fee_split = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_insider
    ON host_arg_ipo(reporting_period, insider_count) WHERE has_insider_restriction = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_comfort
    ON host_arg_ipo(file_path) WHERE has_comfort_letter = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_legal
    ON host_arg_ipo(file_path) WHERE has_legal_opinion = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_cnv
    ON host_arg_ipo(reporting_period) WHERE has_cnv_rg622_filing = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_pricing
    ON host_arg_ipo(reporting_period) WHERE has_pricing_decision = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_issuer
    ON host_arg_ipo(issuer_cuit_prefix, issuer_cuit_suffix4) WHERE has_issuer_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_bookrunner
    ON host_arg_ipo(bookrunner_cuit_prefix, bookrunner_cuit_suffix4) WHERE has_bookrunner_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_large_size
    ON host_arg_ipo(offering_size_ars) WHERE has_large_offering_size = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_cred_exp
    ON host_arg_ipo(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_prepricing
    ON host_arg_ipo(file_path) WHERE is_pre_pricing_disclosure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_alloc_leak
    ON host_arg_ipo(file_path) WHERE is_allocation_leak_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_lockup_leak
    ON host_arg_ipo(file_path) WHERE is_lockup_intelligence_leak = 1;

CREATE INDEX IF NOT EXISTS idx_ipo_drift
    ON host_arg_ipo(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_ipo_kind
    ON host_arg_ipo(artifact_kind, bookrunner_alyc);
