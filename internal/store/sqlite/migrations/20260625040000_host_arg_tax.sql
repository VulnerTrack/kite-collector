-- host_arg_tax inventories AR tax-advisory-firm artifact files
-- cached on AR Big 4 tax practice + local boutique workstations.
--
-- AR tax-advisory practice is distinct from external audit (iter
-- 191) because:
--
--   - Tax advisory = non-audit service (CNV RG 622 art.61 caps
--     non-audit fees at 50% of audit fee — independence concern).
--   - Tax advisor opines on capital-markets-instrument tax
--     treatment (ON / FCI / CEDEAR / sov-bond exemptions).
--   - Files AFIP returns + represents in AFIP audits.
--   - Negotiates AR-specific regimes (RIPRO industrial promotion,
--     Tierra del Fuego, Mining Regime under Ley 24.196).
--   - Distinct regulator: AFIP (not CNV).
--
-- Top AR tax advisors (Big 4 tax practice + local boutiques):
-- PwC Tax, Deloitte Tax, EY Tax, KPMG Tax + Estudio Beccar Varela
-- Tax, Bruchou Tax, PAGBAM Tax, Lisicki Litvin & Asoc., Estudio
-- Pistrelli Henry Martin, Estudio Diaz Sieiro.
--
-- Distinct from prior iters:
--
--   - vs iter 195 winargacdi      — FCI distribution.
--   - vs iter 194 winargir        — issuer IR.
--   - vs iter 193 winargabogado   — securities law firm.
--   - vs iter 192 winargma        — M&A advisor.
--   - vs iter 191 winargperito    — audit firm.
--   - vs iter 186 winargcrs       — CRS/FATCA reporting (tax
--                                   advisor often files the CRS).
--
-- Tax-advisory distinctive features:
--
--   - Fiscal opinion (dictamen fiscal) on capital-markets-
--     instrument tax treatment — issuer- or investor-side
--     consultation.
--   - Transfer-pricing memo (AFIP RG 1122 + Ley 27.430 art.131).
--   - AFIP RG 5193 securities-tax-reporting filing.
--   - Bienes Personales (BP) annual filing for HNW clients —
--     Ley 23.966 (wealth tax) requires declaration of all AR +
--     foreign securities held.
--   - Régimen Informativo Operaciones Internacionales (RG 4838).
--   - AFIP F.8125 cross-border-transfer authorization.
--   - Régimen de Promoción Industrial / Mining (Ley 24.196) tax
--     position memos.
--   - Tax-litigation defense memo (AFIP enforcement).
--   - Fiscalización AFIP response (tax audit reply).
--   - Tax-position-uncertainty memo (FIN 48 / IAS 12 equivalent).
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\TaxAdvisor\<client>\
--     fiscal_opinion_<topic>.pdf                       opinion
--     transfer_pricing_memo_<period>.pdf               TP memo
--     afip_rg5193_<period>.xml                         RG 5193
--     bienes_personales_<period>.pdf                   BP filing
--     afip_f8125_<dt>.pdf                              F.8125
--     argentina_fatca_<period>.xml                     AR FATCA
--     regimen_industrial_<period>.pdf                  RIPRO
--     tax_litigation_defense.pdf                       litigation
--     fiscalizacion_response.pdf                       audit reply
--     tax_position_uncertainty.pdf                     FIN 48
--     transfer_pricing_studies.pdf                     TP study
--     engagement_letter_tax.pdf                        engagement
--     billable_hours_tax.csv                           hours
--
-- Tax-specific risk signals:
--
--   * Cleartext password in tax-tool config = T1552 + AFIP RG
--     5193 confidentiality.
--   * Fiscal opinion with `RESERVADO` / `DRAFT` = pre-publication
--     legal-fiscal advice (privileged).
--   * Transfer-pricing memo = inter-company-pricing analysis
--     (cross-border attribution).
--   * Bienes Personales filing = HNW client wealth disclosure
--     (Ley 23.966 + Ley 25.246 PLA/FT).
--   * AFIP F.8125 = cross-border wire authorization (regulated
--     transfer under BCRA Com. A 7916).
--   * ARGENTINA-FATCA filing = cross-border-CRS reporting
--     (cross-ref iter 186 winargcrs).
--   * Tax-litigation defense memo = pending AFIP-tax-court action
--     (pre-resolution).
--   * Tax-position-uncertainty memo = FIN 48 / IAS 12 reserve
--     (financial-statement adjustment driver).
--   * Cliente HNW CUIT in BP filing = ultra-high-net-worth PII.
--
-- Regulatory base:
--
--   Ley 23.966       Bienes Personales (wealth tax)
--   Ley 23.576       Obligaciones Negociables (exempt regime)
--   Ley 25.246       PLA/FT
--   Ley 25.326       Datos Personales (cliente PII)
--   Ley 27.430 art.74 Reforma Tributaria (FCI tax)
--   Ley 27.430 art.131 Transfer pricing
--   Ley 24.196       Régimen Minero (mining tax)
--   AFIP RG 1122     Transfer pricing
--   AFIP RG 4056     CRS regime
--   AFIP RG 4838     Cross-border services
--   AFIP RG 5193     Securities tax reporting
--   AFIP RG 5527     Prop-firm payouts
--   AFIP F.8125      Cross-border transfer
--   CNV RG 622 art.61 Auditor independence (non-audit fee 50% cap)
--   FACPCE RT 17     Tax provisions (IAS 12 + FIN 48 AR)
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories (tax vault)
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (AFIP TaxIT credentials)
--   T1005    Data from Local System (fiscal opinion PDFs)
--   T1199    Trusted Relationship (advisor ↔ client chain)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config         — cleartext.
--   has_fiscal_opinion             — fiscal opinion.
--   has_transfer_pricing_memo      — TP memo.
--   has_afip_rg5193_filing         — RG 5193 filing.
--   has_bienes_personales_filing   — BP annual filing.
--   has_afip_f8125                 — cross-border transfer.
--   has_argentina_fatca            — AR FATCA filing.
--   has_regimen_industrial         — RIPRO tax position.
--   has_tax_litigation_defense     — pending AFIP litigation.
--   has_fiscalizacion_response     — AFIP audit response.
--   has_tax_position_uncertainty   — FIN 48 / IAS 12.
--   has_engagement_letter_tax      — tax engagement.
--   has_billable_hours_tax         — tax billable hours.
--   has_pre_publication_draft      — DRAFT marker.
--   has_hnw_filing                 — HNW BP filing.
--   has_cliente_cuit               — cliente CUIT.
--   has_lawyer_cuil                — tax-advisor CUIL.
--   is_credential_exposure_risk    — readable + (password OR
--                                    fiscal opinion OR BP filing
--                                    OR TP memo OR cliente CUIT).
--   is_hnw_pii_risk                — readable + HNW BP filing +
--                                    cliente CUIT.
--   is_cross_border_attribution_risk — readable + (TP memo OR
--                                      F.8125 OR AR FATCA).

CREATE TABLE IF NOT EXISTS host_arg_tax (
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
            'tax-fiscal-opinion','tax-transfer-pricing-memo',
            'tax-afip-rg5193-filing','tax-bienes-personales-filing',
            'tax-afip-f8125','tax-argentina-fatca',
            'tax-regimen-industrial','tax-litigation-defense',
            'tax-fiscalizacion-response','tax-position-uncertainty',
            'tax-engagement-letter','tax-billable-hours',
            'tax-config','tax-credentials',
            'tax-installer','other','unknown'
        )),
    tax_firm                    TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (tax_firm IN (
            'pwc-tax-argentina','deloitte-tax-argentina',
            'ey-tax-argentina','kpmg-tax-argentina',
            'bdo-tax-argentina','beccar-varela-tax',
            'bruchou-tax','pagbam-tax',
            'lisicki-litvin','pistrelli-henry-martin',
            'diaz-sieiro','local-mid-tier',
            'custom','none','unknown'
        )),
    tax_role                    TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (tax_role IN (
            'tax-partner','tax-senior-manager','tax-manager',
            'tax-senior','tax-staff','tax-litigation-partner',
            'transfer-pricing-specialist',
            'cross-border-specialist','crs-fatca-specialist',
            'billing-clerk','compliance-officer',
            'api','other','unknown'
        )),
    tax_regime                  TEXT    NOT NULL DEFAULT ''
        CHECK (tax_regime IN (
            '','impuesto-ganancias','bienes-personales',
            'iva','transfer-pricing','imp-cred-deb-bancarios',
            'imp-sellos','ingresos-brutos',
            'ripro','tierra-del-fuego','mineria',
            'ley-23576-on-exempt','ley-27430-fci',
            'cedear','sov-bond-exempt',
            'crs-fatca','custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    lawyer_cuil_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (lawyer_cuil_prefix IN ('','20','23','24','27')),
    lawyer_cuil_suffix4         TEXT    NOT NULL DEFAULT '',
    client_name_hash            TEXT    NOT NULL DEFAULT '',
    engagement_id               TEXT    NOT NULL DEFAULT '',
    afip_filing_id              TEXT    NOT NULL DEFAULT '',
    billable_hours_count        INTEGER NOT NULL DEFAULT 0,
    hnw_threshold_ars_millions  INTEGER NOT NULL DEFAULT 0,
    tax_reserve_ars_millions    INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_fiscal_opinion          INTEGER NOT NULL DEFAULT 0 CHECK (has_fiscal_opinion IN (0,1)),
    has_transfer_pricing_memo   INTEGER NOT NULL DEFAULT 0 CHECK (has_transfer_pricing_memo IN (0,1)),
    has_afip_rg5193_filing      INTEGER NOT NULL DEFAULT 0 CHECK (has_afip_rg5193_filing IN (0,1)),
    has_bienes_personales_filing INTEGER NOT NULL DEFAULT 0 CHECK (has_bienes_personales_filing IN (0,1)),
    has_afip_f8125              INTEGER NOT NULL DEFAULT 0 CHECK (has_afip_f8125 IN (0,1)),
    has_argentina_fatca         INTEGER NOT NULL DEFAULT 0 CHECK (has_argentina_fatca IN (0,1)),
    has_regimen_industrial      INTEGER NOT NULL DEFAULT 0 CHECK (has_regimen_industrial IN (0,1)),
    has_tax_litigation_defense  INTEGER NOT NULL DEFAULT 0 CHECK (has_tax_litigation_defense IN (0,1)),
    has_fiscalizacion_response  INTEGER NOT NULL DEFAULT 0 CHECK (has_fiscalizacion_response IN (0,1)),
    has_tax_position_uncertainty INTEGER NOT NULL DEFAULT 0 CHECK (has_tax_position_uncertainty IN (0,1)),
    has_engagement_letter_tax   INTEGER NOT NULL DEFAULT 0 CHECK (has_engagement_letter_tax IN (0,1)),
    has_billable_hours_tax      INTEGER NOT NULL DEFAULT 0 CHECK (has_billable_hours_tax IN (0,1)),
    has_pre_publication_draft   INTEGER NOT NULL DEFAULT 0 CHECK (has_pre_publication_draft IN (0,1)),
    has_hnw_filing              INTEGER NOT NULL DEFAULT 0 CHECK (has_hnw_filing IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    has_lawyer_cuil             INTEGER NOT NULL DEFAULT 0 CHECK (has_lawyer_cuil IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_hnw_pii_risk             INTEGER NOT NULL DEFAULT 0 CHECK (is_hnw_pii_risk IN (0,1)),
    is_cross_border_attribution_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_cross_border_attribution_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_tax_password
    ON host_arg_tax(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_tax_opinion
    ON host_arg_tax(engagement_id, reporting_period) WHERE has_fiscal_opinion = 1;

CREATE INDEX IF NOT EXISTS idx_tax_tp
    ON host_arg_tax(engagement_id, reporting_period) WHERE has_transfer_pricing_memo = 1;

CREATE INDEX IF NOT EXISTS idx_tax_rg5193
    ON host_arg_tax(afip_filing_id, reporting_period) WHERE has_afip_rg5193_filing = 1;

CREATE INDEX IF NOT EXISTS idx_tax_bp
    ON host_arg_tax(reporting_period, hnw_threshold_ars_millions) WHERE has_bienes_personales_filing = 1;

CREATE INDEX IF NOT EXISTS idx_tax_f8125
    ON host_arg_tax(engagement_id) WHERE has_afip_f8125 = 1;

CREATE INDEX IF NOT EXISTS idx_tax_fatca
    ON host_arg_tax(reporting_period) WHERE has_argentina_fatca = 1;

CREATE INDEX IF NOT EXISTS idx_tax_ripro
    ON host_arg_tax(engagement_id) WHERE has_regimen_industrial = 1;

CREATE INDEX IF NOT EXISTS idx_tax_litigation
    ON host_arg_tax(engagement_id, reporting_period) WHERE has_tax_litigation_defense = 1;

CREATE INDEX IF NOT EXISTS idx_tax_fisca
    ON host_arg_tax(engagement_id) WHERE has_fiscalizacion_response = 1;

CREATE INDEX IF NOT EXISTS idx_tax_uncertainty
    ON host_arg_tax(engagement_id, tax_reserve_ars_millions) WHERE has_tax_position_uncertainty = 1;

CREATE INDEX IF NOT EXISTS idx_tax_billable
    ON host_arg_tax(tax_firm, billable_hours_count) WHERE has_billable_hours_tax = 1;

CREATE INDEX IF NOT EXISTS idx_tax_hnw
    ON host_arg_tax(reporting_period, hnw_threshold_ars_millions) WHERE has_hnw_filing = 1;

CREATE INDEX IF NOT EXISTS idx_tax_cliente
    ON host_arg_tax(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_tax_lawyer
    ON host_arg_tax(lawyer_cuil_prefix, lawyer_cuil_suffix4) WHERE has_lawyer_cuil = 1;

CREATE INDEX IF NOT EXISTS idx_tax_exposure
    ON host_arg_tax(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_tax_hnw_pii
    ON host_arg_tax(file_path) WHERE is_hnw_pii_risk = 1;

CREATE INDEX IF NOT EXISTS idx_tax_cross_border
    ON host_arg_tax(file_path) WHERE is_cross_border_attribution_risk = 1;

CREATE INDEX IF NOT EXISTS idx_tax_drift
    ON host_arg_tax(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_tax_kind
    ON host_arg_tax(artifact_kind, tax_firm);
