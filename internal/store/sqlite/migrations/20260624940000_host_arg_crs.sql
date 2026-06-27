-- host_arg_crs inventories AFIP CRS (Common Reporting Standard)
-- and FATCA (Foreign Account Tax Compliance Act) cross-border tax
-- reporting artifact files cached on Argentine ALYC, bank, and
-- compliance-officer workstations.
--
-- CRS / FATCA reporting transforms every Argentine financial
-- institution into a tax-reporting entity that transmits
-- account-holder records to ~100 jurisdictions via AFIP's
-- Competent Authority channel. Distinct from prior iters because
-- the shape is regulatory XML schema reporting (not a trading
-- terminal):
--
--   - vs iter 185 winargcohen      — broker-dealer ALYC terminal.
--   - vs iter 178 winargsintesis   — FCI back-office.
--   - vs iter 174 winargbcrasiscen — BCRA SISCEN regime.
--
-- CRS / FATCA distinctive features:
--
--   - OECD CRS schema 2.0 XML messages (CRS:CrsBody, FATCA:FATCAFI).
--   - W-8BEN (foreign person attestation, IRS form).
--   - W-9 (US person attestation, IRS form).
--   - Account-holder JSON with NAME + DOB + tax residence (per
--     reportable jurisdiction).
--   - Self-certification forms (account opening + change of
--     circumstances).
--   - Competent Authority transmission XML (AFIP CA-CA channel).
--   - AFIP RG 4056 / RG 3826 / RG 4838 filing receipts.
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\AFIP CRS\<year>\crs_body.xml         AFIP CRS body
--   %APPDATA%\AFIP CRS\<year>\fatca_body.xml       AFIP FATCA body
--   %APPDATA%\AFIP CRS\<year>\ca_transmission.xml  competent-auth
--   %APPDATA%\AFIP CRS\<year>\account_holder_<CUIT>.json
--   %APPDATA%\AFIP CRS\<year>\self_certification_<CUIT>.pdf
--   %APPDATA%\AFIP CRS\w8ben\w8ben_<CUIT>.pdf      foreign-attest
--   %APPDATA%\AFIP CRS\w9\w9_<CUIT>.pdf            US-attest
--   %APPDATA%\AFIP CRS\balance\balance_<YYYYMM>.csv
--   %APPDATA%\AFIP CRS\receipt\afip_rg4056_<YYYY>.xml
--   %APPDATA%\AFIP CRS\receipt\afip_rg3826_<YYYY>.xml
--   %APPDATA%\AFIP CRS\receipt\afip_rg4838_<YYYY>.xml
--   %USERPROFILE%\Documents\AFIP CRS\              docs root
--
-- CRS / FATCA risk signals:
--
--   * Cleartext password in CRS-tool config = T1552 + CNV RG 1023
--     (Ciberresiliencia).
--   * Account-holder JSON with NAME + DOB + tax residence =
--     T1213 + Ley 25.326 + GDPR (cross-border PII for OECD
--     transmission, regulated under AFIP RG 4056).
--   * CRS XML body with > 100 reportable accounts in a single
--     file = institutional volume (AFIP RG 4056 art.6 monthly
--     batch threshold).
--   * W-8BEN / W-9 form readable by world = IRS PII exposure
--     (T1213 + CNV RG 1023; IRS Form Privacy Act notice
--     mandates institutional secure storage).
--   * Competent Authority transmission XML = AFIP-IRS / AFIP-
--     HMRC / etc. CA-CA channel signature.
--   * Balance CSV with USD column > $250k = high-net-worth
--     account (FATCA Annex I §IV threshold).
--   * Self-certification with multi-residence claim = potential
--     tax-haven flag (CRS § §III.A indicia of multi-jurisdiction
--     residence).
--   * AFIP RG filing receipt = proof of regulatory filing
--     compliance (CNV RG 1023 art.8 audit trail).
--
-- Regulatory base:
--
--   Ley 26.831       Mercado de Capitales (AR)
--   CNV RG 731       Régimen de Agentes
--   CNV RG 1023      Ciberresiliencia
--   AFIP RG 4056     CRS regime (OECD CRS implementation)
--   AFIP RG 3826     FATCA regime (IRS FATCA IGA Model 1)
--   AFIP RG 4838     Cross-border services reporting
--   BCRA Com. A 6310 CRS / FATCA implementation
--   BCRA Com. A 7916 Operaciones cambiarias (cross-border)
--   BCRA Com. A 8005 Ciberseguridad financiera
--   AFIP RG 5193     Securities tax reporting
--   Ley 25.246       PLA/FT
--   Ley 25.326       Datos Personales (PII)
--   Ley 27.430 art.74 FCI tax + cross-border
--
-- US-side regs (FATCA):
--
--   IRS § 1471-1474 FATCA chapters
--   IRS Form W-8BEN — foreign person attestation
--   IRS Form W-9    — US person attestation
--   IGA Model 1     — AR-US intergovernmental agreement
--
-- OECD-side regs (CRS):
--
--   OECD CRS Standard 2014 — multilateral CRS
--   OECD CRS Schema 2.0    — XML schema
--   OECD Competent Authority Agreement (MCAA)
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories (PII vault)
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (AFIP TaxIT credentials)
--   T1005    Data from Local System (account-holder JSON)
--   CWE-200, CWE-359, CWE-532, CWE-922
--
-- Headline finding shapes:
--
--   has_password_in_config        — cleartext.
--   has_crs_xml_body              — OECD CRS XML message.
--   has_fatca_xml_body            — IRS FATCA XML message.
--   has_competent_authority       — CA-CA transmission XML.
--   has_account_holder_record     — account-holder JSON.
--   has_w8ben_attestation         — W-8BEN foreign-person form.
--   has_w9_attestation            — W-9 US-person form.
--   has_self_certification        — self-certification form.
--   has_balance_report            — balance CSV/XML.
--   has_afip_filing_receipt       — AFIP RG filing receipt.
--   has_institutional_volume      — > 100 reportable accounts.
--   has_high_net_worth_account    — > $250k USD balance.
--   has_multi_residence_claim     — tax-haven indicia.
--   has_cliente_cuit              — cliente CUIT detected.
--   has_foreign_tin               — foreign TIN detected.
--   is_credential_exposure_risk   — readable + (password OR PII
--                                   record OR attestation OR
--                                   competent-auth OR cliente CUIT).
--   is_cross_border_pii_risk      — account-holder + non-AR
--                                   tax residence + readable.

CREATE TABLE IF NOT EXISTS host_arg_crs (
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
            'crs-xml-body','fatca-xml-body',
            'competent-authority-transmission',
            'account-holder-record',
            'self-certification',
            'w8ben-form','w9-form',
            'balance-report','income-report',
            'afip-rg4056-receipt','afip-rg3826-receipt',
            'afip-rg4838-receipt',
            'crs-config','crs-credentials',
            'crs-installer','other','unknown'
        )),
    reporting_regime            TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (reporting_regime IN (
            'crs','fatca','dual','rg4056','rg3826','rg4838',
            'custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    institution_class           TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (institution_class IN (
            'reporting-fi','non-reporting-fi',
            'depository-institution','custodial-institution',
            'investment-entity','specified-insurance',
            'aly-c-alyc','aly-c-aagi',
            'compliance-officer','api','other','unknown'
        )),
    account_holder_class        TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_holder_class IN (
            'ar-individual','ar-entity',
            'foreign-individual','foreign-entity',
            'us-person','passive-nffe','active-nffe',
            'high-net-worth','dormant',
            'other','unknown'
        )),
    competent_authority         TEXT    NOT NULL DEFAULT ''
        CHECK (competent_authority IN (
            '','afip','irs','hmrc','ato','cra',
            'sat','sii','bzst','euca','custom','none','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    foreign_tin_country_code    TEXT    NOT NULL DEFAULT ''
        CHECK (length(foreign_tin_country_code) <= 3),
    foreign_tin_hash            TEXT    NOT NULL DEFAULT '',
    reporting_fi_giin           TEXT    NOT NULL DEFAULT '',
    afip_receipt_id             TEXT    NOT NULL DEFAULT '',
    account_holder_count        INTEGER NOT NULL DEFAULT 0,
    balance_total_usd_thousands INTEGER NOT NULL DEFAULT 0,
    reportable_jurisdictions    INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_crs_xml_body            INTEGER NOT NULL DEFAULT 0 CHECK (has_crs_xml_body IN (0,1)),
    has_fatca_xml_body          INTEGER NOT NULL DEFAULT 0 CHECK (has_fatca_xml_body IN (0,1)),
    has_competent_authority     INTEGER NOT NULL DEFAULT 0 CHECK (has_competent_authority IN (0,1)),
    has_account_holder_record   INTEGER NOT NULL DEFAULT 0 CHECK (has_account_holder_record IN (0,1)),
    has_w8ben_attestation       INTEGER NOT NULL DEFAULT 0 CHECK (has_w8ben_attestation IN (0,1)),
    has_w9_attestation          INTEGER NOT NULL DEFAULT 0 CHECK (has_w9_attestation IN (0,1)),
    has_self_certification      INTEGER NOT NULL DEFAULT 0 CHECK (has_self_certification IN (0,1)),
    has_balance_report          INTEGER NOT NULL DEFAULT 0 CHECK (has_balance_report IN (0,1)),
    has_afip_filing_receipt     INTEGER NOT NULL DEFAULT 0 CHECK (has_afip_filing_receipt IN (0,1)),
    has_institutional_volume    INTEGER NOT NULL DEFAULT 0 CHECK (has_institutional_volume IN (0,1)),
    has_high_net_worth_account  INTEGER NOT NULL DEFAULT 0 CHECK (has_high_net_worth_account IN (0,1)),
    has_multi_residence_claim   INTEGER NOT NULL DEFAULT 0 CHECK (has_multi_residence_claim IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    has_foreign_tin             INTEGER NOT NULL DEFAULT 0 CHECK (has_foreign_tin IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_cross_border_pii_risk    INTEGER NOT NULL DEFAULT 0 CHECK (is_cross_border_pii_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_crs_password
    ON host_arg_crs(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_crs_xml
    ON host_arg_crs(file_path, reporting_period) WHERE has_crs_xml_body = 1;

CREATE INDEX IF NOT EXISTS idx_crs_fatca
    ON host_arg_crs(file_path, reporting_period) WHERE has_fatca_xml_body = 1;

CREATE INDEX IF NOT EXISTS idx_crs_ca
    ON host_arg_crs(competent_authority, reporting_period) WHERE has_competent_authority = 1;

CREATE INDEX IF NOT EXISTS idx_crs_holder
    ON host_arg_crs(foreign_tin_country_code, account_holder_count) WHERE has_account_holder_record = 1;

CREATE INDEX IF NOT EXISTS idx_crs_w8ben
    ON host_arg_crs(file_path) WHERE has_w8ben_attestation = 1;

CREATE INDEX IF NOT EXISTS idx_crs_w9
    ON host_arg_crs(file_path) WHERE has_w9_attestation = 1;

CREATE INDEX IF NOT EXISTS idx_crs_balance
    ON host_arg_crs(reporting_period, balance_total_usd_thousands) WHERE has_balance_report = 1;

CREATE INDEX IF NOT EXISTS idx_crs_receipt
    ON host_arg_crs(afip_receipt_id, reporting_period) WHERE has_afip_filing_receipt = 1;

CREATE INDEX IF NOT EXISTS idx_crs_high_net_worth
    ON host_arg_crs(reporting_period, balance_total_usd_thousands) WHERE has_high_net_worth_account = 1;

CREATE INDEX IF NOT EXISTS idx_crs_multi_residence
    ON host_arg_crs(foreign_tin_country_code) WHERE has_multi_residence_claim = 1;

CREATE INDEX IF NOT EXISTS idx_crs_institutional
    ON host_arg_crs(reporting_period, account_holder_count) WHERE has_institutional_volume = 1;

CREATE INDEX IF NOT EXISTS idx_crs_cliente
    ON host_arg_crs(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_crs_foreign_tin
    ON host_arg_crs(foreign_tin_country_code) WHERE has_foreign_tin = 1;

CREATE INDEX IF NOT EXISTS idx_crs_exposure
    ON host_arg_crs(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_crs_cross_border_pii
    ON host_arg_crs(foreign_tin_country_code) WHERE is_cross_border_pii_risk = 1;

CREATE INDEX IF NOT EXISTS idx_crs_drift
    ON host_arg_crs(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_crs_kind
    ON host_arg_crs(artifact_kind, institution_class);
