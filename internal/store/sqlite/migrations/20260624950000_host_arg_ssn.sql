-- host_arg_ssn inventories SSN (Superintendencia de Seguros de
-- la Nación) insurance investment portfolio + regulatory reporting
-- artifact files cached on Argentine insurance company, ART
-- (Aseguradora de Riesgos del Trabajo), and reinsurance entity
-- workstations.
--
-- AR insurance companies are major institutional investors in AR
-- capital markets — they hold AR sovereign bonds (AL30/GD30/AE38),
-- FCIs (Cohen AM, Galileo, Sintesis-managed), BYMA equity, and
-- CEDEAR. SSN regulates their investment-limit compliance under
-- the Inversiones Admitidas / No Admitidas regime (Ley 20.091 +
-- Resolución SSN 38.708 + Ley 24.557 for ART).
--
-- Distinct from prior iters because the reporter is the insurance
-- company itself (institutional asset-manager perspective), not a
-- broker-dealer ALYC executing trades:
--
--   - vs iter 186 winargcrs       — cross-border CRS/FATCA tax.
--   - vs iter 185 winargcohen     — broker-dealer ALYC terminal.
--   - vs iter 178 winargsintesis  — FCI back-office.
--   - vs iter 174 winargbcrasiscen — BCRA SISCEN regime (banks).
--
-- SSN distinctive features:
--
--   - Inversiones Admitidas regime (admissible-investment limits
--     per category: sov bonds < 70%, corporate bonds < 40%, equity
--     < 30%, FCI < 50%, RE funds < 30%, etc.).
--   - Monthly investment portfolio detail (`inversiones_<period>.
--     xml` or XLSX with category × instrument × custodian rollup).
--   - Custody proof from Caja de Valores (`custodia_<period>.pdf`
--     evidence of unencumbered holdings).
--   - Encaje sobre primas (premium reserves — short-tail vs
--     long-tail line-of-business split).
--   - SSN Resolución 32/2024 cyber-insurance reporting (new
--     2024 regime for cyber-policy issuance + claims).
--   - ART monthly claim payment reports (Ley 24.557).
--   - Reinsurance treaty XML (cross-border ceded premium).
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\SSN\inversiones\<period>.xml      portfolio XML
--   %APPDATA%\SSN\inversiones\<period>.xlsx     portfolio XLSX
--   %APPDATA%\SSN\custodia\<period>.pdf         custody proof
--   %APPDATA%\SSN\estados\<period>.xlsx         financial states
--   %APPDATA%\SSN\primas\<period>.csv           premium written
--   %APPDATA%\SSN\siniestros\<period>.csv       claims
--   %APPDATA%\SSN\encaje\<period>.csv           reserves
--   %APPDATA%\SSN\cyber\<period>.csv            cyber-policy
--   %APPDATA%\SSN\reaseguro\<treaty>.xml        reinsurance
--   %APPDATA%\SSN\art\<period>.csv              ART claims
--   %APPDATA%\SSN\config\ssn_config.ini         tool config
--   %APPDATA%\SSN\receipt\ssn_<period>.xml      filing receipt
--
-- SSN-specific risk signals:
--
--   * Cleartext password in SSN-tool config = T1552 + Ley 20.091
--     art.74 (insurance company recordkeeping).
--   * Investment portfolio XML with > 100 instruments = full
--     institutional portfolio (T1213 + CWE-200 across BYMA/
--     CEDEAR/FCI/sov bonds).
--   * Investment limit breach detected (`limite_excedido=true`)
--     = SSN sanctionable (Ley 20.091 art.32, multa progresiva).
--   * Custody proof PDF readable by group = T1213; Caja de Valores
--     proof of unencumbered holdings under CNV RG 622 art.44.
--   * Cross-border reinsurance treaty = AFIP F.8125 cross-border
--     + FATCA W-8BEN if US reinsurer.
--   * ART claim record with cliente CUIL = trabajador PII (Ley
--     25.326 + SRT regulation).
--   * Cyber-insurance policy record with cliente data = SSN Res.
--     32/2024 + Ley 25.326 (cyber is a "dato sensible" overlay).
--   * Cliente CUIT in policy or investment record = AR resident
--     beneficiary (AFIP F.8125 + Bienes Personales aggregator).
--
-- Regulatory base:
--
--   Ley 20.091       Régimen de Seguros (insurance)
--   Ley 24.557       Riesgos del Trabajo (ART)
--   Ley 26.831       Mercado de Capitales (AR)
--   Resolución SSN 38.708  Inversiones admitidas
--   Resolución SSN 19.106  Capital adequacy
--   Resolución SSN 32/2024 Cyber insurance
--   Resolución SSN 35.726  Reinsurance regime
--   Resolución SSN 1.119   Stress testing
--   CNV RG 622 art.44      Custody by Caja de Valores
--   AFIP RG 5193           Securities tax reporting
--   AFIP F.8125            Cross-border transfer
--   BCRA Com. A 7916       Cross-border FX
--   Ley 25.326             Datos Personales
--   Ley 25.246             PLA/FT
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories (portfolio vault)
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (SSN portal credentials)
--   T1005    Data from Local System (custody PDF, policy CSV)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config        — SSN-tool cleartext.
--   has_investment_portfolio      — investment detail XML/XLSX.
--   has_custody_proof             — Caja de Valores PDF.
--   has_financial_statement       — estados contables.
--   has_premium_report            — primas emitidas.
--   has_claim_report              — siniestros.
--   has_reserve_report            — encaje técnico.
--   has_cyber_policy_report       — SSN Res. 32/2024.
--   has_reinsurance_treaty        — cross-border reinsurance.
--   has_art_claim_record          — ART trabajador claim.
--   has_filing_receipt            — SSN filing receipt.
--   has_investment_limit_breach   — Inversiones No Admitidas.
--   has_cross_border_reinsurance  — non-AR reinsurer.
--   has_institutional_portfolio   — > 100 instruments.
--   has_cliente_cuit              — cliente CUIT detected.
--   has_trabajador_cuil           — ART trabajador CUIL detected.
--   is_credential_exposure_risk   — readable + (password OR
--                                   portfolio OR custody OR policy
--                                   OR cliente CUIT).
--   is_institutional_pii_risk     — readable + (cliente CUIT OR
--                                   trabajador CUIL) + (portfolio
--                                   OR policy OR claim record).

CREATE TABLE IF NOT EXISTS host_arg_ssn (
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
            'ssn-investment-portfolio','ssn-custody-proof',
            'ssn-financial-statement','ssn-premium-report',
            'ssn-claim-report','ssn-reserve-report',
            'ssn-cyber-policy-report','ssn-reinsurance-treaty',
            'ssn-art-claim-record','ssn-filing-receipt',
            'ssn-config','ssn-credentials',
            'ssn-installer','other','unknown'
        )),
    insurer_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (insurer_class IN (
            'life-insurer','non-life-insurer','health-insurer',
            'art-insurer','reinsurer','retrocessionaire',
            'mutual','cooperative','captive',
            'compliance-officer','actuary','api','other','unknown'
        )),
    portfolio_class             TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (portfolio_class IN (
            'ar-sovereign-bond','ar-corporate-bond',
            'ar-equity','ar-fci','cedear',
            'real-estate-fund','time-deposit','cash',
            'multi-asset','other','unknown'
        )),
    line_of_business            TEXT    NOT NULL DEFAULT ''
        CHECK (line_of_business IN (
            '','vida-individual','vida-colectivo',
            'retiro','automotor','incendio','combinado',
            'caucion','responsabilidad-civil',
            'transporte','salud',
            'cyber','riesgos-del-trabajo','agropecuario',
            'reaseguro','custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    trabajador_cuil_prefix      TEXT    NOT NULL DEFAULT ''
        CHECK (trabajador_cuil_prefix IN ('','20','23','24','27')),
    trabajador_cuil_suffix4     TEXT    NOT NULL DEFAULT '',
    ssn_entity_code             TEXT    NOT NULL DEFAULT '',
    ssn_receipt_id              TEXT    NOT NULL DEFAULT '',
    portfolio_instruments_count INTEGER NOT NULL DEFAULT 0,
    sov_bond_position_count     INTEGER NOT NULL DEFAULT 0,
    fci_position_count          INTEGER NOT NULL DEFAULT 0,
    equity_position_count       INTEGER NOT NULL DEFAULT 0,
    cedear_position_count       INTEGER NOT NULL DEFAULT 0,
    portfolio_total_ars_millions INTEGER NOT NULL DEFAULT 0,
    premium_total_ars_millions  INTEGER NOT NULL DEFAULT 0,
    claim_count                 INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_investment_portfolio    INTEGER NOT NULL DEFAULT 0 CHECK (has_investment_portfolio IN (0,1)),
    has_custody_proof           INTEGER NOT NULL DEFAULT 0 CHECK (has_custody_proof IN (0,1)),
    has_financial_statement     INTEGER NOT NULL DEFAULT 0 CHECK (has_financial_statement IN (0,1)),
    has_premium_report          INTEGER NOT NULL DEFAULT 0 CHECK (has_premium_report IN (0,1)),
    has_claim_report            INTEGER NOT NULL DEFAULT 0 CHECK (has_claim_report IN (0,1)),
    has_reserve_report          INTEGER NOT NULL DEFAULT 0 CHECK (has_reserve_report IN (0,1)),
    has_cyber_policy_report     INTEGER NOT NULL DEFAULT 0 CHECK (has_cyber_policy_report IN (0,1)),
    has_reinsurance_treaty      INTEGER NOT NULL DEFAULT 0 CHECK (has_reinsurance_treaty IN (0,1)),
    has_art_claim_record        INTEGER NOT NULL DEFAULT 0 CHECK (has_art_claim_record IN (0,1)),
    has_filing_receipt          INTEGER NOT NULL DEFAULT 0 CHECK (has_filing_receipt IN (0,1)),
    has_investment_limit_breach INTEGER NOT NULL DEFAULT 0 CHECK (has_investment_limit_breach IN (0,1)),
    has_cross_border_reinsurance INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_border_reinsurance IN (0,1)),
    has_institutional_portfolio INTEGER NOT NULL DEFAULT 0 CHECK (has_institutional_portfolio IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    has_trabajador_cuil         INTEGER NOT NULL DEFAULT 0 CHECK (has_trabajador_cuil IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_institutional_pii_risk   INTEGER NOT NULL DEFAULT 0 CHECK (is_institutional_pii_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_ssn_password
    ON host_arg_ssn(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_portfolio
    ON host_arg_ssn(reporting_period, portfolio_instruments_count) WHERE has_investment_portfolio = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_custody
    ON host_arg_ssn(reporting_period) WHERE has_custody_proof = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_premium
    ON host_arg_ssn(reporting_period, premium_total_ars_millions) WHERE has_premium_report = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_claim
    ON host_arg_ssn(reporting_period, claim_count) WHERE has_claim_report = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_cyber
    ON host_arg_ssn(reporting_period) WHERE has_cyber_policy_report = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_reinsurance
    ON host_arg_ssn(reporting_period) WHERE has_reinsurance_treaty = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_art
    ON host_arg_ssn(reporting_period, claim_count) WHERE has_art_claim_record = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_receipt
    ON host_arg_ssn(ssn_receipt_id, reporting_period) WHERE has_filing_receipt = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_breach
    ON host_arg_ssn(reporting_period) WHERE has_investment_limit_breach = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_cross_border
    ON host_arg_ssn(reporting_period) WHERE has_cross_border_reinsurance = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_institutional
    ON host_arg_ssn(reporting_period, portfolio_instruments_count) WHERE has_institutional_portfolio = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_cliente
    ON host_arg_ssn(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_trabajador
    ON host_arg_ssn(trabajador_cuil_prefix, trabajador_cuil_suffix4) WHERE has_trabajador_cuil = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_exposure
    ON host_arg_ssn(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_pii
    ON host_arg_ssn(file_path) WHERE is_institutional_pii_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ssn_drift
    ON host_arg_ssn(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_ssn_kind
    ON host_arg_ssn(artifact_kind, insurer_class);
