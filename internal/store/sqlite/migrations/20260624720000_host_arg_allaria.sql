-- host_arg_allaria inventories Allaria Ledesma & Cía
-- institutional-broker + FCI-custodian artifact files cached
-- on Argentine pension-fund, insurance, FCI-manager, family-
-- office, and corporate-treasury workstations.
--
-- Allaria Ledesma & Cía is Argentina's largest institutional
-- broker by AUM and the dominant **FCI custodian** (Sociedad
-- Depositaria). Distinct surfaces:
--
--   AlInvest        institutional desktop terminal
--   Allaria Plus    retail offshoot (smaller)
--   Custody bank    FCI Sociedad Depositaria role
--   Block trades    off-book pre-arranged execution
--   Pension funds   ANSeS / FCAA counterparty
--   Insurance       SSN-regulated holding counterparty
--   Family office   UHNW wealth segment
--
-- **The institutional-broker + custodian layer.** Distinct
-- from:
--   - iter 151 winargiolinvertironline IOL retail
--   - iter 152 winargcocoscapital      Cocos fintech
--   - iter 154 winargbalanz            Balanz retail
--   - iter 163 winargppi               PPI wealth-mgmt
--   - iter 158 winargprismaweb         BYMA clearing
--   - iter 157 winargmaeclear          MAE bond clearing
--   - iter 137 winargcvsa              CVSA CSD depository
--   - iter 110 winargfci               FCI sociedad gerente
--
-- Workstation cache footprint:
--
--   C:\Allaria\AlInvest\config.xml      terminal cfg
--   C:\Allaria\AlInvest\positions.json  positions cache
--   C:\Allaria\AlInvest\orders.json     orders cache
--   C:\Allaria\block_trades_<dt>.csv    block-trade book
--   C:\Allaria\custody_recon_<dt>.xml   FCI custody recon
--   C:\Allaria\custody_report_<dt>.xml  daily custody report
--   C:\Allaria\anses_flows_<dt>.csv     ANSeS counterparty
--   C:\Allaria\ssn_holdings_<dt>.xml    insurance holdings
--   %APPDATA%\Allaria\credentials.json  API creds
--
-- Allaria-specific risk signals:
--   * Cleartext password in config = T1552 + CNV RG 1023
--   * Custody-bank role artifacts = FCI manager-vs-custodian
--     reconciliation surface (CNV RG 622 art. 47)
--   * Block trade > USD 1 M = CNV RG 622 art. 23 disclosure
--     obligation (must publish via CNV AIF)
--   * Pension-fund counterparty (ANSeS / FCAA) = systemic
--     sovereign-debt exposure (Ley 26.425 transparency)
--   * Insurance counterparty (SSN-regulated) = solvencia II
--     equivalent reporting
--   * Family-office UHNW = high-impact PII (Ley 25.326)
--   * Institutional AUM > USD 10 M = large-position threshold
--   * CER/UVA + Letras combined = sovereign-debt portfolio
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   Ley 24.083       Fondos Comunes de Inversión (FCI)
--   Ley 26.425       Sistema Integrado Previsional (ANSeS)
--   CNV RG 731       Régimen de Agentes (ALYC ad. integral)
--   CNV RG 622 art.23 Disclosure de bloque
--   CNV RG 622 art.47 Sociedad Depositaria FCI
--   CNV RG 1023      Ciberresiliencia
--   AFIP RG 5193     Securities tax reporting
--   SSN Resol. 38708 Insurance investment regime
--   Ley 25.326       Protección de Datos Personales
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_password_in_config         — config cleartext.
--   has_bearer_token               — API auth bearer leak.
--   has_custody_bank_role          — Allaria as FCI depositary.
--   has_block_trade                — off-book pre-arranged.
--   has_disclosure_obligation      — block > USD 1 M trigger.
--   has_pension_fund_account       — ANSeS / FCAA counterparty.
--   has_insurance_account          — SSN-regulated holding.
--   has_fci_custody_recon          — depositary reconciliation.
--   has_high_aum_institutional     — > USD 10 M.
--   has_cer_uva_holdings           — CER/UVA inflation-linked.
--   has_letras_tesoro              — LECAP/BONCER/Bontes.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable + (password OR
--                                    bearer OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_allaria (
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
            'allaria-config','allaria-credentials',
            'allaria-positions-cache','allaria-orders-cache',
            'allaria-block-trade','allaria-custody-report',
            'allaria-custody-recon','allaria-anses-flows',
            'allaria-ssn-holdings','allaria-installer',
            'other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'institutional','pension-fund','insurance',
            'fci-manager','family-office','corporate-treasury',
            'retail-plus','api','demo','other','unknown'
        )),
    broker_matricula            TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    bearer_token_hash           TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    portfolio_aum_usd_cents     INTEGER NOT NULL DEFAULT 0,
    block_trade_count           INTEGER NOT NULL DEFAULT 0,
    block_trade_max_usd_cents   INTEGER NOT NULL DEFAULT 0,
    fci_custody_recon_count     INTEGER NOT NULL DEFAULT 0,
    pension_fund_count          INTEGER NOT NULL DEFAULT 0,
    insurance_count             INTEGER NOT NULL DEFAULT 0,
    cer_uva_position_count      INTEGER NOT NULL DEFAULT 0,
    letras_position_count       INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_bearer_token            INTEGER NOT NULL DEFAULT 0 CHECK (has_bearer_token IN (0,1)),
    has_custody_bank_role       INTEGER NOT NULL DEFAULT 0 CHECK (has_custody_bank_role IN (0,1)),
    has_block_trade             INTEGER NOT NULL DEFAULT 0 CHECK (has_block_trade IN (0,1)),
    has_disclosure_obligation   INTEGER NOT NULL DEFAULT 0 CHECK (has_disclosure_obligation IN (0,1)),
    has_pension_fund_account    INTEGER NOT NULL DEFAULT 0 CHECK (has_pension_fund_account IN (0,1)),
    has_insurance_account       INTEGER NOT NULL DEFAULT 0 CHECK (has_insurance_account IN (0,1)),
    has_fci_custody_recon       INTEGER NOT NULL DEFAULT 0 CHECK (has_fci_custody_recon IN (0,1)),
    has_high_aum_institutional  INTEGER NOT NULL DEFAULT 0 CHECK (has_high_aum_institutional IN (0,1)),
    has_cer_uva_holdings        INTEGER NOT NULL DEFAULT 0 CHECK (has_cer_uva_holdings IN (0,1)),
    has_letras_tesoro           INTEGER NOT NULL DEFAULT 0 CHECK (has_letras_tesoro IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_allaria_password
    ON host_arg_allaria(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_allaria_bearer
    ON host_arg_allaria(file_path) WHERE has_bearer_token = 1;

CREATE INDEX IF NOT EXISTS idx_allaria_custody_bank
    ON host_arg_allaria(broker_matricula, period_yyyymm) WHERE has_custody_bank_role = 1;

CREATE INDEX IF NOT EXISTS idx_allaria_block
    ON host_arg_allaria(broker_matricula, period_yyyymm, block_trade_max_usd_cents) WHERE has_block_trade = 1;

CREATE INDEX IF NOT EXISTS idx_allaria_disclosure
    ON host_arg_allaria(broker_matricula, period_yyyymm) WHERE has_disclosure_obligation = 1;

CREATE INDEX IF NOT EXISTS idx_allaria_pension
    ON host_arg_allaria(broker_matricula, period_yyyymm) WHERE has_pension_fund_account = 1;

CREATE INDEX IF NOT EXISTS idx_allaria_insurance
    ON host_arg_allaria(broker_matricula, period_yyyymm) WHERE has_insurance_account = 1;

CREATE INDEX IF NOT EXISTS idx_allaria_recon
    ON host_arg_allaria(broker_matricula, period_yyyymm) WHERE has_fci_custody_recon = 1;

CREATE INDEX IF NOT EXISTS idx_allaria_high_aum
    ON host_arg_allaria(broker_matricula, portfolio_aum_usd_cents) WHERE has_high_aum_institutional = 1;

CREATE INDEX IF NOT EXISTS idx_allaria_cer_uva
    ON host_arg_allaria(broker_matricula, period_yyyymm) WHERE has_cer_uva_holdings = 1;

CREATE INDEX IF NOT EXISTS idx_allaria_letras
    ON host_arg_allaria(broker_matricula, period_yyyymm) WHERE has_letras_tesoro = 1;

CREATE INDEX IF NOT EXISTS idx_allaria_cliente
    ON host_arg_allaria(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_allaria_exposure
    ON host_arg_allaria(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_allaria_drift
    ON host_arg_allaria(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_allaria_kind
    ON host_arg_allaria(artifact_kind, account_class);
