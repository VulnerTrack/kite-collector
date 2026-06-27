-- host_arg_ppi inventories PPI (Portfolio Personal Inversiones)
-- artifact files cached on Argentine retail, wealth, private-
-- banking, and corporate-treasury workstations.
--
-- PPI is a CNV-registered ALYC ad. integral owned by Banco
-- Galicia (acquired 2017). PPI is positioned as a wealth-
-- management broker with three distinctive surfaces:
--
--   PPI Pro            professional terminal (desktop)
--   PPI Internacional  US-equity / global access tier
--   PPI Quant          algotrading API (launched 2024)
--
-- Cuenta Empresa serves corporate-treasury clients and integrates
-- with Banco Galicia infrastructure via SSO.
--
-- **The PPI broker layer.** Distinct from:
--   - iter 151 winargiolinvertironline  IOL (also Galicia)
--   - iter 152 winargcocoscapital       Cocos fintech
--   - iter 154 winargbalanz             Balanz independent
--   - iter 155 winarghomebroker         HomeBroker white-label
--   - iter 150 winargpyhomebroker       portal scrape lib
--
-- Workstation cache footprint:
--
--   C:\PPI\Pro\config.json             terminal cfg
--   C:\PPI\Pro\positions_<dt>.json     positions cache
--   C:\PPI\Pro\orders_<dt>.json        orders cache
--   C:\PPI\Pro\wealth_portfolio.json   PPI Wealth portfolio
--   C:\PPI\Pro\cuenta_empresa.json     corporate treasury
--   C:\PPI\Pro\perfil_inversor.json    CNV-mandatory survey
--   C:\PPI\Pro\internacional_<dt>.json US equities (PPI Intl)
--   C:\PPI\Pro\tax_statement.xlsx      annual tax statement
--   %APPDATA%\PPI\credentials.json     API credentials
--   %USERPROFILE%\.ppi-quant\          PPI Quant SDK
--
-- PPI-specific risk signals:
--   * Cleartext password in config = T1552 + CNV RG 1023
--   * Galicia SSO token leak = bank-level account compromise
--   * Wealth portfolio > USD 100 K = AFIP RG 5193 trigger
--     + Bienes Personales reporting
--   * Corporate-treasury Cuenta Empresa = corporate cash
--     management, AFIP F.8125 cross-border transfer surface
--   * PPI Internacional US-equity positions = BCRA Com. A
--     7916 outbound USD flow scrutiny
--   * PPI Quant API key = algotrading account compromise
--     (CNV RG 731 art. 23 if HFT pattern)
--   * Perfil Inversor survey content = direct cliente PII
--     (CNV RG 622 art. 19, Ley 25.326)
--   * CER/UVA inflation-linked positions = ARS hedging signal
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes (ALYC)
--   CNV RG 622 art.19 Perfil del Inversor (obligatorio)
--   CNV RG 622 art.50 Operativa con divisas
--   CNV RG 1023      Ciberresiliencia
--   AFIP RG 5193     Securities tax reporting
--   AFIP F.8125      Cross-border transfer
--   BCRA Com. A 7916 Operaciones cambiarias
--   Ley 25.326       Protección de Datos Personales
--   UIF Resol. 30    PEP / AML KYC
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
--   has_galicia_sso                — Banco Galicia SSO token.
--   has_wealth_portfolio           — PPI Wealth offering.
--   has_corporate_treasury         — Cuenta Empresa present.
--   has_perfil_inversor            — mandatory survey present.
--   has_quant_strategy             — PPI Quant API integration.
--   has_international_assets       — PPI Internacional US-eq.
--   has_high_aum                   — > USD 100 K portfolio.
--   has_cer_uva_holdings           — CER/UVA inflation-linked.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable + (password OR
--                                    bearer OR Galicia SSO
--                                    OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_ppi (
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
            'ppi-config','ppi-credentials',
            'ppi-positions-cache','ppi-orders-cache',
            'ppi-wealth-portfolio','ppi-corporate-treasury',
            'ppi-perfil-inversor','ppi-quant-script',
            'ppi-internacional','ppi-account-export',
            'ppi-tax-statement','ppi-installer',
            'other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'retail','wealth','private-banking',
            'corporate-treasury','api','demo',
            'other','unknown'
        )),
    broker_matricula            TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    bearer_token_hash           TEXT    NOT NULL DEFAULT '',
    galicia_sso_hash            TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    portfolio_aum_usd_cents     INTEGER NOT NULL DEFAULT 0,
    international_position_count INTEGER NOT NULL DEFAULT 0,
    cer_uva_position_count      INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_bearer_token            INTEGER NOT NULL DEFAULT 0 CHECK (has_bearer_token IN (0,1)),
    has_galicia_sso             INTEGER NOT NULL DEFAULT 0 CHECK (has_galicia_sso IN (0,1)),
    has_wealth_portfolio        INTEGER NOT NULL DEFAULT 0 CHECK (has_wealth_portfolio IN (0,1)),
    has_corporate_treasury      INTEGER NOT NULL DEFAULT 0 CHECK (has_corporate_treasury IN (0,1)),
    has_perfil_inversor         INTEGER NOT NULL DEFAULT 0 CHECK (has_perfil_inversor IN (0,1)),
    has_quant_strategy          INTEGER NOT NULL DEFAULT 0 CHECK (has_quant_strategy IN (0,1)),
    has_international_assets    INTEGER NOT NULL DEFAULT 0 CHECK (has_international_assets IN (0,1)),
    has_high_aum                INTEGER NOT NULL DEFAULT 0 CHECK (has_high_aum IN (0,1)),
    has_cer_uva_holdings        INTEGER NOT NULL DEFAULT 0 CHECK (has_cer_uva_holdings IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_ppi_password
    ON host_arg_ppi(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_ppi_bearer
    ON host_arg_ppi(file_path) WHERE has_bearer_token = 1;

CREATE INDEX IF NOT EXISTS idx_ppi_galicia_sso
    ON host_arg_ppi(file_path) WHERE has_galicia_sso = 1;

CREATE INDEX IF NOT EXISTS idx_ppi_wealth
    ON host_arg_ppi(broker_matricula, period_yyyymm) WHERE has_wealth_portfolio = 1;

CREATE INDEX IF NOT EXISTS idx_ppi_corporate
    ON host_arg_ppi(broker_matricula, period_yyyymm) WHERE has_corporate_treasury = 1;

CREATE INDEX IF NOT EXISTS idx_ppi_perfil
    ON host_arg_ppi(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_perfil_inversor = 1;

CREATE INDEX IF NOT EXISTS idx_ppi_quant
    ON host_arg_ppi(broker_matricula, period_yyyymm) WHERE has_quant_strategy = 1;

CREATE INDEX IF NOT EXISTS idx_ppi_international
    ON host_arg_ppi(broker_matricula, period_yyyymm) WHERE has_international_assets = 1;

CREATE INDEX IF NOT EXISTS idx_ppi_high_aum
    ON host_arg_ppi(broker_matricula, portfolio_aum_usd_cents) WHERE has_high_aum = 1;

CREATE INDEX IF NOT EXISTS idx_ppi_cer_uva
    ON host_arg_ppi(broker_matricula, period_yyyymm) WHERE has_cer_uva_holdings = 1;

CREATE INDEX IF NOT EXISTS idx_ppi_cliente
    ON host_arg_ppi(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ppi_exposure
    ON host_arg_ppi(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ppi_drift
    ON host_arg_ppi(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_ppi_kind
    ON host_arg_ppi(artifact_kind, account_class);
