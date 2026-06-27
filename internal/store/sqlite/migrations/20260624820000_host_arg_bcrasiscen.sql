-- host_arg_bcrasiscen inventories BCRA SISCEN (Régimen
-- Informativo de Compraventa de Títulos Valores) artifact
-- files cached on Argentine bank, ALYC broker-dealer, FCI
-- sociedad-gerente, and FCI sociedad-depositaria workstations.
--
-- SISCEN is the **daily securities transaction reporting**
-- regime mandated by BCRA Comunicación "A" 4856 and its
-- subsequent updates. All entidades financieras (Banks and
-- ALYCs registered with BCRA) and FCI managing companies
-- must submit a fixed-width text file (typically named
-- `A6356_YYYYMMDD.txt` or `COMPRAVENTA_YYYYMMDD.txt`) to the
-- BCRA SISCEN portal containing the per-transaction detail
-- for the trading day.
--
-- The SISCEN report carries:
--
--   1. AR sovereign bonds (AL30, GD30, AE38, LECAP, BONCER).
--   2. AR corporate ON (Obligaciones Negociables).
--   3. BYMA / Mercado Argentino equity.
--   4. FCI cuotapartes (subscription / redemption).
--   5. Repo (caución bursátil).
--   6. Forward and swap operations over securities.
--   7. Per-trade cliente CUIT, ticker, quantity, price, ISIN.
--
-- **The BCRA SISCEN reporting layer.** Distinct from:
--
--   - iter ??? winargbcracendeu     — Central de Deudores
--                                     (credit register, BCRA).
--   - iter ??? winargbcracomunic    — BCRA Comunicaciones (cfg).
--   - iter ??? winargbcraforex      — BCRA FX (Com. A 7916).
--   - iter ??? winargcnvaif         — CNV AIF (CNV-side).
--   - iter 159 winargafiprg5193     — AFIP RG 5193 (tax).
--   - iter 112 winargcvsa           — CVSA custody (CSD).
--   - iter 157 winargmaeclear       — MAE OTC clearing.
--   - iter 158 winargprismaweb      — BYMA clearing.
--
-- Workstation cache footprint (typical):
--
--   C:\BCRA\SISCEN\                       SISCEN generator
--   C:\BCRA\SISCEN\Reportes\<YYYY>\       per-year reports
--   C:\BCRA\SISCEN\COMPRAVENTA_<dt>.txt   daily fixed-width
--   C:\BCRA\SISCEN\A6356_<dt>.txt         alt-format daily
--   C:\BCRA\SISCEN\siscen_config.xml      generator cfg
--   C:\BCRA\SISCEN\Templates\<entity>.tpl per-entity templates
--   C:\BCRA\SISCEN\Errors\<dt>.log        rejection log
--   C:\BCRA\Portal\token.dat              SISCEN portal token
--   C:\BCRA\Portal\cert.pfx               BCRA SSL cert
--   %APPDATA%\BCRA\SISCEN\                user data
--   ~/.config/bcra-siscen/
--   ~/.bcra/
--
-- SISCEN-specific risk signals:
--
--   * Cleartext password in siscen_config.xml = T1552 +
--     CNV RG 1023.
--   * BCRA portal token / .pfx cert exposure = upload-channel
--     compromise (T1078, BCRA Com. A 8005).
--   * Per-trade cliente CUIT export = full client trading
--     roster (Ley 26.831 art. 117 secreto bursátil; Ley
--     25.326 PII; UIF Resol. 30 PEP screening trigger).
--   * High-value single trade > USD 1 M = UIF Resol. 30
--     ROS (Reporte Operación Sospechosa) potential trigger.
--   * Repo caución exposure = inter-bank short-term funding
--     intelligence (BCRA monitoring sensitive).
--   * Forward / swap on AR sovereigns = derivative position
--     intelligence (BCRA Com. A 7916 derivatives flag).
--   * Rejection log frequent codes = compliance health
--     metric (BCRA Com. A 8005 reporting fitness).
--   * Foreign-resident cliente CUIT = AFIP F.8125 trigger
--     when cross-border USD outflow > 10 K.
--   * FCI cuotaparte subscriptions > USD 100 K = AFIP RG
--     5193 + Bienes Personales aggregator.
--   * Concentrated counter-party = market-power /
--     manipulation concern (CNV RG 622 art. 50).
--
-- Regulatory base:
--
--   BCRA Com. A 4856 SISCEN Régimen Informativo
--   BCRA Com. A 7724 SISCEN actualización
--   BCRA Com. A 7916 Operaciones cambiarias
--   BCRA Com. A 8005 Ciberseguridad financiera
--   Ley 21.526       Entidades Financieras
--   Ley 26.831       Mercado de Capitales
--   Ley 24.083       FCI
--   Ley 25.326       Datos Personales
--   Ley 25.246       PLA/FT
--   CNV RG 622       Régimen General
--   CNV RG 731       Régimen de Agentes
--   CNV RG 1023      Ciberresiliencia
--   AFIP RG 5193     Securities tax reporting
--   UIF Resol. 30    PEP / AML / ROS
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1530    Data from Cloud Storage Object
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config       — siscen_config cleartext.
--   has_bcra_portal_token        — BCRA portal bearer / cert.
--   has_siscen_report            — formatted SISCEN report.
--   has_sov_bonds                — AR sovereign bonds reported.
--   has_corp_on                  — corporate ON reported.
--   has_byma_equity              — BYMA equity reported.
--   has_fci_cuotapartes          — FCI cuotapartes reported.
--   has_repo_caucion             — REPO / caución bursátil.
--   has_forward_ops              — forward securities ops.
--   has_swap_ops                 — securities swap ops.
--   has_cliente_cuit_export      — full client CUIT roster.
--   has_rejection_log            — BCRA validation rejection.
--   has_high_value_trade         — single trade > USD 1 M.
--   has_foreign_resident         — non-AR cliente CUIT block.
--   has_concentrated_counterparty — single CP > 50 % of vol.
--   is_credential_exposure_risk  — readable + (password OR
--                                  portal token OR client
--                                  CUIT export OR rejection
--                                  log).

CREATE TABLE IF NOT EXISTS host_arg_bcrasiscen (
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
            'siscen-config','siscen-credentials',
            'siscen-portal-token','siscen-portal-cert',
            'siscen-report','siscen-template',
            'siscen-rejection-log','siscen-source-dump',
            'siscen-archive','siscen-installer',
            'other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'entidad-financiera','alyc',
            'sociedad-gerente','sociedad-depositaria',
            'agente-corredor-cambios','agente-fideicomiso',
            'demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'sov-bonds-trades','corp-on-trades',
            'equity-trades','fci-cuotapartes-trades',
            'repo-caucion','forward-ops','swap-ops',
            'multi-product','other','unknown'
        )),
    entity_code                 TEXT    NOT NULL DEFAULT '',
    siscen_form_code            TEXT    NOT NULL DEFAULT ''
        CHECK (siscen_form_code IN ('','A6356','A4856','A7724','COMPRAVENTA','other')),
    reporting_date              TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    portal_token_hash           TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    trade_record_count          INTEGER NOT NULL DEFAULT 0,
    distinct_isins_count        INTEGER NOT NULL DEFAULT 0,
    distinct_clientes_count     INTEGER NOT NULL DEFAULT 0,
    distinct_counterparties_count INTEGER NOT NULL DEFAULT 0,
    high_value_trade_count      INTEGER NOT NULL DEFAULT 0,
    rejection_record_count      INTEGER NOT NULL DEFAULT 0,
    sov_bond_record_count       INTEGER NOT NULL DEFAULT 0,
    corp_on_record_count        INTEGER NOT NULL DEFAULT 0,
    equity_record_count         INTEGER NOT NULL DEFAULT 0,
    fci_record_count            INTEGER NOT NULL DEFAULT 0,
    repo_record_count           INTEGER NOT NULL DEFAULT 0,
    forward_record_count        INTEGER NOT NULL DEFAULT 0,
    swap_record_count           INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_bcra_portal_token       INTEGER NOT NULL DEFAULT 0 CHECK (has_bcra_portal_token IN (0,1)),
    has_siscen_report           INTEGER NOT NULL DEFAULT 0 CHECK (has_siscen_report IN (0,1)),
    has_sov_bonds               INTEGER NOT NULL DEFAULT 0 CHECK (has_sov_bonds IN (0,1)),
    has_corp_on                 INTEGER NOT NULL DEFAULT 0 CHECK (has_corp_on IN (0,1)),
    has_byma_equity             INTEGER NOT NULL DEFAULT 0 CHECK (has_byma_equity IN (0,1)),
    has_fci_cuotapartes         INTEGER NOT NULL DEFAULT 0 CHECK (has_fci_cuotapartes IN (0,1)),
    has_repo_caucion            INTEGER NOT NULL DEFAULT 0 CHECK (has_repo_caucion IN (0,1)),
    has_forward_ops             INTEGER NOT NULL DEFAULT 0 CHECK (has_forward_ops IN (0,1)),
    has_swap_ops                INTEGER NOT NULL DEFAULT 0 CHECK (has_swap_ops IN (0,1)),
    has_cliente_cuit_export     INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit_export IN (0,1)),
    has_rejection_log           INTEGER NOT NULL DEFAULT 0 CHECK (has_rejection_log IN (0,1)),
    has_high_value_trade        INTEGER NOT NULL DEFAULT 0 CHECK (has_high_value_trade IN (0,1)),
    has_foreign_resident        INTEGER NOT NULL DEFAULT 0 CHECK (has_foreign_resident IN (0,1)),
    has_concentrated_counterparty INTEGER NOT NULL DEFAULT 0 CHECK (has_concentrated_counterparty IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_siscen_password
    ON host_arg_bcrasiscen(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_portal_token
    ON host_arg_bcrasiscen(file_path) WHERE has_bcra_portal_token = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_report
    ON host_arg_bcrasiscen(entity_code, reporting_date) WHERE has_siscen_report = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_sov
    ON host_arg_bcrasiscen(entity_code, reporting_date) WHERE has_sov_bonds = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_corp_on
    ON host_arg_bcrasiscen(entity_code, reporting_date) WHERE has_corp_on = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_byma
    ON host_arg_bcrasiscen(entity_code, reporting_date) WHERE has_byma_equity = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_fci
    ON host_arg_bcrasiscen(entity_code, reporting_date) WHERE has_fci_cuotapartes = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_repo
    ON host_arg_bcrasiscen(entity_code, reporting_date) WHERE has_repo_caucion = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_forward
    ON host_arg_bcrasiscen(entity_code, reporting_date) WHERE has_forward_ops = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_swap
    ON host_arg_bcrasiscen(entity_code, reporting_date) WHERE has_swap_ops = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_cliente_export
    ON host_arg_bcrasiscen(entity_code, reporting_date) WHERE has_cliente_cuit_export = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_rejection
    ON host_arg_bcrasiscen(entity_code, reporting_date) WHERE has_rejection_log = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_high_value
    ON host_arg_bcrasiscen(entity_code, reporting_date) WHERE has_high_value_trade = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_foreign
    ON host_arg_bcrasiscen(entity_code, reporting_date) WHERE has_foreign_resident = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_concentrated
    ON host_arg_bcrasiscen(entity_code, reporting_date) WHERE has_concentrated_counterparty = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_exposure
    ON host_arg_bcrasiscen(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_siscen_drift
    ON host_arg_bcrasiscen(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_siscen_kind
    ON host_arg_bcrasiscen(artifact_kind, account_class);
