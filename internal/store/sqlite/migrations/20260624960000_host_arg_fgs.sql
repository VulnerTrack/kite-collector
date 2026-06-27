-- host_arg_fgs inventories ANSES FGS (Fondo de Garantía de
-- Sustentabilidad, Ley 26.425) sovereign-wealth-fund artifact
-- files cached on Argentine government, ANSES, and FGS executive
-- workstations.
--
-- FGS is the AR public pension sovereign wealth fund. Distinct
-- from all prior iters because the shape is **state-owned
-- sovereign-wealth-fund** under public-administration law (Ley
-- 24.156), not CNV RG 731 (broker-dealer ALYC):
--
--   - vs iter 187 winargssn       — private insurance investor.
--   - vs iter 186 winargcrs       — cross-border CRS/FATCA tax.
--   - vs iter 185 winargcohen     — broker-dealer ALYC.
--   - vs iter 178 winargsintesis  — FCI back-office.
--
-- FGS is the largest single institutional holder of AR equity
-- (~10-15% of Merval panel líder market cap) plus the dominant
-- holder of LICs (Letras Intransferibles — non-tradeable special
-- government instruments unique to FGS). Its leakage is
-- politically sensitive (every Merval move with FGS rotation =
-- market-moving news, BCRA/CNV insider-information regime).
--
-- FGS distinctive features:
--
--   - Cartera FGS detail (institutional portfolio with BYMA
--     equity, LIC, sov bonds, ON, FCI, real-estate-fund mix).
--   - LIC (Letras Intransferibles) — special non-tradeable
--     government instrument FGS holds against ANSES SIPA pension
--     obligations.
--   - Lineamientos de Inversión policy docs (Resolución FGS
--     specific framework).
--   - Comité de Inversiones + Directorio actas (board minutes).
--   - Primary-market auction bids (Lecaps / Bonares / Boncer
--     subscription via BCRA window).
--   - ANSES SIPA pension cross-references (pensioner CUIL).
--   - Custodia records (CVSA-side institutional custody).
--   - Acción de Reposición — equity-stake voting record.
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\FGS\cartera\<period>.xlsx           portfolio
--   %APPDATA%\FGS\lic\lic_<series>.xml            LIC subscription
--   %APPDATA%\FGS\directorio\acta_<n>.pdf         board minutes
--   %APPDATA%\FGS\comite\inv_<period>.pdf         committee minutes
--   %APPDATA%\FGS\lineamientos\<year>.pdf         policy doc
--   %APPDATA%\FGS\subasta\bid_<auction>.xml       auction bid
--   %APPDATA%\FGS\subasta\result_<auction>.xml    auction result
--   %APPDATA%\FGS\custodia\<period>.pdf           custody record
--   %APPDATA%\FGS\votacion\acta_<asambl>.pdf      voting record
--   %APPDATA%\FGS\anses\sipa_<period>.csv         SIPA pension
--   %APPDATA%\FGS\receipt\receipt_<period>.xml    filing receipt
--   %APPDATA%\FGS\config\fgs_config.ini           tool config
--   %USERPROFILE%\Documents\FGS\                  docs root
--
-- FGS-specific risk signals:
--
--   * Cleartext password in FGS-tool config = T1552 + Ley 24.156
--     art.101 (Sindicatura General de la Nación audit).
--   * Cartera FGS XLSX with > 100 instruments = full sovereign-
--     wealth-fund portfolio (T1213, blast-radius = AR equity
--     market-moving information, CNV insider-info regime).
--   * LIC subscription record = ANSES-Treasury intra-government
--     debt (T1213; LIC face value is the actuarial liability of
--     the public pension system).
--   * Comité / Directorio acta = pre-disclosure of investment
--     decisions (CNV RG 622 art.50 insider-information regime
--     applies because FGS is an institutional investor in CNV-
--     regulated public companies).
--   * Voting-record (acta de asamblea) = AR-corporate-governance
--     position (FGS as >5% shareholder votes on board seats,
--     dividends, M&A — CNV RG 622 art.42 transparency regime).
--   * SIPA pension CSV with trabajador CUIL = ANSES PII vault
--     (Ley 25.326 + Ley 24.241 pension privacy).
--   * Primary-market auction bid pre-result = market-moving
--     information (Ministerio de Economía + BCRA + CNV regimes
--     all apply).
--   * Cross-border custodian = unusual (FGS uses CVSA solely;
--     foreign-custodian record = anomaly).
--
-- Regulatory base:
--
--   Ley 24.156   Administración Financiera del Estado
--   Ley 24.241   SIPA (pension system)
--   Ley 26.425   FGS creation (2008 AFJP nationalization)
--   Ley 26.831   Mercado de Capitales (AR)
--   CNV RG 731   Régimen de Agentes
--   CNV RG 622 art.42  Transparencia accionaria
--   CNV RG 622 art.50  Insider information
--   CNV RG 622 art.23  Sistemas Automatizados
--   CNV RG 1023  Ciberresiliencia
--   AFIP RG 5193 Securities tax reporting
--   Ley 25.326   Datos Personales (SIPA PII)
--   Resolución ANSES (FGS investment framework)
--   Resolución SIGEN (audit standards)
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories (cartera vault)
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (FGS / ANSES portal credentials)
--   T1005    Data from Local System (acta, lineamientos)
--   T1199    Trusted Relationship (BCRA primary-market window)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config        — FGS-tool cleartext.
--   has_cartera_fgs               — FGS portfolio detail.
--   has_lic_record                — LIC subscription / holding.
--   has_directorio_acta           — board-of-directors minutes.
--   has_comite_acta               — investment-committee minutes.
--   has_lineamientos_doc          — investment policy.
--   has_primary_auction_bid       — auction bid pre-result.
--   has_primary_auction_result    — auction result.
--   has_custodia_record           — CVSA custody record.
--   has_voting_record             — asamblea voting position.
--   has_sipa_pension_record       — SIPA pensioner roster.
--   has_filing_receipt            — SIGEN / SSN filing receipt.
--   has_byma_panel_lider_holding  — FGS >5% in panel líder name.
--   has_institutional_portfolio   — > 100 instruments.
--   has_pre_disclosure_risk       — acta + (future-dated decision
--                                   OR auction bid pre-result).
--   has_cliente_cuit              — entity CUIT detected.
--   has_trabajador_cuil           — SIPA pensioner CUIL detected.
--   is_credential_exposure_risk   — readable + (password OR
--                                   cartera OR LIC OR acta OR
--                                   SIPA OR cliente CUIT).
--   is_market_moving_info_risk    — readable + (acta OR auction
--                                   bid OR voting record).

CREATE TABLE IF NOT EXISTS host_arg_fgs (
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
            'fgs-cartera','fgs-lic-record',
            'fgs-directorio-acta','fgs-comite-acta',
            'fgs-lineamientos-doc',
            'fgs-primary-auction-bid','fgs-primary-auction-result',
            'fgs-custodia-record','fgs-voting-record',
            'fgs-sipa-pension-record','fgs-filing-receipt',
            'fgs-config','fgs-credentials',
            'fgs-installer','other','unknown'
        )),
    holder_role                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (holder_role IN (
            'director','comite-inversiones','tesoreria',
            'custodia','auditoria-sigen','riesgo',
            'analista-equity','analista-fixed-income',
            'compliance-officer','api','other','unknown'
        )),
    portfolio_class             TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (portfolio_class IN (
            'lic','ar-sovereign-bond','ar-corporate-bond',
            'ar-equity','ar-fci','real-estate-fund',
            'project-finance','time-deposit','cash',
            'multi-asset','other','unknown'
        )),
    auction_window              TEXT    NOT NULL DEFAULT ''
        CHECK (auction_window IN (
            '','bcra-primary','minecon-primary','anses-lic',
            'tesoro-corto-plazo','tesoro-largo-plazo',
            'on-corporate','custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    trabajador_cuil_prefix      TEXT    NOT NULL DEFAULT ''
        CHECK (trabajador_cuil_prefix IN ('','20','23','24','27')),
    trabajador_cuil_suffix4     TEXT    NOT NULL DEFAULT '',
    fgs_series_code             TEXT    NOT NULL DEFAULT '',
    auction_id                  TEXT    NOT NULL DEFAULT '',
    acta_id                     TEXT    NOT NULL DEFAULT '',
    portfolio_instruments_count INTEGER NOT NULL DEFAULT 0,
    lic_face_value_ars_millions INTEGER NOT NULL DEFAULT 0,
    equity_holding_count        INTEGER NOT NULL DEFAULT 0,
    sov_bond_holding_count      INTEGER NOT NULL DEFAULT 0,
    panel_lider_holding_count   INTEGER NOT NULL DEFAULT 0,
    auction_bid_amount_ars_millions INTEGER NOT NULL DEFAULT 0,
    sipa_pensioner_count        INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_cartera_fgs             INTEGER NOT NULL DEFAULT 0 CHECK (has_cartera_fgs IN (0,1)),
    has_lic_record              INTEGER NOT NULL DEFAULT 0 CHECK (has_lic_record IN (0,1)),
    has_directorio_acta         INTEGER NOT NULL DEFAULT 0 CHECK (has_directorio_acta IN (0,1)),
    has_comite_acta             INTEGER NOT NULL DEFAULT 0 CHECK (has_comite_acta IN (0,1)),
    has_lineamientos_doc        INTEGER NOT NULL DEFAULT 0 CHECK (has_lineamientos_doc IN (0,1)),
    has_primary_auction_bid     INTEGER NOT NULL DEFAULT 0 CHECK (has_primary_auction_bid IN (0,1)),
    has_primary_auction_result  INTEGER NOT NULL DEFAULT 0 CHECK (has_primary_auction_result IN (0,1)),
    has_custodia_record         INTEGER NOT NULL DEFAULT 0 CHECK (has_custodia_record IN (0,1)),
    has_voting_record           INTEGER NOT NULL DEFAULT 0 CHECK (has_voting_record IN (0,1)),
    has_sipa_pension_record     INTEGER NOT NULL DEFAULT 0 CHECK (has_sipa_pension_record IN (0,1)),
    has_filing_receipt          INTEGER NOT NULL DEFAULT 0 CHECK (has_filing_receipt IN (0,1)),
    has_byma_panel_lider_holding INTEGER NOT NULL DEFAULT 0 CHECK (has_byma_panel_lider_holding IN (0,1)),
    has_institutional_portfolio INTEGER NOT NULL DEFAULT 0 CHECK (has_institutional_portfolio IN (0,1)),
    has_pre_disclosure_risk     INTEGER NOT NULL DEFAULT 0 CHECK (has_pre_disclosure_risk IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    has_trabajador_cuil         INTEGER NOT NULL DEFAULT 0 CHECK (has_trabajador_cuil IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_market_moving_info_risk  INTEGER NOT NULL DEFAULT 0 CHECK (is_market_moving_info_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_fgs_password
    ON host_arg_fgs(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_cartera
    ON host_arg_fgs(reporting_period, portfolio_instruments_count) WHERE has_cartera_fgs = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_lic
    ON host_arg_fgs(fgs_series_code, lic_face_value_ars_millions) WHERE has_lic_record = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_directorio
    ON host_arg_fgs(acta_id, reporting_period) WHERE has_directorio_acta = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_comite
    ON host_arg_fgs(acta_id, reporting_period) WHERE has_comite_acta = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_auction_bid
    ON host_arg_fgs(auction_id, auction_bid_amount_ars_millions) WHERE has_primary_auction_bid = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_auction_result
    ON host_arg_fgs(auction_id, reporting_period) WHERE has_primary_auction_result = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_custodia
    ON host_arg_fgs(reporting_period) WHERE has_custodia_record = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_voting
    ON host_arg_fgs(acta_id, reporting_period) WHERE has_voting_record = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_sipa
    ON host_arg_fgs(reporting_period, sipa_pensioner_count) WHERE has_sipa_pension_record = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_panel_lider
    ON host_arg_fgs(reporting_period, panel_lider_holding_count) WHERE has_byma_panel_lider_holding = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_institutional
    ON host_arg_fgs(reporting_period, portfolio_instruments_count) WHERE has_institutional_portfolio = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_pre_disclosure
    ON host_arg_fgs(reporting_period) WHERE has_pre_disclosure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_cliente
    ON host_arg_fgs(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_trabajador
    ON host_arg_fgs(trabajador_cuil_prefix, trabajador_cuil_suffix4) WHERE has_trabajador_cuil = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_exposure
    ON host_arg_fgs(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_market_moving
    ON host_arg_fgs(file_path) WHERE is_market_moving_info_risk = 1;

CREATE INDEX IF NOT EXISTS idx_fgs_drift
    ON host_arg_fgs(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_fgs_kind
    ON host_arg_fgs(artifact_kind, holder_role);
