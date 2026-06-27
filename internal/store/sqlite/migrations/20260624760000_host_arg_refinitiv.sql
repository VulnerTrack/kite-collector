-- host_arg_refinitiv inventories Refinitiv (Eikon / LSEG
-- Workspace / Datastream / World-Check) artifact files cached
-- on Argentine institutional-bank, FCI-manager, compliance,
-- and academic-quant workstations.
--
-- Refinitiv (acquired by LSEG 2021, rebranded as LSEG
-- Workspace 2024) is the canonical Bloomberg alternative in
-- Argentine institutional markets. Many local desks subscribe
-- to BOTH Bloomberg + Refinitiv (cost optimization) or use
-- Refinitiv only (smaller institutions).
--
-- Distinctive surfaces:
--
--   Eikon Desktop             classic terminal
--   LSEG Workspace            2024+ rebranded terminal
--   Eikon API                 SDK (Python / .NET / Java)
--   refinitiv-data            Python SDK (2024+)
--   Eikon Excel add-in        =TR()/RData() formulas
--   Datastream                historical-data (academic/quant)
--   World-Check One           AML/KYC screening (UIF)
--   RKD / Tick History        bulk historical data
--   Reuters NRT               machine-readable news for algos
--
-- **The Refinitiv institutional layer.** Distinct from:
--   - iter 156 winargbymadata   BYMA-local market-data feed
--   - iter 110 winargfci        FCI Sociedad Gerente files
--   - iter 164 winargallaria    institutional broker side
--   - iter 166 winargbloomberg  Bloomberg Terminal/BLPAPI/AIM
--
-- Workstation cache footprint:
--
--   C:\Refinitiv\Eikon\config.xml         terminal cfg
--   C:\Refinitiv\Eikon\eikon.lic          license file
--   C:\Refinitiv\Eikon\eikon.log          terminal log
--   C:\Refinitiv\Datastream\dws.xml       Datastream cfg
--   C:\Refinitiv\WorldCheck\config.json   World-Check cfg
--   C:\LSEG\Workspace\workspace.cfg       LSEG Workspace cfg
--   %APPDATA%\Refinitiv\session.tok       session token
--   %USERPROFILE%\refinitiv-data\config   refinitiv-data SDK
--   ~/Documents/*.xlsm                    Excel TR/RData formulas
--   ~/projects/quant/refinitiv_*.py       Python SDK scripts
--
-- Refinitiv-specific risk signals:
--   * Cleartext password in config = T1552 + CNV RG 1023
--   * Eikon.lic file = ~USD 22 K/year subscription identifier
--   * World-Check API key = AML screening source compromise
--     (Ley 25.246 + UIF Resol. 30 obligation)
--   * Datastream credentials = bulk historical data access
--     (potential redistribution-rights violation)
--   * Machine-readable news (MRN) subscription = algo trading
--     news-arbitrage signal (CNV RG 731 art. 23 monitoring)
--   * refinitiv-data Python script = automated scraping
--   * Excel TR/RData formulas = workbook leak surface
--   * Multiple sessions per host = subscription-sharing
--   * LSEG Workspace 2024+ vs legacy Eikon = migration tier
--   * Argentine ticker concentration = AR-focused desk
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   Ley 25.246       Encubrimiento (AML; UIF KYC)
--   UIF Resol. 30    PEP / AML KYC procedure
--   BCRA Com. A      KYC obligations for financial entities
--   CNV RG 731       Régimen de Agentes
--   CNV RG 1023      Ciberresiliencia
--   Refinitiv TOS    Per-user / per-host subscription limits
--   LSEG / Refinitiv data-redistribution agreement
--   Ley 25.326       Protección de Datos Personales
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1071    Application Layer Protocol (Eikon API)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_password_in_config         — config cleartext.
--   has_license_file               — Eikon.lic present.
--   has_session_token              — session leak.
--   has_world_check_screening      — AML/KYC source.
--   has_datastream_subscription    — historical-data sub.
--   has_machine_readable_news      — Reuters MRN feed.
--   has_python_sdk                 — refinitiv-data SDK.
--   has_excel_eikon_addin          — Excel TR/RData formulas.
--   has_lseg_workspace_rebrand     — 2024+ LSEG markers.
--   has_multiple_sessions          — >1 distinct user.
--   has_argentine_focus            — AR ticker concentration.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable + (password OR
--                                    session token OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_refinitiv (
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
            'eikon-config','eikon-credentials',
            'eikon-license','eikon-session-log',
            'lseg-workspace-config','datastream-config',
            'world-check-config','eikon-python-sdk',
            'eikon-excel-addin','refinitiv-installer',
            'other','unknown'
        )),
    subscription_tier           TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (subscription_tier IN (
            'eikon','eikon-plus','lseg-workspace',
            'datastream','world-check','data-license',
            'other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'market-data','news-machine-readable','risk',
            'portfolio-mgmt','aml-kyc-world-check',
            'historical-data','fci-portfolio',
            'other','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    session_token_hash          TEXT    NOT NULL DEFAULT '',
    license_id_hash             TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_user_count         INTEGER NOT NULL DEFAULT 0,
    distinct_ar_ticker_count    INTEGER NOT NULL DEFAULT 0,
    distinct_ticker_count       INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_license_file            INTEGER NOT NULL DEFAULT 0 CHECK (has_license_file IN (0,1)),
    has_session_token           INTEGER NOT NULL DEFAULT 0 CHECK (has_session_token IN (0,1)),
    has_world_check_screening   INTEGER NOT NULL DEFAULT 0 CHECK (has_world_check_screening IN (0,1)),
    has_datastream_subscription INTEGER NOT NULL DEFAULT 0 CHECK (has_datastream_subscription IN (0,1)),
    has_machine_readable_news   INTEGER NOT NULL DEFAULT 0 CHECK (has_machine_readable_news IN (0,1)),
    has_python_sdk              INTEGER NOT NULL DEFAULT 0 CHECK (has_python_sdk IN (0,1)),
    has_excel_eikon_addin       INTEGER NOT NULL DEFAULT 0 CHECK (has_excel_eikon_addin IN (0,1)),
    has_lseg_workspace_rebrand  INTEGER NOT NULL DEFAULT 0 CHECK (has_lseg_workspace_rebrand IN (0,1)),
    has_multiple_sessions       INTEGER NOT NULL DEFAULT 0 CHECK (has_multiple_sessions IN (0,1)),
    has_argentine_focus         INTEGER NOT NULL DEFAULT 0 CHECK (has_argentine_focus IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_refinitiv_password
    ON host_arg_refinitiv(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_refinitiv_license
    ON host_arg_refinitiv(file_path) WHERE has_license_file = 1;

CREATE INDEX IF NOT EXISTS idx_refinitiv_session
    ON host_arg_refinitiv(file_path) WHERE has_session_token = 1;

CREATE INDEX IF NOT EXISTS idx_refinitiv_world_check
    ON host_arg_refinitiv(file_path) WHERE has_world_check_screening = 1;

CREATE INDEX IF NOT EXISTS idx_refinitiv_datastream
    ON host_arg_refinitiv(file_path, period_yyyymm) WHERE has_datastream_subscription = 1;

CREATE INDEX IF NOT EXISTS idx_refinitiv_mrn
    ON host_arg_refinitiv(file_path) WHERE has_machine_readable_news = 1;

CREATE INDEX IF NOT EXISTS idx_refinitiv_python
    ON host_arg_refinitiv(file_path) WHERE has_python_sdk = 1;

CREATE INDEX IF NOT EXISTS idx_refinitiv_excel
    ON host_arg_refinitiv(file_path) WHERE has_excel_eikon_addin = 1;

CREATE INDEX IF NOT EXISTS idx_refinitiv_lseg
    ON host_arg_refinitiv(file_path, period_yyyymm) WHERE has_lseg_workspace_rebrand = 1;

CREATE INDEX IF NOT EXISTS idx_refinitiv_multi_session
    ON host_arg_refinitiv(file_path, distinct_user_count) WHERE has_multiple_sessions = 1;

CREATE INDEX IF NOT EXISTS idx_refinitiv_ar_focus
    ON host_arg_refinitiv(file_path, distinct_ar_ticker_count) WHERE has_argentine_focus = 1;

CREATE INDEX IF NOT EXISTS idx_refinitiv_cliente
    ON host_arg_refinitiv(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_refinitiv_exposure
    ON host_arg_refinitiv(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_refinitiv_drift
    ON host_arg_refinitiv(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_refinitiv_kind
    ON host_arg_refinitiv(artifact_kind, subscription_tier, product_class);
