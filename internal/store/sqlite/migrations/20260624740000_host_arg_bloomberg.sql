-- host_arg_bloomberg inventories Bloomberg Terminal + BLPAPI
-- + Bloomberg AIM artifact files cached on Argentine
-- institutional-bank, FCI-manager, pension-fund, family-
-- office, and prop-desk workstations.
--
-- Bloomberg Terminal (BBG / BLP) is the dominant institutional
-- market-data + execution + portfolio-management terminal in
-- Argentine financial markets. At ~USD 2 K / month per seat it
-- is the canonical institutional spend signal. Distinct
-- surfaces:
--
--   Bloomberg Terminal       desktop (Java + native)
--   Bloomberg Anywhere       mobile / web access
--   B-Pipe / BPipe           managed market-data feed
--   AIM (Asset & Inv Mgr)    FCI / portfolio mgmt
--   BLPAPI                   SDK (Python/C++/Java/.NET)
--   Excel BLP add-in         BDP/BDH/BDS formulas
--   Data License             bulk historical data
--
-- **The institutional Bloomberg layer.** Distinct from:
--   - iter 156 winargbymadata  BYMA-local market-data feed
--   - iter 110 winargfci       FCI Sociedad Gerente files
--   - iter 164 winargallaria   institutional broker side
--   - iter 165 winargib        IB offshore brokerage
--
-- Workstation cache footprint:
--
--   C:\blp\Bloomberg.lic                license file
--   C:\blp\BBT.cfg                      terminal config
--   C:\blp\bbg.log                      terminal session log
--   C:\blp\Vault\<cache>                local data vault
--   %APPDATA%\Bloomberg\BPipe.cfg       BPipe feed cfg
--   %APPDATA%\Bloomberg\AIM\portfolio   AIM portfolios
--   %USERPROFILE%\blpapi\config.ini     BLPAPI SDK cfg
--   %USERPROFILE%\Documents\*.xlsm      Excel BLP add-in
--   ~/.bloomberg/credentials            macOS/Linux creds
--   ~/projects/quant/blpapi_*.py        BLPAPI scripts
--
-- Bloomberg-specific risk signals:
--   * Cleartext password in config = T1552 + CNV RG 1023
--   * Bloomberg.lic file = $24 K/year subscription identifier
--   * Multiple session tokens across distinct users on one
--     host = subscription-sharing concern (Bloomberg TOS
--     violation; compliance + cost overrun)
--   * BPipe managed feed = institutional spend tier
--     (Bloomberg fees + Argentine regulatory tap if used for
--     execution-quality reporting)
--   * AIM portfolio file = FCI / managed-portfolio composition
--     (CNV RG 622 art. 25 disclosure trigger)
--   * BLPAPI Python script with embedded session = automated
--     market-data scraping vs. interactive use (Bloomberg
--     monitors session-rate; aggressive use = throttling)
--   * Excel BLP add-in in shared workbook = formulas leak
--     subscription on every recipient's open (TOS surface)
--   * Argentine instrument tickers (e.g. `GGAL AR`, `AL30
--     Govt`) = AR-focused desk vs. global generalist
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes
--   CNV RG 622 art.25 Disclosure de concentración
--   CNV RG 1023      Ciberresiliencia
--   Bloomberg TOS    Subscription per-user / per-host limits
--   Bloomberg DAPI / BPipe contract terms
--   Ley 25.326       Protección de Datos Personales
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1071    Application Layer Protocol (BLPAPI)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_password_in_config         — config cleartext.
--   has_license_file               — Bloomberg.lic present.
--   has_session_token              — bbg session leak.
--   has_anywhere_mobile            — mobile cert.
--   has_bpipe_managed_feed         — BPipe institutional feed.
--   has_aim_fci_manager            — Bloomberg AIM portfolio.
--   has_blpapi_script              — Python/Java/C# SDK.
--   has_excel_blp_addin            — Excel BDP/BDH/BDS.
--   has_multiple_sessions          — >1 distinct user on host.
--   has_argentine_focus            — AR ticker concentration.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable + (password OR
--                                    session token OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_bloomberg (
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
            'bbg-config','bbg-license','bbg-credentials',
            'bbg-session-log','bbg-vault-cache','bbg-bpipe-config',
            'bbg-blpapi-script','bbg-excel-addin','bbg-aim-config',
            'bbg-anywhere-cert','bbg-installer','other','unknown'
        )),
    subscription_tier           TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (subscription_tier IN (
            'terminal','anywhere','bpipe','aim',
            'data-license','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'market-data','news','execution-mgmt','risk',
            'portfolio-mgmt','fci-aim','other','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    bbg_session_hash            TEXT    NOT NULL DEFAULT '',
    bbg_license_id_hash         TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_user_count         INTEGER NOT NULL DEFAULT 0,
    distinct_ar_ticker_count    INTEGER NOT NULL DEFAULT 0,
    distinct_ticker_count       INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_license_file            INTEGER NOT NULL DEFAULT 0 CHECK (has_license_file IN (0,1)),
    has_session_token           INTEGER NOT NULL DEFAULT 0 CHECK (has_session_token IN (0,1)),
    has_anywhere_mobile         INTEGER NOT NULL DEFAULT 0 CHECK (has_anywhere_mobile IN (0,1)),
    has_bpipe_managed_feed      INTEGER NOT NULL DEFAULT 0 CHECK (has_bpipe_managed_feed IN (0,1)),
    has_aim_fci_manager         INTEGER NOT NULL DEFAULT 0 CHECK (has_aim_fci_manager IN (0,1)),
    has_blpapi_script           INTEGER NOT NULL DEFAULT 0 CHECK (has_blpapi_script IN (0,1)),
    has_excel_blp_addin         INTEGER NOT NULL DEFAULT 0 CHECK (has_excel_blp_addin IN (0,1)),
    has_multiple_sessions       INTEGER NOT NULL DEFAULT 0 CHECK (has_multiple_sessions IN (0,1)),
    has_argentine_focus         INTEGER NOT NULL DEFAULT 0 CHECK (has_argentine_focus IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_bbg_password
    ON host_arg_bloomberg(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_bbg_license
    ON host_arg_bloomberg(file_path) WHERE has_license_file = 1;

CREATE INDEX IF NOT EXISTS idx_bbg_session
    ON host_arg_bloomberg(file_path) WHERE has_session_token = 1;

CREATE INDEX IF NOT EXISTS idx_bbg_anywhere
    ON host_arg_bloomberg(file_path) WHERE has_anywhere_mobile = 1;

CREATE INDEX IF NOT EXISTS idx_bbg_bpipe
    ON host_arg_bloomberg(file_path, period_yyyymm) WHERE has_bpipe_managed_feed = 1;

CREATE INDEX IF NOT EXISTS idx_bbg_aim
    ON host_arg_bloomberg(file_path, period_yyyymm) WHERE has_aim_fci_manager = 1;

CREATE INDEX IF NOT EXISTS idx_bbg_blpapi
    ON host_arg_bloomberg(file_path) WHERE has_blpapi_script = 1;

CREATE INDEX IF NOT EXISTS idx_bbg_excel
    ON host_arg_bloomberg(file_path) WHERE has_excel_blp_addin = 1;

CREATE INDEX IF NOT EXISTS idx_bbg_multi_session
    ON host_arg_bloomberg(file_path, distinct_user_count) WHERE has_multiple_sessions = 1;

CREATE INDEX IF NOT EXISTS idx_bbg_ar_focus
    ON host_arg_bloomberg(file_path, distinct_ar_ticker_count) WHERE has_argentine_focus = 1;

CREATE INDEX IF NOT EXISTS idx_bbg_cliente
    ON host_arg_bloomberg(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_bbg_exposure
    ON host_arg_bloomberg(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_bbg_drift
    ON host_arg_bloomberg(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_bbg_kind
    ON host_arg_bloomberg(artifact_kind, subscription_tier, product_class);
