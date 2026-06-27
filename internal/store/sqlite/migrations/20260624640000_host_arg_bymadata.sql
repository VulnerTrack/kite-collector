-- host_arg_bymadata inventories Bymadata market-data feed
-- artifact files cached on Argentine quant, prop-desk, ALYC,
-- and FCI-manager workstations.
--
-- Bymadata is BYMA's official paid market-data product —
-- the canonical real-time + historical feed for ARS-listed
-- equity, options, fixed-income, and indices. It is the
-- upstream data vendor that every collector below depends on:
--
--   - iter 109 winargmatbarofex   futures positions/orders
--   - iter 139 winargprimary      Primary REST/WS routing
--   - iter 150 winargpyhomebroker portal scrape lib
--   - iter 155 winarghomebroker   Decsis HB terminal
--   - iter 151 winargiolinvertironline
--   - iter 152 winargcocoscapital
--   - iter 154 winargbalanz
--
-- Distribution surfaces:
--
--   FIX-FAST 5.0   institutional / vendor tier
--   WebSocket      real-time streaming for retail/quant
--   REST snapshot  daily/period batch
--   Bloomberg-like terminal GUI (Decsis-built)
--   Bymadata Vendor SDK (Python/Java/C#)
--
-- Subscription tiers (per CNV RG 731 art. 50 licensing):
--
--   basic           top-of-book ARS equity only
--   profesional     full depth-of-book + options
--   internacional   ARS + LATAM mirror feeds
--
-- Workstation cache footprint:
--
--   C:\Bymadata\config\api_key.json         API credentials
--   C:\Bymadata\terminal\settings.xml       terminal cfg
--   %APPDATA%\Bymadata\sessions\fix.log     FIX-FAST log
--   %APPDATA%\Bymadata\sessions\ws.log      WebSocket log
--   %APPDATA%\Bymadata\cache\snapshot.json  REST cache
--   %USERPROFILE%\bymadata-sdk\*.py         vendor SDK
--   ~/Bymadata/historical/<symbol>.csv      historical CSV
--
-- Bymadata-specific risk signals:
--   * API key leak in config or .py source = T1552
--   * FIX-FAST 5.0 session detected = institutional tier
--     (CNV RG 731 art. 50 vendor licensing)
--   * Depth-of-book subscription = profesional tier
--   * Multiple distinct CUITs in same cache = license
--     sharing concern (CNV RG 731 art. 50 violation)
--   * > 1000 msg/s in WS log = HFT pattern (CNV scrutiny)
--   * Historical bulk download = retroactive analysis
--     (legitimate but flagged for context)
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731 art.50 Distribución de datos de mercado
--   CNV RG 622       Operativa + transparencia
--   CNV RG 1023      Ciberresiliencia
--   Ley 25.326       Protección de Datos Personales
--   Bymadata Manual del Vendor v3.2
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1071    Application Layer Protocol (FIX-FAST)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_password_in_config        — config cleartext.
--   has_api_key                   — bymadata API key leak.
--   has_fix_fast_session          — institutional FIX-FAST.
--   has_websocket_session         — WS streaming session.
--   has_depth_of_book             — Level-2 (premium tier).
--   has_international_tier        — internacional sub.
--   has_historical_download       — bulk historical CSV.
--   has_high_message_rate         — > 1000 msg/s HFT.
--   has_license_sharing_risk      — > 1 distinct CUIT.
--   has_cliente_cuit              — cliente CUIT detected.
--   is_credential_exposure_risk   — readable + (password OR
--                                   api key OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_bymadata (
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
            'bymadata-config','bymadata-credentials',
            'bymadata-fix-fast-log','bymadata-ws-log',
            'bymadata-rest-cache','bymadata-historical-csv',
            'bymadata-sdk-script','bymadata-terminal-config',
            'bymadata-installer','other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'vendor','market-maker','fci-manager','quant',
            'retail-aggregator','demo','other','unknown'
        )),
    subscription_tier           TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (subscription_tier IN (
            'basic','profesional','internacional',
            'other','unknown'
        )),
    licensee_cuit_prefix        TEXT    NOT NULL DEFAULT ''
        CHECK (licensee_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    licensee_cuit_suffix4       TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    fix_session_sender          TEXT    NOT NULL DEFAULT '',
    fix_session_target          TEXT    NOT NULL DEFAULT '',
    session_first_seen          TEXT    NOT NULL DEFAULT '',
    session_last_seen           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    distinct_cuit_count         INTEGER NOT NULL DEFAULT 0,
    message_count               INTEGER NOT NULL DEFAULT 0,
    peak_msg_per_sec            INTEGER NOT NULL DEFAULT 0,
    historical_rows_count       INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_api_key                 INTEGER NOT NULL DEFAULT 0 CHECK (has_api_key IN (0,1)),
    has_fix_fast_session        INTEGER NOT NULL DEFAULT 0 CHECK (has_fix_fast_session IN (0,1)),
    has_websocket_session       INTEGER NOT NULL DEFAULT 0 CHECK (has_websocket_session IN (0,1)),
    has_depth_of_book           INTEGER NOT NULL DEFAULT 0 CHECK (has_depth_of_book IN (0,1)),
    has_international_tier      INTEGER NOT NULL DEFAULT 0 CHECK (has_international_tier IN (0,1)),
    has_historical_download     INTEGER NOT NULL DEFAULT 0 CHECK (has_historical_download IN (0,1)),
    has_high_message_rate       INTEGER NOT NULL DEFAULT 0 CHECK (has_high_message_rate IN (0,1)),
    has_license_sharing_risk    INTEGER NOT NULL DEFAULT 0 CHECK (has_license_sharing_risk IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_bymadata_password
    ON host_arg_bymadata(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_bymadata_apikey
    ON host_arg_bymadata(file_path) WHERE has_api_key = 1;

CREATE INDEX IF NOT EXISTS idx_bymadata_fix_fast
    ON host_arg_bymadata(fix_session_sender, fix_session_target) WHERE has_fix_fast_session = 1;

CREATE INDEX IF NOT EXISTS idx_bymadata_ws
    ON host_arg_bymadata(licensee_cuit_prefix, period_yyyymm) WHERE has_websocket_session = 1;

CREATE INDEX IF NOT EXISTS idx_bymadata_depth
    ON host_arg_bymadata(licensee_cuit_prefix) WHERE has_depth_of_book = 1;

CREATE INDEX IF NOT EXISTS idx_bymadata_international
    ON host_arg_bymadata(licensee_cuit_prefix) WHERE has_international_tier = 1;

CREATE INDEX IF NOT EXISTS idx_bymadata_historical
    ON host_arg_bymadata(licensee_cuit_prefix, period_yyyymm) WHERE has_historical_download = 1;

CREATE INDEX IF NOT EXISTS idx_bymadata_hft
    ON host_arg_bymadata(licensee_cuit_prefix, peak_msg_per_sec) WHERE has_high_message_rate = 1;

CREATE INDEX IF NOT EXISTS idx_bymadata_sharing
    ON host_arg_bymadata(licensee_cuit_prefix, distinct_cuit_count) WHERE has_license_sharing_risk = 1;

CREATE INDEX IF NOT EXISTS idx_bymadata_cliente
    ON host_arg_bymadata(licensee_cuit_prefix, licensee_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_bymadata_exposure
    ON host_arg_bymadata(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_bymadata_drift
    ON host_arg_bymadata(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_bymadata_kind
    ON host_arg_bymadata(artifact_kind, account_class, subscription_tier);
