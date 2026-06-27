-- host_arg_das inventories DAS Trader Pro artifact files
-- cached on Argentine retail US-equity prop-trader, day-trader,
-- and prop-firm-trainee workstations.
--
-- DAS Trader Pro (Direct Access Software) is the **second pillar**
-- of US equity prop-trading platforms alongside Sterling Trader Pro
-- (iter 182). Both run DMA equity execution but differ across:
--
--   - Vendor:        DAS Inc.   vs Sterling Trading Tech
--   - Scripting:     DASScript  vs (Sterling has none)
--   - HotKeys:       chord-based vs single-key
--   - Broker stack:  Stratos / Centerpoint / Velocity / Ironbeam
--                    vs Sterling Equities / SMB Capital / T3 Live
--   - AR community:  Bear Bull Traders, Investors Underground
--                    vs SMB Capital prop trainees
--
-- DASScript distinctive features:
--
--   - Native automation language for chart studies + alerts.
--   - Bracket order automation (entry + stop + TP).
--   - One-click `LOAD_SCRIPT` from DAS Mobile.
--   - DAS API gateway for Python / C++ external orders.
--
-- **The DAS US equity prop-terminal layer.** Distinct from:
--
--   - iter 182 winargsterling     — Sterling Trader Pro.
--   - iter 165 winargib           — IB TWS/Gateway (retail).
--   - iter 173 winargtradestation — TradeStation EasyLanguage.
--   - iter 170 winargsierra       — Sierra Chart (DTC futures).
--   - iter 171 winargamibroker    — AmiBroker AFL (equity).
--
-- Workstation cache footprint (typical):
--
--   C:\DAS Trader\                       install root
--   C:\DAS Trader\Layouts\<name>.das     layout
--   C:\DAS Trader\HotKeys.cfg            chord-based keymap
--   C:\DAS Trader\Scripts\<name>.script  DASScript automation
--   C:\DAS Trader\Routes\<exch>.cfg      DMA exchange route
--   C:\DAS Trader\Clearing\<broker>.cfg  clearing creds
--   C:\DAS Trader\OrderLog\<dt>.csv      daily order log
--   C:\DAS Trader\ShortLocate\<dt>.log   short-locate req
--   C:\DAS Trader\DASInet\<route>.cfg    DAS Inet route
--   C:\DAS Trader\API\token.json         DAS API token
--   C:\DAS Trader\Mobile\token.json      DAS Mobile API token
--   %APPDATA%\DAS Trader\                user data
--
-- DAS-specific risk signals:
--
--   * Cleartext password / API key in clearing.cfg = T1552 +
--     CNV RG 1023.
--   * Stratos / Centerpoint clearing credentials = back-office
--     access (broker-side exposure).
--   * DASScript with `SEND_ORDER` calls + active deployment =
--     CNV RG 622 art. 23 (Sistemas Automatizados).
--   * DAS API token leak = remote-order execution surface
--     (T1078; Bear Bull Traders / Investors Underground
--     subscribers may share scripts that include tokens).
--   * Chord-based HotKey (`Ctrl-Alt-1`, `Shift-F2`) with
--     destructive actions (SHORT, COVER, FLATTEN) = scalper
--     pattern with error-blast-radius (BCRA Com. A 7916 if
--     ARS/USD pair).
--   * OrderLog.csv > N fills/day = Pattern Day Trader (FINRA
--     Rule 4210) — affects AR resident if margin call hits.
--   * Short-locate log = Reg SHO compliance trail (FINRA
--     observation).
--   * High-volume short-locate requests = aggressive short
--     selling (AFIP RG 5193 + Bienes Personales aggregator
--     for AR resident).
--   * Cliente CUIT in user record = AR resident trader (AFIP
--     F.8125 cross-border + Bienes Personales aggregator).
--
-- Regulatory base:
--
--   Ley 26.831       Mercado de Capitales (AR side)
--   CNV RG 731       Régimen de Agentes
--   CNV RG 622 art.23 Sistemas Automatizados
--   CNV RG 622 art.50 Operativa con divisas
--   CNV RG 1023      Ciberresiliencia
--   BCRA Com. A 7916 Operaciones cambiarias
--   BCRA Com. A 8005 Ciberseguridad financiera
--   AFIP RG 5193     Securities tax reporting
--   AFIP F.8125      Cross-border transfer
--   Ley 25.326       Datos Personales
--
-- US-side regs (DAS broker-side):
--
--   SEC Reg SHO art. 200 Short-locate
--   SEC Reg NMS Order routing
--   FINRA Rule 4370 BCP
--   FINRA Rule 4210 Day-trading margin
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (DAS API)
--   T1059    Command and Scripting (DASScript)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config       — cfg cleartext.
--   has_clearing_credentials     — Stratos / Centerpoint / etc.
--   has_dasscript                — DASScript automation.
--   has_dasinet_routing          — DAS Inet direct route.
--   has_hotkey_oneclick          — single-key or chord HotKey.
--   has_orderlog_export          — daily order/fill trail.
--   has_us_equity                — US equity ticker.
--   has_options_chain            — options-trading enabled.
--   has_short_locate_log         — short-locate requests.
--   has_high_volume_trader       — > 1000 fills/day.
--   has_pattern_day_trader       — PDT classification.
--   has_api_credentials          — DAS API or Mobile API token.
--   has_cliente_cuit             — cliente CUIT detected.
--   is_credential_exposure_risk  — readable + (password OR
--                                  clearing cred OR DASScript
--                                  OR API token OR orderlog
--                                  OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_das (
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
            'das-config','das-credentials',
            'das-layout','das-hotkeys','das-script',
            'das-route','das-clearing-config',
            'das-orderlog','das-short-locate-log',
            'das-api-token','das-mobile-token',
            'das-installer','other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'prop-firm-trainee','us-equity-daytrader',
            'pattern-day-trader','scalper','prop-trader',
            'compliance-officer','branch-admin',
            'api','demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'us-equity','us-options','etf',
            'multi-asset','other','unknown'
        )),
    clearing_firm               TEXT    NOT NULL DEFAULT ''
        CHECK (clearing_firm IN (
            '','stratos','centerpoint','alliance-trader',
            'velocity','ironbeam','suretrader',
            'centerpoint-securities','das-clearing',
            'custom','none','unknown'
        )),
    prop_firm                   TEXT    NOT NULL DEFAULT ''
        CHECK (prop_firm IN (
            '','bear-bull-traders','investors-underground',
            'warrior-trading','simplertrading','tradenetstrategies',
            'maverick-trading','custom','none','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    das_trader_id               TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    us_equity_symbols_count     INTEGER NOT NULL DEFAULT 0,
    options_symbols_count       INTEGER NOT NULL DEFAULT 0,
    hotkey_count                INTEGER NOT NULL DEFAULT 0,
    chord_hotkey_count          INTEGER NOT NULL DEFAULT 0,
    script_send_order_count     INTEGER NOT NULL DEFAULT 0,
    fill_count                  INTEGER NOT NULL DEFAULT 0,
    short_locate_count          INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_clearing_credentials    INTEGER NOT NULL DEFAULT 0 CHECK (has_clearing_credentials IN (0,1)),
    has_dasscript               INTEGER NOT NULL DEFAULT 0 CHECK (has_dasscript IN (0,1)),
    has_dasinet_routing         INTEGER NOT NULL DEFAULT 0 CHECK (has_dasinet_routing IN (0,1)),
    has_hotkey_oneclick         INTEGER NOT NULL DEFAULT 0 CHECK (has_hotkey_oneclick IN (0,1)),
    has_orderlog_export         INTEGER NOT NULL DEFAULT 0 CHECK (has_orderlog_export IN (0,1)),
    has_us_equity               INTEGER NOT NULL DEFAULT 0 CHECK (has_us_equity IN (0,1)),
    has_options_chain           INTEGER NOT NULL DEFAULT 0 CHECK (has_options_chain IN (0,1)),
    has_short_locate_log        INTEGER NOT NULL DEFAULT 0 CHECK (has_short_locate_log IN (0,1)),
    has_high_volume_trader      INTEGER NOT NULL DEFAULT 0 CHECK (has_high_volume_trader IN (0,1)),
    has_pattern_day_trader      INTEGER NOT NULL DEFAULT 0 CHECK (has_pattern_day_trader IN (0,1)),
    has_api_credentials         INTEGER NOT NULL DEFAULT 0 CHECK (has_api_credentials IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_das_password
    ON host_arg_das(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_das_clearing
    ON host_arg_das(clearing_firm, period_yyyymm) WHERE has_clearing_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_das_script
    ON host_arg_das(file_path, script_send_order_count) WHERE has_dasscript = 1;

CREATE INDEX IF NOT EXISTS idx_das_dasinet
    ON host_arg_das(file_path) WHERE has_dasinet_routing = 1;

CREATE INDEX IF NOT EXISTS idx_das_orderlog
    ON host_arg_das(das_trader_id, period_yyyymm) WHERE has_orderlog_export = 1;

CREATE INDEX IF NOT EXISTS idx_das_hotkey
    ON host_arg_das(file_path, chord_hotkey_count) WHERE has_hotkey_oneclick = 1;

CREATE INDEX IF NOT EXISTS idx_das_short_locate
    ON host_arg_das(das_trader_id, period_yyyymm) WHERE has_short_locate_log = 1;

CREATE INDEX IF NOT EXISTS idx_das_high_volume
    ON host_arg_das(das_trader_id, fill_count) WHERE has_high_volume_trader = 1;

CREATE INDEX IF NOT EXISTS idx_das_pdt
    ON host_arg_das(das_trader_id, period_yyyymm) WHERE has_pattern_day_trader = 1;

CREATE INDEX IF NOT EXISTS idx_das_options
    ON host_arg_das(das_trader_id, period_yyyymm) WHERE has_options_chain = 1;

CREATE INDEX IF NOT EXISTS idx_das_api
    ON host_arg_das(file_path) WHERE has_api_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_das_cliente
    ON host_arg_das(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_das_exposure
    ON host_arg_das(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_das_drift
    ON host_arg_das(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_das_kind
    ON host_arg_das(artifact_kind, account_class);
