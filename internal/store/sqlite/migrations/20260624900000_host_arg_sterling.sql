-- host_arg_sterling inventories Sterling Trader Pro artifact
-- files cached on Argentine retail US-equity prop-trader,
-- day-trader, and prop-firm-trainee workstations.
--
-- Sterling Trader Pro is the dominant **US equity prop-trader
-- terminal** with direct-market-access (DMA) routing to
-- NYSE / NASDAQ / ARCA / BATS. AR retail traders access it
-- through US prop firms (SMB Capital, T3 Live, CenterPoint,
-- Bright Trading, Hold Brothers).
--
-- Distinguishing Sterling characteristics:
--
--   1. HotKeys — one-click execution keymap (Ctrl-1 = BUY,
--      Ctrl-3 = SHORT, etc.) — scalper / day-trader pattern.
--   2. Branch / Office / Trader hierarchy — prop-firm risk
--      structure (trader bound to branch limits).
--   3. Per-trader risk limits — daily-loss / max-position
--      caps enforced at the terminal.
--   4. DMA route configs — direct exchange routing tickets.
--   5. Short locate log — borrow-availability + cost logs
--      (NYSE Rule 200, Reg SHO compliance).
--   6. Sterling Equities clearing — back-office layer.
--
-- **The Sterling US equity prop-terminal layer.** Distinct
-- from:
--
--   - iter 165 winargib           — IB TWS/Gateway (retail).
--   - iter 173 winargtradestation — TradeStation EasyLanguage.
--   - iter 170 winargsierra       — Sierra Chart (DTC futures).
--   - iter 171 winargamibroker    — AmiBroker AFL (equity).
--
-- Workstation cache footprint (typical):
--
--   C:\Sterling Trader\                   install root
--   C:\Sterling Trader\Layouts\<name>.stx layout
--   C:\Sterling Trader\HotKeys.cfg        one-click keymap
--   C:\Sterling Trader\ChartDef.cfg       chart definitions
--   C:\Sterling Trader\Routes\<exch>.cfg  DMA exchange route
--   C:\Sterling Trader\Branch.cfg         broker / branch
--   C:\Sterling Trader\TraderRiskLimits.cfg
--   C:\Sterling Trader\OrderLog\<dt>.csv  daily order log
--   C:\Sterling Trader\ShortLocate\<dt>.log short-locate req
--   C:\Sterling Trader\Clearing\<broker>.cfg clearing creds
--   C:\Sterling Trader\FIX\<route>.cfg    FIX direct route
--   %APPDATA%\Sterling Trader\            user data
--
-- Sterling-specific risk signals:
--
--   * Cleartext password / API key in clearing.cfg = T1552 +
--     CNV RG 1023.
--   * Sterling Equities clearing credentials = back-office
--     access (broker-side exposure beyond trader).
--   * DMA route cfg with cleartext FIX SenderCompID +
--     password = unauthorized exchange routing if leaked
--     (FINRA Rule 4370 BCP cross-ref).
--   * HotKeys.cfg with one-click destructive operations
--     (BUY/SHORT bound to single keypress) = error-risk +
--     CNV RG 622 art. 50 if FX symbols routed.
--   * TraderRiskLimits.cfg = risk-cap intelligence (any
--     adversary obtaining knows the trader's daily-loss
--     limit and max-position size).
--   * Branch.cfg = prop-firm organizational structure leak.
--   * OrderLog.csv = full daily fill trail (BCRA Com. A
--     7916 cross-border USD if filled in USD).
--   * Short-locate log > N requests / day = active short-
--     selling (Reg SHO compliance + AR Bienes Personales
--     foreign-portfolio reporting trigger).
--   * High-volume trader (> 1000 trades/day) = pattern day
--     trader (PDT) classification + AFIP RG 5193 trigger.
--   * Options-chain access in layout = options-trading
--     enabled (additional regulatory / tax surface).
--   * Cliente CUIT in trader record = AR resident trader
--     (AFIP F.8125 + Bienes Personales aggregator).
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
-- US-side regs (Sterling broker-side):
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
--   T1078    Valid Accounts
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config       — cfg cleartext.
--   has_clearing_credentials     — Sterling Equities clearing.
--   has_dma_route_config         — direct exchange route.
--   has_orderlog_export          — daily order/fill trail.
--   has_hotkey_oneclick          — HotKey one-click execution.
--   has_trader_risk_limits       — per-trader risk cap file.
--   has_branch_hierarchy         — broker/branch/trader struct.
--   has_us_equity                — US equity ticker present.
--   has_options_chain            — options-trading enabled.
--   has_short_locate_log         — short-locate request log.
--   has_high_volume_trader       — > 1000 trades/day pattern.
--   has_pattern_day_trader       — PDT classification (FINRA).
--   has_cliente_cuit             — cliente CUIT detected.
--   is_credential_exposure_risk  — readable + (password OR
--                                  clearing cred OR DMA route
--                                  OR orderlog OR cliente
--                                  CUIT).

CREATE TABLE IF NOT EXISTS host_arg_sterling (
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
            'sterling-config','sterling-credentials',
            'sterling-layout','sterling-hotkeys',
            'sterling-chart-def','sterling-dma-route',
            'sterling-branch-config','sterling-trader-risk-limits',
            'sterling-clearing-config','sterling-orderlog',
            'sterling-short-locate-log','sterling-fix-route',
            'sterling-installer','other','unknown'
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
    prop_firm                   TEXT    NOT NULL DEFAULT ''
        CHECK (prop_firm IN (
            '','smb-capital','t3-live','centerpoint',
            'bright-trading','hold-brothers','dtcc',
            'kershner','great-point','sterling-equities',
            'custom','none','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    sterling_trader_id          TEXT    NOT NULL DEFAULT '',
    sterling_branch_id          TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    us_equity_symbols_count     INTEGER NOT NULL DEFAULT 0,
    options_symbols_count       INTEGER NOT NULL DEFAULT 0,
    hotkey_count                INTEGER NOT NULL DEFAULT 0,
    fill_count                  INTEGER NOT NULL DEFAULT 0,
    short_locate_count          INTEGER NOT NULL DEFAULT 0,
    daily_loss_limit_usd        INTEGER NOT NULL DEFAULT 0,
    max_position_usd            INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_clearing_credentials    INTEGER NOT NULL DEFAULT 0 CHECK (has_clearing_credentials IN (0,1)),
    has_dma_route_config        INTEGER NOT NULL DEFAULT 0 CHECK (has_dma_route_config IN (0,1)),
    has_orderlog_export         INTEGER NOT NULL DEFAULT 0 CHECK (has_orderlog_export IN (0,1)),
    has_hotkey_oneclick         INTEGER NOT NULL DEFAULT 0 CHECK (has_hotkey_oneclick IN (0,1)),
    has_trader_risk_limits      INTEGER NOT NULL DEFAULT 0 CHECK (has_trader_risk_limits IN (0,1)),
    has_branch_hierarchy        INTEGER NOT NULL DEFAULT 0 CHECK (has_branch_hierarchy IN (0,1)),
    has_us_equity               INTEGER NOT NULL DEFAULT 0 CHECK (has_us_equity IN (0,1)),
    has_options_chain           INTEGER NOT NULL DEFAULT 0 CHECK (has_options_chain IN (0,1)),
    has_short_locate_log        INTEGER NOT NULL DEFAULT 0 CHECK (has_short_locate_log IN (0,1)),
    has_high_volume_trader      INTEGER NOT NULL DEFAULT 0 CHECK (has_high_volume_trader IN (0,1)),
    has_pattern_day_trader      INTEGER NOT NULL DEFAULT 0 CHECK (has_pattern_day_trader IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_sterling_password
    ON host_arg_sterling(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_sterling_clearing
    ON host_arg_sterling(prop_firm, period_yyyymm) WHERE has_clearing_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_sterling_dma
    ON host_arg_sterling(file_path) WHERE has_dma_route_config = 1;

CREATE INDEX IF NOT EXISTS idx_sterling_orderlog
    ON host_arg_sterling(sterling_trader_id, period_yyyymm) WHERE has_orderlog_export = 1;

CREATE INDEX IF NOT EXISTS idx_sterling_hotkey
    ON host_arg_sterling(file_path) WHERE has_hotkey_oneclick = 1;

CREATE INDEX IF NOT EXISTS idx_sterling_risk_limits
    ON host_arg_sterling(sterling_trader_id) WHERE has_trader_risk_limits = 1;

CREATE INDEX IF NOT EXISTS idx_sterling_branch
    ON host_arg_sterling(sterling_branch_id) WHERE has_branch_hierarchy = 1;

CREATE INDEX IF NOT EXISTS idx_sterling_short_locate
    ON host_arg_sterling(sterling_trader_id, period_yyyymm) WHERE has_short_locate_log = 1;

CREATE INDEX IF NOT EXISTS idx_sterling_high_volume
    ON host_arg_sterling(sterling_trader_id, fill_count) WHERE has_high_volume_trader = 1;

CREATE INDEX IF NOT EXISTS idx_sterling_pdt
    ON host_arg_sterling(sterling_trader_id, period_yyyymm) WHERE has_pattern_day_trader = 1;

CREATE INDEX IF NOT EXISTS idx_sterling_options
    ON host_arg_sterling(sterling_trader_id, period_yyyymm) WHERE has_options_chain = 1;

CREATE INDEX IF NOT EXISTS idx_sterling_cliente
    ON host_arg_sterling(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_sterling_exposure
    ON host_arg_sterling(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_sterling_drift
    ON host_arg_sterling(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_sterling_kind
    ON host_arg_sterling(artifact_kind, account_class);
