-- host_arg_ninja inventories NinjaTrader 8 artifact files cached
-- on Argentine retail futures algotrader and prop-firm-trainee
-- workstations.
--
-- NinjaTrader 8 (NT8) is the dominant C#/.NET futures algotrading
-- platform — distinct from the iters around it because it is **the
-- prop-firm-funded futures terminal** on Continuum / Rithmic / CQG
-- data feeds. Key differentiators:
--
--   - Language:      NinjaScript (C# 7.x, .NET Framework 4.8)
--   - Asset class:   Futures (primary), forex / equities (secondary)
--   - Data feeds:    Continuum (NT's), Rithmic, CQG, Kinetick
--   - AR community:  Apex Trader Funding, TopstepX, Earn2Trade,
--                    MyFundedFutures, Bulenox — micro-futures
--                    (MES/MNQ/MGC/MCL) prop-funded.
--
-- **The C# futures algotrading + prop-funding terminal.** Distinct
-- from:
--
--   - iter 179 winargquantower    — Quantower .NET multi-broker.
--   - iter 180 winargmotivewave   — MotiveWave Java Elliott Wave.
--   - iter 169 winargtt           — TT pro futures (ADL graphical).
--   - iter 170 winargsierra       — Sierra Chart DTC futures.
--   - iter 181 winargbookmap      — Bookmap L3 heatmap.
--   - iter 182 winargsterling     — Sterling US equity.
--   - iter 183 winargdas          — DAS US equity.
--   - iter 165 winargib           — IB TWS/Gateway.
--
-- NinjaScript distinctive features:
--
--   - C# strategies / indicators / AddOns compiled to .dll under
--     `bin\Custom\`. Source `.cs` lives alongside compiled `.dll`.
--   - `Strategy.OnBarUpdate()` / `EnterLong()` / `EnterShort()` /
--     `SubmitOrderUnmanaged()` order-submission API.
--   - AddOn API exposes full UI surface — elevated privilege
--     code can replace dialogs, intercept clicks, exfiltrate.
--   - `OnRender()` custom drawings = chart overlay surface.
--
-- Workstation cache footprint (typical):
--
--   C:\Program Files\NinjaTrader 8\               install root
--   %USERPROFILE%\Documents\NinjaTrader 8\        user data root
--   .\bin\Custom\Strategies\<name>.cs             NinjaScript src
--   .\bin\Custom\Indicators\<name>.cs             indicator src
--   .\bin\Custom\AddOns\<name>.cs                 AddOn src
--   .\bin\Custom\NinjaTrader.Custom.dll           compiled custom
--   .\bin\Custom\NinjaTrader.Custom.dll.suo       compile state
--   .\templates\Chart\<name>.xml                  chart template
--   .\templates\Strategy\<name>.xml               strategy template
--   .\workspaces\<name>.xml                       workspace
--   .\db\Connections\<name>.xml                   connection profile
--   .\db\Connections\Connections.xml              feed creds
--   .\incoming\<name>.zip                         exported pkg
--   .\outgoing\<name>.zip                         imported pkg
--   .\log\<dt>.log                                trace log
--   .\trace\<dt>.txt                              detailed trace
--   .\Performance\TradePerformance-<dt>.csv       perf export
--   %APPDATA%\NinjaTrader 8\Account\<broker>.xml  broker creds
--
-- NinjaTrader-specific risk signals:
--
--   * Cleartext password in Connections.xml = T1552 + CNV
--     RG 1023 (Ciberresiliencia).
--   * Compiled `NinjaTrader.Custom.dll` without source `.cs` =
--     opaque code execution surface (T1078).
--   * AddOn `.cs` with `System.Net.Http` / `System.Diagnostics
--     .Process.Start` calls = exfiltration / RCE surface.
--   * NinjaScript strategy with `EnterLong()` / `SubmitOrder
--     Unmanaged()` calls + active deployment = CNV RG 622
--     art. 23 Sistemas Automatizados.
--   * Apex Trader Funding / TopstepX / Earn2Trade /
--     MyFundedFutures config = prop-firm-trainee (subject to
--     prop-firm KYC + AFIP RG 5527 if pay-out to AR resident).
--   * Continuum / Rithmic / CQG creds = direct futures-feed
--     credentials (broker-side exposure).
--   * TradePerformance CSV with fill_count > 1000 = high-
--     volume futures trader (AFIP RG 5193 + Bienes Personales
--     aggregator).
--   * Micro-futures (MES, MNQ, MGC, MCL, M2K, MYM) bias =
--     AR retail prop-trainee signature (AR's economic ladder
--     into US futures markets).
--   * Cliente CUIT in account record = AR resident trader
--     (AFIP F.8125 cross-border + Bienes Personales).
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
--   AFIP RG 5527     Prop-firm payouts
--   AFIP F.8125      Cross-border transfer
--   Ley 25.246       PLA/FT
--   Ley 25.326       Datos Personales
--
-- US-side regs (NT brokerage):
--
--   CFTC Reg. 1.55   Risk disclosure
--   NFA Compliance Rule 2-43b — futures account
--   FINRA Rule 4370  BCP
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (NinjaTrader brokerage)
--   T1059    Command and Scripting (NinjaScript)
--   T1027    Obfuscated Files (compiled .dll only)
--   CWE-200, CWE-359, CWE-532, CWE-798, CWE-915
--
-- Headline finding shapes:
--
--   has_password_in_config       — cleartext.
--   has_ninjascript_strategy     — NinjaScript Strategy class.
--   has_ninjascript_indicator    — Indicator class.
--   has_ninjascript_addon        — AddOn class (privileged).
--   has_compiled_only_dll        — .dll present, .cs absent.
--   has_connection_credentials   — Continuum / Rithmic / CQG.
--   has_apex_prop                — Apex Trader Funding marker.
--   has_topstepx_prop            — TopstepX marker.
--   has_earn2trade_prop          — Earn2Trade marker.
--   has_trade_performance_export — TradePerformance.csv.
--   has_futures                  — futures ticker.
--   has_micro_futures            — MES/MNQ/MGC/MCL/M2K/MYM.
--   has_python_bridge            — Iron Python bridge.
--   has_high_volume_trader       — > 1000 fills/day.
--   has_pattern_day_trader       — PDT classification.
--   has_cliente_cuit             — cliente CUIT detected.
--   is_credential_exposure_risk  — readable + (password OR
--                                  connection cred OR
--                                  ninjascript OR addon OR
--                                  trade-perf OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_ninja (
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
            'ninja-config','ninja-credentials',
            'ninja-strategy','ninja-indicator','ninja-addon',
            'ninja-workspace','ninja-chart-template',
            'ninja-strategy-template','ninja-connection',
            'ninja-compiled-dll','ninja-export-package',
            'ninja-trade-performance','ninja-log',
            'ninja-prop-firm-config','ninja-installer',
            'other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'prop-firm-trainee','futures-daytrader',
            'pattern-day-trader','scalper','algotrader',
            'prop-trader','compliance-officer',
            'api','demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'futures','equities','forex','options',
            'crypto','multi-asset','other','unknown'
        )),
    data_feed                   TEXT    NOT NULL DEFAULT ''
        CHECK (data_feed IN (
            '','continuum','rithmic','cqg','kinetick',
            'iqfeed','tradovate','interactive-brokers',
            'amp-futures','custom','none','unknown'
        )),
    prop_firm                   TEXT    NOT NULL DEFAULT ''
        CHECK (prop_firm IN (
            '','apex-trader-funding','topstepx',
            'earn2trade','myfundedfutures','bulenox',
            'the-trading-pit','ftmo','custom','none','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    ninja_account_id            TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    futures_symbols_count       INTEGER NOT NULL DEFAULT 0,
    micro_futures_symbols_count INTEGER NOT NULL DEFAULT 0,
    options_symbols_count       INTEGER NOT NULL DEFAULT 0,
    enter_order_call_count      INTEGER NOT NULL DEFAULT 0,
    addon_count                 INTEGER NOT NULL DEFAULT 0,
    fill_count                  INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_ninjascript_strategy    INTEGER NOT NULL DEFAULT 0 CHECK (has_ninjascript_strategy IN (0,1)),
    has_ninjascript_indicator   INTEGER NOT NULL DEFAULT 0 CHECK (has_ninjascript_indicator IN (0,1)),
    has_ninjascript_addon       INTEGER NOT NULL DEFAULT 0 CHECK (has_ninjascript_addon IN (0,1)),
    has_compiled_only_dll       INTEGER NOT NULL DEFAULT 0 CHECK (has_compiled_only_dll IN (0,1)),
    has_connection_credentials  INTEGER NOT NULL DEFAULT 0 CHECK (has_connection_credentials IN (0,1)),
    has_apex_prop               INTEGER NOT NULL DEFAULT 0 CHECK (has_apex_prop IN (0,1)),
    has_topstepx_prop           INTEGER NOT NULL DEFAULT 0 CHECK (has_topstepx_prop IN (0,1)),
    has_earn2trade_prop         INTEGER NOT NULL DEFAULT 0 CHECK (has_earn2trade_prop IN (0,1)),
    has_trade_performance_export INTEGER NOT NULL DEFAULT 0 CHECK (has_trade_performance_export IN (0,1)),
    has_futures                 INTEGER NOT NULL DEFAULT 0 CHECK (has_futures IN (0,1)),
    has_micro_futures           INTEGER NOT NULL DEFAULT 0 CHECK (has_micro_futures IN (0,1)),
    has_python_bridge           INTEGER NOT NULL DEFAULT 0 CHECK (has_python_bridge IN (0,1)),
    has_high_volume_trader      INTEGER NOT NULL DEFAULT 0 CHECK (has_high_volume_trader IN (0,1)),
    has_pattern_day_trader      INTEGER NOT NULL DEFAULT 0 CHECK (has_pattern_day_trader IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_ninja_password
    ON host_arg_ninja(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_connection
    ON host_arg_ninja(data_feed, period_yyyymm) WHERE has_connection_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_strategy
    ON host_arg_ninja(file_path, enter_order_call_count) WHERE has_ninjascript_strategy = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_addon
    ON host_arg_ninja(file_path, addon_count) WHERE has_ninjascript_addon = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_compiled_only
    ON host_arg_ninja(file_path) WHERE has_compiled_only_dll = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_apex
    ON host_arg_ninja(ninja_account_id, period_yyyymm) WHERE has_apex_prop = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_topstepx
    ON host_arg_ninja(ninja_account_id, period_yyyymm) WHERE has_topstepx_prop = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_earn2trade
    ON host_arg_ninja(ninja_account_id, period_yyyymm) WHERE has_earn2trade_prop = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_perf
    ON host_arg_ninja(ninja_account_id, period_yyyymm) WHERE has_trade_performance_export = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_micro
    ON host_arg_ninja(ninja_account_id, period_yyyymm) WHERE has_micro_futures = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_python
    ON host_arg_ninja(file_path) WHERE has_python_bridge = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_high_volume
    ON host_arg_ninja(ninja_account_id, fill_count) WHERE has_high_volume_trader = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_pdt
    ON host_arg_ninja(ninja_account_id, period_yyyymm) WHERE has_pattern_day_trader = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_cliente
    ON host_arg_ninja(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_exposure
    ON host_arg_ninja(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ninja_drift
    ON host_arg_ninja(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_ninja_kind
    ON host_arg_ninja(artifact_kind, account_class);
