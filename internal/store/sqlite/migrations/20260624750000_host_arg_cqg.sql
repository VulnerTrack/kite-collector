-- host_arg_cqg inventories CQG (Continuum / IC / QTrader /
-- API / FIX-adapter) artifact files cached on Argentine pro
-- futures, prop-desk, arbitrageur, and institutional-quant
-- workstations.
--
-- CQG is the dominant US-based futures-trading platform with
-- direct connectivity to CME (CME / CBOT / NYMEX / COMEX) +
-- many non-US futures venues including MATba-Rofex via FIX.
-- Argentine pro futures traders use CQG for:
--
--   - Direct MATba-Rofex execution (DLR / DOM / SOJ / MAI)
--   - CME group futures (ES / NQ / CL / GC / 6E etc.)
--   - Cross-venue arbitrage (MTR-USD ↔ CME DXY)
--   - Block trades (CQG QTrader, pre-arranged off-book)
--   - Algorithmic execution (CQG Algo SE)
--
-- **The pro futures platform layer.** Distinct from:
--   - iter 109 winargmatbarofex   MATba-Rofex positions
--   - iter 139 winargprimary      Primary REST/WS API
--   - iter 143 winargmt           MetaTrader (FX retail)
--   - iter 148 winargninjatrader  NinjaTrader (futures retail)
--   - iter 160 winarglean         LEAN (backtest framework)
--   - iter 165 winargib           IB (general brokerage)
--
-- CQG product surfaces:
--
--   CQG IC (Integrated Client)  desktop terminal
--   CQG QTrader                  block-trading workstation
--   CQG Continuum                FIX market-data + execution
--   CQG Mobile                   mobile execution
--   CQG API                      Python/C++/.NET SDK
--   CQG Algo SE                  Strategy Engine
--   CQG One                      web platform
--
-- Workstation cache footprint:
--
--   C:\CQG\IC\config.xml          terminal cfg
--   C:\CQG\IC\positions.csv       positions cache
--   C:\CQG\QTrader\blocks.xml     block-trade workspace
--   C:\CQG\Continuum\fix.cfg      FIX session cfg
--   C:\CQG\AlgoSE\strategies\*.cqg Algo SE scripts
--   %APPDATA%\CQG\session.log     terminal session log
--   ~/cqg-api/script.py           CQG API Python scripts
--
-- CQG-specific risk signals:
--   * Cleartext password in config = T1552 + CNV RG 1023
--   * CQG Continuum FIX session = institutional FIX 4.4 tier
--   * MATba-Rofex routing detected = cross-border execution
--     (BCRA Com. A 7916 + CNV RG 731 dual-jurisdiction)
--   * CME futures routing = USD-denominated futures exposure
--     (AFIP RG 5193 + Bienes Personales reporting)
--   * Block QTrader = pre-arranged off-book trade (CNV RG
--     622 art. 23 disclosure trigger if > USD 1 M)
--   * Algo SE strategy script = automated trading
--     (CNV RG 731 art. 23 manipulation concern if HFT)
--   * Cross-venue arbitrage pattern (MATba-Rofex + CME) =
--     dual-jurisdiction reporting (AFIP RG 5193 + IRS 1042)
--   * FIX drop-copy multi-account = subscription sharing
--     concern
--   * Cliente CUIT in strategy parameter = Ley 25.326 PII
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes (algotrading subset)
--   CNV RG 731 art.23 Manipulación de mercado (HFT)
--   CNV RG 622 art.23 Disclosure de bloque
--   CNV RG 1023      Ciberresiliencia
--   AFIP RG 5193     Securities tax reporting
--   BCRA Com. A 7916 Operaciones cambiarias
--   CFTC Part 1.31   US futures reporting (cross-border)
--   IRS 1042-S       US futures tax reporting
--   Ley 25.326       Protección de Datos Personales
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1071    Application Layer Protocol (FIX 4.4)
--   T1059    Command and Scripting (Algo SE)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_password_in_config         — config cleartext.
--   has_api_credentials            — CQG API key leak.
--   has_continuum_fix_session      — FIX 4.4 institutional.
--   has_matba_rofex_routing        — AR futures routing.
--   has_cme_futures                — CME group products.
--   has_block_qtrader              — QTrader block trade.
--   has_algo_se_strategy           — CQG Algo SE script.
--   has_fix_drop_copy              — FIX drop-copy session.
--   has_cross_venue_arb            — MATba-Rofex + CME both.
--   has_high_message_rate          — > 1000 msg/s HFT.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable + (password OR
--                                    api OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_cqg (
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
            'cqg-config','cqg-credentials',
            'cqg-ic-config','cqg-qtrader-config',
            'cqg-continuum-config','cqg-algo-se-strategy',
            'cqg-api-script','cqg-session-log',
            'cqg-positions','cqg-orders',
            'cqg-fix-log','cqg-installer',
            'other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'pro-futures','prop-trader','arbitrageur',
            'institutional','api','demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'cme-futures','matba-rofex','global-futures',
            'multi-venue','options','other','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    cqg_account_id              TEXT    NOT NULL DEFAULT '',
    fix_sender_compid           TEXT    NOT NULL DEFAULT '',
    fix_target_compid           TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    matba_symbols_count         INTEGER NOT NULL DEFAULT 0,
    cme_symbols_count           INTEGER NOT NULL DEFAULT 0,
    block_trade_count           INTEGER NOT NULL DEFAULT 0,
    peak_msg_per_sec            INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_api_credentials         INTEGER NOT NULL DEFAULT 0 CHECK (has_api_credentials IN (0,1)),
    has_continuum_fix_session   INTEGER NOT NULL DEFAULT 0 CHECK (has_continuum_fix_session IN (0,1)),
    has_matba_rofex_routing     INTEGER NOT NULL DEFAULT 0 CHECK (has_matba_rofex_routing IN (0,1)),
    has_cme_futures             INTEGER NOT NULL DEFAULT 0 CHECK (has_cme_futures IN (0,1)),
    has_block_qtrader           INTEGER NOT NULL DEFAULT 0 CHECK (has_block_qtrader IN (0,1)),
    has_algo_se_strategy        INTEGER NOT NULL DEFAULT 0 CHECK (has_algo_se_strategy IN (0,1)),
    has_fix_drop_copy           INTEGER NOT NULL DEFAULT 0 CHECK (has_fix_drop_copy IN (0,1)),
    has_cross_venue_arb         INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_venue_arb IN (0,1)),
    has_high_message_rate       INTEGER NOT NULL DEFAULT 0 CHECK (has_high_message_rate IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_cqg_password
    ON host_arg_cqg(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_cqg_api
    ON host_arg_cqg(file_path) WHERE has_api_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_cqg_continuum
    ON host_arg_cqg(fix_sender_compid, fix_target_compid) WHERE has_continuum_fix_session = 1;

CREATE INDEX IF NOT EXISTS idx_cqg_matba
    ON host_arg_cqg(cqg_account_id, period_yyyymm) WHERE has_matba_rofex_routing = 1;

CREATE INDEX IF NOT EXISTS idx_cqg_cme
    ON host_arg_cqg(cqg_account_id, period_yyyymm) WHERE has_cme_futures = 1;

CREATE INDEX IF NOT EXISTS idx_cqg_block
    ON host_arg_cqg(cqg_account_id, period_yyyymm) WHERE has_block_qtrader = 1;

CREATE INDEX IF NOT EXISTS idx_cqg_algo
    ON host_arg_cqg(file_path) WHERE has_algo_se_strategy = 1;

CREATE INDEX IF NOT EXISTS idx_cqg_drop_copy
    ON host_arg_cqg(fix_sender_compid, fix_target_compid) WHERE has_fix_drop_copy = 1;

CREATE INDEX IF NOT EXISTS idx_cqg_cross_venue
    ON host_arg_cqg(cqg_account_id, period_yyyymm) WHERE has_cross_venue_arb = 1;

CREATE INDEX IF NOT EXISTS idx_cqg_hft
    ON host_arg_cqg(file_path, peak_msg_per_sec) WHERE has_high_message_rate = 1;

CREATE INDEX IF NOT EXISTS idx_cqg_cliente
    ON host_arg_cqg(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_cqg_exposure
    ON host_arg_cqg(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_cqg_drift
    ON host_arg_cqg(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_cqg_kind
    ON host_arg_cqg(artifact_kind, account_class, product_class);
