-- host_arg_tt inventories Trading Technologies (TT) Desktop /
-- FIX-adapter / ADL / Algo SE / Aurora / Score / TTAS artifact
-- files cached on Argentine pro futures, prop-desk, HFT, and
-- institutional-quant workstations.
--
-- Trading Technologies (TT) is the direct competitor to CQG
-- (iter 167) in the pro futures-execution platform tier.
-- Argentine pro futures traders use either CQG or TT depending
-- on broker preference + execution-quality requirements. Some
-- desks use both for redundancy.
--
-- TT product surfaces:
--
--   TT Desktop / Web      classic terminal (HTML5)
--   TT Mobile             mobile execution
--   TT FIX adapter        FIX 4.4 institutional gateway
--   TT ADL                Algo Development Language (visual)
--   TT Algo SE            Strategy Engine (server-side)
--   TT Aurora             HFT-grade execution
--   TT Score              algo monitoring + audit (CFTC tap)
--   TTAS                  TT Access Service (broker connect)
--   TT REST API           Python / Java SDK
--
-- TTAS provides MATba-Rofex connectivity for Argentine
-- futures + CME group for cross-venue arbitrage.
--
-- **The TT pro futures platform layer.** Distinct from:
--   - iter 167 winargcqg          CQG (competitor, same tier)
--   - iter 109 winargmatbarofex   MATba-Rofex positions
--   - iter 139 winargprimary      Primary REST/WS API
--   - iter 143 winargmt           MetaTrader (FX retail)
--   - iter 148 winargninjatrader  NinjaTrader (futures retail)
--   - iter 160 winarglean         LEAN (backtest framework)
--   - iter 165 winargib           IB (general brokerage)
--
-- Workstation cache footprint:
--
--   C:\TradingTechnologies\config.xml      terminal cfg
--   C:\TradingTechnologies\tt.lic          license file
--   C:\TT\Desktop\workspace.xml            workspace
--   C:\TT\Aurora\aurora.cfg                HFT execution cfg
--   C:\TT\ADL\strategies\*.adl             ADL visual algos
--   C:\TT\AlgoSE\strategies\*.tt           Algo SE scripts
--   C:\TT\Score\reports\*.score            Score monitoring
--   C:\TT\FIX\fix.cfg                      FIX session cfg
--   %APPDATA%\TT\session.log               session log
--   ~/.tt-api/credentials.json             TT API credentials
--
-- TT-specific risk signals:
--   * Cleartext password in config = T1552 + CNV RG 1023
--   * TT FIX 4.4 session = institutional tier
--   * MATba-Rofex routing via TTAS = AR futures + BCRA tap
--   * CME group routing = USD-denominated futures + IRS 1042
--   * ADL visual algo = automated trading (CNV RG 731 art. 23)
--   * Algo SE server-side strategy = persistent automated
--     execution (audit-trail under CFTC + CNV)
--   * Aurora HFT execution = co-location + high-frequency
--     (CNV scrutiny + CME tick-history audit)
--   * Score algo audit report = self-monitoring artifact
--     (legitimate but reveals algo behavior)
--   * Cross-venue arbitrage (MATba-Rofex + CME) =
--     dual-jurisdiction reporting (AFIP RG 5193 + IRS 1042)
--   * Cliente CUIT in strategy parameter = Ley 25.326 PII
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
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
--   T1059    Command and Scripting (ADL / Algo SE)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_password_in_config         — config cleartext.
--   has_api_credentials            — TT API key leak.
--   has_tt_fix_session             — FIX 4.4 institutional.
--   has_matba_rofex_routing        — TTAS AR routing.
--   has_cme_futures                — CME group products.
--   has_adl_visual_algo            — TT ADL strategy.
--   has_algo_se_strategy           — TT Algo SE script.
--   has_aurora_hft                 — TT Aurora HFT exec.
--   has_score_audit                — TT Score algo monitoring.
--   has_cross_venue_arb            — MATba-Rofex + CME both.
--   has_high_message_rate          — > 1000 msg/s HFT.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable + (password OR
--                                    api OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_tt (
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
            'tt-config','tt-credentials',
            'tt-desktop-config','tt-fix-adapter-config',
            'tt-adl-strategy','tt-algo-se-strategy',
            'tt-aurora-config','tt-score-report',
            'tt-api-script','tt-session-log',
            'tt-installer','other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'pro-futures','prop-trader','arbitrageur',
            'institutional','api','hft','demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'cme-futures','matba-rofex','global-futures',
            'multi-venue','options','hft-execution',
            'other','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    tt_account_id               TEXT    NOT NULL DEFAULT '',
    fix_sender_compid           TEXT    NOT NULL DEFAULT '',
    fix_target_compid           TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    matba_symbols_count         INTEGER NOT NULL DEFAULT 0,
    cme_symbols_count           INTEGER NOT NULL DEFAULT 0,
    peak_msg_per_sec            INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_api_credentials         INTEGER NOT NULL DEFAULT 0 CHECK (has_api_credentials IN (0,1)),
    has_tt_fix_session          INTEGER NOT NULL DEFAULT 0 CHECK (has_tt_fix_session IN (0,1)),
    has_matba_rofex_routing     INTEGER NOT NULL DEFAULT 0 CHECK (has_matba_rofex_routing IN (0,1)),
    has_cme_futures             INTEGER NOT NULL DEFAULT 0 CHECK (has_cme_futures IN (0,1)),
    has_adl_visual_algo         INTEGER NOT NULL DEFAULT 0 CHECK (has_adl_visual_algo IN (0,1)),
    has_algo_se_strategy        INTEGER NOT NULL DEFAULT 0 CHECK (has_algo_se_strategy IN (0,1)),
    has_aurora_hft              INTEGER NOT NULL DEFAULT 0 CHECK (has_aurora_hft IN (0,1)),
    has_score_audit             INTEGER NOT NULL DEFAULT 0 CHECK (has_score_audit IN (0,1)),
    has_cross_venue_arb         INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_venue_arb IN (0,1)),
    has_high_message_rate       INTEGER NOT NULL DEFAULT 0 CHECK (has_high_message_rate IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_tt_password
    ON host_arg_tt(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_tt_api
    ON host_arg_tt(file_path) WHERE has_api_credentials = 1;

CREATE INDEX IF NOT EXISTS idx_tt_fix
    ON host_arg_tt(fix_sender_compid, fix_target_compid) WHERE has_tt_fix_session = 1;

CREATE INDEX IF NOT EXISTS idx_tt_matba
    ON host_arg_tt(tt_account_id, period_yyyymm) WHERE has_matba_rofex_routing = 1;

CREATE INDEX IF NOT EXISTS idx_tt_cme
    ON host_arg_tt(tt_account_id, period_yyyymm) WHERE has_cme_futures = 1;

CREATE INDEX IF NOT EXISTS idx_tt_adl
    ON host_arg_tt(file_path) WHERE has_adl_visual_algo = 1;

CREATE INDEX IF NOT EXISTS idx_tt_algo_se
    ON host_arg_tt(file_path) WHERE has_algo_se_strategy = 1;

CREATE INDEX IF NOT EXISTS idx_tt_aurora
    ON host_arg_tt(tt_account_id, period_yyyymm) WHERE has_aurora_hft = 1;

CREATE INDEX IF NOT EXISTS idx_tt_score
    ON host_arg_tt(file_path, period_yyyymm) WHERE has_score_audit = 1;

CREATE INDEX IF NOT EXISTS idx_tt_cross_venue
    ON host_arg_tt(tt_account_id, period_yyyymm) WHERE has_cross_venue_arb = 1;

CREATE INDEX IF NOT EXISTS idx_tt_hft
    ON host_arg_tt(file_path, peak_msg_per_sec) WHERE has_high_message_rate = 1;

CREATE INDEX IF NOT EXISTS idx_tt_cliente
    ON host_arg_tt(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_tt_exposure
    ON host_arg_tt(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_tt_drift
    ON host_arg_tt(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_tt_kind
    ON host_arg_tt(artifact_kind, account_class, product_class);
