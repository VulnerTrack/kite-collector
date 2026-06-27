-- host_arg_oms inventories AR institutional Order-Management-
-- System (OMS) artifacts cached on portfolio-manager, trader,
-- compliance-officer, middle-office, and back-office workstations
-- at ALYC asset managers (Sociedad Gerente de FCI) and at the
-- buy-side desks of AR pension funds (FGS-ANSES, FCI institucionales),
-- AR insurance companies (SSN-regulated), and BCRA wholesale banks
-- operating on BYMA / MAE / MATba-Rofex / MAV.
--
-- Regulated under:
--
--   - CNV RG 731   (Mejor Ejecución / Best Execution) — buy-side
--                  must demonstrate routing achieved best price /
--                  liquidity / settlement / cost. Annual report
--                  required for FCI sociedades gerentes.
--   - CNV RG 622   art.50   Order Audit Trail (OAT) — full
--                  pre-trade / in-trade / post-trade order lifecycle
--                  must be reconstructable.
--   - CNV RG 622   art.42   Cross-trade rules between FCI vehicles
--                  managed by same sociedad gerente.
--   - CNV RG 622   art.41   Block-trade reporting.
--   - CNV RG 731   art.6    Pre-trade compliance (suitability,
--                  concentration limits, eligible securities).
--   - CNV RG 622   art.43   Restricted-list (insider) discipline
--                  for sociedad gerente staff.
--   - BCRA Com. A 7916       Wholesale trading desk audit trail.
--   - UIF Res. 21/2018       Watch-list for PLA/FT.
--
-- Distinct from prior iters because the shape is **front-office
-- order-routing back-office** (the institutional buy-side trading
-- desk perspective):
--
--   - vs iter 198 winargsoc        — defensive SOC (different team).
--   - vs iter 197 winargmodel      — quant model lab (research, not
--                                    execution).
--   - vs iter 195 winargacdi       — agente de custodia (custody, not
--                                    routing).
--   - vs iter 185 winargcohen      — single-broker (one ALYC) vs OMS
--                                    is multi-broker routing.
--   - vs iter 184 winargninja      — retail platform vs institutional.
--
-- An OMS artifact leak is doubly-dangerous because:
--
--   * Order audit trail reveals client identity + position + intent
--     before trade is public (= front-running material).
--   * Best-execution / TCA report reveals broker-quality scoring (=
--     reverse-engineer routing logic + arbitrage routing).
--   * Restricted-list / watch-list reveals MNPI (material non-public
--     information) about target tickers (= insider trading).
--   * Cross-trade record reveals inter-fund transfers at sociedad
--     gerente discretion (= CNV RG 622 art.42 fairness violation
--     evidence if pricing wrong).
--   * Pre-trade compliance config reveals concentration / leverage
--     limits (= attack via limit-edge exploits).
--   * Broker list reveals counterparty universe (= competitive intel).
--   * FIX session config reveals SenderCompID / TargetCompID /
--     password (= unauthorized order injection on the wire).
--
-- OMS distinctive features:
--
--   - Charles River IMS (CRIMS) — State Street-owned, dominant for
--     institutional asset managers (.crim / .xml export).
--   - Fidessa — order routing + smart order routing (SOR), used by
--     equity desks (.fid / .xml).
--   - Bloomberg AIM (Asset & Investment Manager) — buy-side OMS,
--     Bloomberg's own (.aim / .csv export).
--   - Bloomberg EMSX — execution-management cousin of AIM.
--   - FlexTrade — multi-asset OMS/EMS hybrid.
--   - Eze / SS&C Eze (formerly Eze Software / RealTick) — popular
--     among hedge funds (.eze / .csv).
--   - Itiviti (Broadridge) — institutional EMS.
--   - TradingScreen — multi-asset cloud OMS/EMS.
--   - iMatch — local AR variant from Buenos Aires shops.
--   - Portware (FactSet) — algorithmic execution.
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\OMS\<year>\
--     order_blotter_<yyyymmdd>.csv               daily blotter
--     fill_report_<yyyymmdd>.csv                 fills detail
--     best_ex_report_<yyyy>q<n>.pdf              CNV RG 731
--     allocation_<fund>_<yyyymmdd>.csv           post-trade alloc
--     tca_report_<broker>_<yyyy>q<n>.pdf         TCA analysis
--     broker_list.json                           approved brokers
--     order_audit_trail_<yyyymmdd>.csv           CNV RG 622 art.50
--     pre_trade_compliance.json                  pre-trade rules
--     restricted_list_<yyyymm>.csv               restricted tickers
--     watch_list_<yyyymm>.csv                    PLA watch list
--     block_trade_<yyyymmdd>.csv                 block trades
--     cross_trade_<yyyymmdd>.csv                 cross-trade book
--     cnv_rg731_report_<yyyy>.xml                annual best-ex
--     oms_config.ini                             OMS app config
--     fix_session.cfg                            FIX 4.4 session
--
-- Regulatory base:
--
--   CNV RG 731       Mejor Ejecución / Best Execution (FCI)
--   CNV RG 731 art.6   Pre-trade compliance suitability
--   CNV RG 622 art.41  Block-trade reporting
--   CNV RG 622 art.42  Cross-trade fairness
--   CNV RG 622 art.43  Restricted-list (insider)
--   CNV RG 622 art.50  Order Audit Trail (OAT)
--   BCRA Com. A 7916   Wholesale audit trail
--   UIF Res. 21/2018   PLA/FT watch list
--   Ley 26.831         Mercado de Capitales (insider art.117)
--   Ley 25.246         Encubrimiento + LA (PLA/FT)
--   Ley 27.401         Corporate criminal liability
--
-- MITRE / CWE / Industry Standards:
--
--   T1213    Data from Info Repositories (OMS vault)
--   T1552    Unsecured Credentials (FIX session config)
--   T1078    Valid Accounts (OMS API keys)
--   T1005    Data from Local System (blotter export)
--   FIX 4.4 / 5.0 SP2   Financial Information eXchange protocol
--   FIX SenderCompID / TargetCompID / EncryptMethod fields
--   ISO 15022 / 20022   Settlement standards
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config              — cleartext.
--   has_order_blotter                   — daily blotter.
--   has_fill_report                     — execution fills.
--   has_best_ex_report                  — CNV RG 731 best-ex.
--   has_allocation                      — post-trade alloc.
--   has_tca_report                      — Transaction Cost Analysis.
--   has_broker_list                     — approved counterparty list.
--   has_order_audit_trail               — CNV RG 622 art.50 OAT.
--   has_pre_trade_compliance            — pre-trade rules.
--   has_restricted_list                 — insider restricted tickers.
--   has_watch_list                      — PLA/FT watch list.
--   has_block_trade                     — block-trade record.
--   has_cross_trade                     — cross-trade book.
--   has_cnv_rg731_report                — annual best-ex filing.
--   has_fix_session_config              — FIX 4.4 session cfg.
--   has_sociedad_gerente_cuit           — sociedad gerente CUIT.
--   has_large_order_value               — order value > threshold.
--   is_credential_exposure_risk         — readable + (password OR FIX
--                                         credentials OR API token).
--   is_best_execution_disclosure_risk   — readable + (best-ex report
--                                         OR TCA OR broker-list).
--   is_insider_information_risk         — readable + (restricted-list
--                                         OR watch-list OR cross-trade
--                                         OR pre-trade compliance).
--   is_order_audit_trail_leak           — readable + (OAT OR blotter
--                                         OR fills OR allocation OR
--                                         CNV RG 731 filing).

CREATE TABLE IF NOT EXISTS host_arg_oms (
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
            'oms-order-blotter','oms-fill-report',
            'oms-best-ex-report','oms-allocation',
            'oms-tca-report','oms-broker-list',
            'oms-order-audit-trail','oms-pre-trade-compliance',
            'oms-restricted-list','oms-watch-list',
            'oms-block-trade','oms-cross-trade',
            'oms-cnv-rg731-report','oms-fix-session-config',
            'oms-config','oms-credentials',
            'oms-installer','other','unknown'
        )),
    oms_platform                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (oms_platform IN (
            'charles-river','fidessa',
            'bloomberg-aim','bloomberg-emsx',
            'flextrade','eze','itiviti','tradingscreen',
            'imatch','portware',
            'custom','none','unknown'
        )),
    oms_role                    TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (oms_role IN (
            'portfolio-manager','trader','head-trader',
            'compliance-officer','operations-analyst',
            'middle-office','back-office',
            'head-of-trading','cio','cco',
            'api','other','unknown'
        )),
    order_side                  TEXT    NOT NULL DEFAULT ''
        CHECK (order_side IN (
            '','buy','sell','short-sell','buy-cover',
            'none','unknown'
        )),
    order_type                  TEXT    NOT NULL DEFAULT ''
        CHECK (order_type IN (
            '','market','limit','stop','stop-limit',
            'vwap','twap','pegged','iceberg','dark-pool',
            'custom','none','unknown'
        )),
    execution_venue             TEXT    NOT NULL DEFAULT ''
        CHECK (execution_venue IN (
            '','byma','mae','matba-rofex','mav',
            'nyse','nasdaq','arca','bats',
            'otc','dark-pool',
            'custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    sociedad_gerente_cuit_prefix       TEXT    NOT NULL DEFAULT ''
        CHECK (sociedad_gerente_cuit_prefix IN ('','30','33','34')),
    sociedad_gerente_cuit_suffix4      TEXT    NOT NULL DEFAULT '',
    fix_sender_comp_id_hash     TEXT    NOT NULL DEFAULT '',
    fix_target_comp_id_hash     TEXT    NOT NULL DEFAULT '',
    order_count                 INTEGER NOT NULL DEFAULT 0,
    fill_count                  INTEGER NOT NULL DEFAULT 0,
    broker_count                INTEGER NOT NULL DEFAULT 0,
    restricted_ticker_count     INTEGER NOT NULL DEFAULT 0,
    largest_order_notional_ars  INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_order_blotter           INTEGER NOT NULL DEFAULT 0 CHECK (has_order_blotter IN (0,1)),
    has_fill_report             INTEGER NOT NULL DEFAULT 0 CHECK (has_fill_report IN (0,1)),
    has_best_ex_report          INTEGER NOT NULL DEFAULT 0 CHECK (has_best_ex_report IN (0,1)),
    has_allocation              INTEGER NOT NULL DEFAULT 0 CHECK (has_allocation IN (0,1)),
    has_tca_report              INTEGER NOT NULL DEFAULT 0 CHECK (has_tca_report IN (0,1)),
    has_broker_list             INTEGER NOT NULL DEFAULT 0 CHECK (has_broker_list IN (0,1)),
    has_order_audit_trail       INTEGER NOT NULL DEFAULT 0 CHECK (has_order_audit_trail IN (0,1)),
    has_pre_trade_compliance    INTEGER NOT NULL DEFAULT 0 CHECK (has_pre_trade_compliance IN (0,1)),
    has_restricted_list         INTEGER NOT NULL DEFAULT 0 CHECK (has_restricted_list IN (0,1)),
    has_watch_list              INTEGER NOT NULL DEFAULT 0 CHECK (has_watch_list IN (0,1)),
    has_block_trade             INTEGER NOT NULL DEFAULT 0 CHECK (has_block_trade IN (0,1)),
    has_cross_trade             INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_trade IN (0,1)),
    has_cnv_rg731_report        INTEGER NOT NULL DEFAULT 0 CHECK (has_cnv_rg731_report IN (0,1)),
    has_fix_session_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_fix_session_config IN (0,1)),
    has_sociedad_gerente_cuit   INTEGER NOT NULL DEFAULT 0 CHECK (has_sociedad_gerente_cuit IN (0,1)),
    has_large_order_value       INTEGER NOT NULL DEFAULT 0 CHECK (has_large_order_value IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_best_execution_disclosure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_best_execution_disclosure_risk IN (0,1)),
    is_insider_information_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_insider_information_risk IN (0,1)),
    is_order_audit_trail_leak   INTEGER NOT NULL DEFAULT 0 CHECK (is_order_audit_trail_leak IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_oms_password
    ON host_arg_oms(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_oms_blotter
    ON host_arg_oms(reporting_period, order_count) WHERE has_order_blotter = 1;

CREATE INDEX IF NOT EXISTS idx_oms_fill
    ON host_arg_oms(reporting_period, fill_count) WHERE has_fill_report = 1;

CREATE INDEX IF NOT EXISTS idx_oms_best_ex
    ON host_arg_oms(reporting_period, oms_platform) WHERE has_best_ex_report = 1;

CREATE INDEX IF NOT EXISTS idx_oms_alloc
    ON host_arg_oms(reporting_period) WHERE has_allocation = 1;

CREATE INDEX IF NOT EXISTS idx_oms_tca
    ON host_arg_oms(reporting_period, oms_platform) WHERE has_tca_report = 1;

CREATE INDEX IF NOT EXISTS idx_oms_brokers
    ON host_arg_oms(broker_count) WHERE has_broker_list = 1;

CREATE INDEX IF NOT EXISTS idx_oms_oat
    ON host_arg_oms(reporting_period, order_count) WHERE has_order_audit_trail = 1;

CREATE INDEX IF NOT EXISTS idx_oms_pre_trade
    ON host_arg_oms(file_path) WHERE has_pre_trade_compliance = 1;

CREATE INDEX IF NOT EXISTS idx_oms_restricted
    ON host_arg_oms(reporting_period, restricted_ticker_count) WHERE has_restricted_list = 1;

CREATE INDEX IF NOT EXISTS idx_oms_watch
    ON host_arg_oms(reporting_period) WHERE has_watch_list = 1;

CREATE INDEX IF NOT EXISTS idx_oms_block
    ON host_arg_oms(reporting_period, largest_order_notional_ars) WHERE has_block_trade = 1;

CREATE INDEX IF NOT EXISTS idx_oms_cross
    ON host_arg_oms(reporting_period) WHERE has_cross_trade = 1;

CREATE INDEX IF NOT EXISTS idx_oms_rg731
    ON host_arg_oms(reporting_period) WHERE has_cnv_rg731_report = 1;

CREATE INDEX IF NOT EXISTS idx_oms_fix
    ON host_arg_oms(fix_sender_comp_id_hash) WHERE has_fix_session_config = 1;

CREATE INDEX IF NOT EXISTS idx_oms_sg_cuit
    ON host_arg_oms(sociedad_gerente_cuit_prefix, sociedad_gerente_cuit_suffix4) WHERE has_sociedad_gerente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_oms_large_value
    ON host_arg_oms(largest_order_notional_ars) WHERE has_large_order_value = 1;

CREATE INDEX IF NOT EXISTS idx_oms_cred_exp
    ON host_arg_oms(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_oms_best_ex_disc
    ON host_arg_oms(file_path) WHERE is_best_execution_disclosure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_oms_insider
    ON host_arg_oms(file_path) WHERE is_insider_information_risk = 1;

CREATE INDEX IF NOT EXISTS idx_oms_oat_leak
    ON host_arg_oms(file_path) WHERE is_order_audit_trail_leak = 1;

CREATE INDEX IF NOT EXISTS idx_oms_drift
    ON host_arg_oms(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_oms_kind
    ON host_arg_oms(artifact_kind, oms_platform);
