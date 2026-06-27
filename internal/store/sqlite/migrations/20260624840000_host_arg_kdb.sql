-- host_arg_kdb inventories KX Systems KDB+/Q artifact files
-- cached on Argentine HFT prop-trader, quant-research, and
-- institutional algo-execution workstations.
--
-- KDB+ is the **gold-standard HFT time-series database** sold
-- by KX Systems. Its Q functional programming language is
-- used by top-tier AR prop shops (e.g. Galileo, Argonav) for:
--
--   1. Storage of tick-by-tick market-data across MATba-Rofex,
--      CME, NYSE/NASDAQ, and crypto exchanges.
--   2. Real-time order-book reconstruction (RDB tier).
--   3. Historical-data analysis (HDB tier).
--   4. Low-latency strategy back-testing.
--   5. Co-located algo execution (sub-millisecond).
--
-- KX commercial licenses cost > USD 100 K annually so KDB+
-- adoption flags an institutional / HFT-tier deployment.
-- Free `q` (32-bit Personal Edition) is also possible but
-- limited.
--
-- KDB+/Q distinctive surfaces:
--
--   - .q                 Q programming-language script.
--   - .k                 K-language script (Q's predecessor).
--   - q.k                core Q library file.
--   - k4.lic / kc.lic    KX commercial license file.
--   - <table>/<date>/<col>.dat    HDB column-store partition.
--   - <table>/.d         column-name index.
--   - sym                global symbol table (HDB).
--   - tplog_<date>.log   real-time tick log.
--   - .qrc / .q_dot_qrc  user-startup config.
--   - hdb_root/par.txt   HDB partition map.
--
-- **The KDB+/Q HFT tick-database layer.** Distinct from:
--
--   - iter 167 winargcqg          — CQG vendor terminal.
--   - iter 169 winargtt           — TT vendor terminal.
--   - iter 170 winargsierra       — Sierra Chart (DTC + ACSIL).
--   - iter 172 winargmulticharts  — MultiCharts PowerLanguage.
--   - iter 160 winarglean         — LEAN Python.
--   - iter 144 winargpybacktest   — Python backtest libraries.
--   - iter 113 winargfix          — FIX-protocol wire logs.
--
-- Workstation cache footprint (typical):
--
--   C:\q\                              KX Q install root.
--   C:\q\w64\q.exe                     Windows 64-bit binary.
--   C:\q\l64\q                         Linux 64-bit binary.
--   ~/q/                               user q dir.
--   ~/q/q.k                            core lib.
--   ~/.qrc / ~/q.k                     startup script.
--   ~/q/k4.lic / kc.lic                license (commercial).
--   /opt/kx/                           enterprise install.
--   /data/hdb/                         HDB root.
--   /data/hdb/trades/2026.06.15/       date-partition.
--   /data/hdb/trades/2026.06.15/sym    sym col.
--   /data/hdb/trades/2026.06.15/price  price col.
--   /data/rdb/tplog_2026.06.15.log     tplog.
--   /data/rdb/feed_handler.q           feed cfg.
--
-- KDB+-specific risk signals:
--
--   * KX commercial license file (.lic) present = institutional
--     deployment (typically > USD 100 K spend; high-value
--     compromise target).
--   * Cleartext password in .q script / .qrc = T1552 + CNV RG
--     1023.
--   * Hardcoded broker API credentials in .q feed handler =
--     T1078 + CNV RG 622 art. 23 if execution-side.
--   * tplog_<date>.log carrying live tick data = market-data
--     redistribution license concern (CME / BYMA / NYSE).
--   * HDB > 10 GB = institutional historical-data corpus
--     (potential market-data license breach if redistributed).
--   * Per-row CUIT in trade data = client identity (Ley
--     26.831 art. 117 secreto bursátil).
--   * MATba-Rofex AND CME tables in same HDB = cross-venue
--     arbitrage account.
--   * USDT/ARS or crypto/ARS tables = AFIP RG 5527 crypto
--     reporting trigger.
--   * Distinct entity ports listening (5000-5099 range
--     conventional for KDB+ RDB/HDB) = production deployment.
--   * Subscriber config with `.z.ps` / `.z.po` handlers =
--     RPC surface (arbitrary remote code execution if open).
--   * `\l <script>` calls in .qrc = boot-time autoload chain
--     (supply-chain CWE-829).
--
-- Regulatory base:
--
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes (ALYC)
--   CNV RG 622 art.23 Sistemas Automatizados
--   CNV RG 622 art.50 Operativa con divisas
--   CNV RG 1023      Ciberresiliencia
--   BCRA Com. A 7916 Operaciones cambiarias
--   BCRA Com. A 8005 Ciberseguridad financiera
--   AFIP RG 5193     Securities tax reporting
--   AFIP RG 5527     Crypto reporting
--   Ley 25.326       Datos Personales
--
-- MITRE / CWE:
--
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1190    Exploit Public-Facing Application (KDB+ port)
--   T1059    Command and Scripting (Q / K)
--   CWE-200, CWE-359, CWE-532, CWE-798, CWE-829
--
-- Headline finding shapes:
--
--   has_password_in_config       — script / .qrc cleartext.
--   has_kx_license               — KX commercial license file.
--   has_q_script                 — .q strategy / data script.
--   has_k_script                 — .k script.
--   has_tick_db                  — tplog or HDB present.
--   has_large_hdb                — HDB column > 10 GB.
--   has_subscriber_config        — feed-handler / RPC surface.
--   has_matba_rofex_table        — MATba symbol table.
--   has_cme_futures_table        — CME futures table.
--   has_us_equity_table          — US equity table.
--   has_crypto_data              — crypto / USDT-ARS table.
--   has_cross_venue_arb          — multi-venue tables.
--   has_hft_pattern              — KDB+ implies HFT (auto-flag).
--   has_qrc_autoload             — .qrc with `\l <script>` chain.
--   has_cliente_cuit             — cliente CUIT detected.
--   is_credential_exposure_risk  — readable + (password OR KX
--                                  license OR subscriber cfg
--                                  OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_kdb (
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
            'kdb-config','kdb-credentials',
            'kdb-q-script','kdb-k-script',
            'kdb-license','kdb-hdb-column',
            'kdb-hdb-meta','kdb-tplog',
            'kdb-qrc-startup','kdb-subscriber-config',
            'kdb-installer','other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'hft','prop-trader','quant-research',
            'institutional','market-maker',
            'api','demo','other','unknown'
        )),
    product_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (product_class IN (
            'matba-rofex','cme-futures','us-equity',
            'crypto','multi-venue','options',
            'hft-execution','other','unknown'
        )),
    license_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (license_class IN (
            '','commercial','personal-edition',
            'evaluation','none','unknown'
        )),
    kdb_node_role               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (kdb_node_role IN (
            '','feed-handler','tickerplant',
            'rdb','hdb','gateway','client',
            'multi-role','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    api_key_hash                TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_tables_count       INTEGER NOT NULL DEFAULT 0,
    hdb_partition_count         INTEGER NOT NULL DEFAULT 0,
    hdb_total_bytes             INTEGER NOT NULL DEFAULT 0,
    tplog_record_count          INTEGER NOT NULL DEFAULT 0,
    rpc_handler_count           INTEGER NOT NULL DEFAULT 0,
    autoload_chain_depth        INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_kx_license              INTEGER NOT NULL DEFAULT 0 CHECK (has_kx_license IN (0,1)),
    has_q_script                INTEGER NOT NULL DEFAULT 0 CHECK (has_q_script IN (0,1)),
    has_k_script                INTEGER NOT NULL DEFAULT 0 CHECK (has_k_script IN (0,1)),
    has_tick_db                 INTEGER NOT NULL DEFAULT 0 CHECK (has_tick_db IN (0,1)),
    has_large_hdb               INTEGER NOT NULL DEFAULT 0 CHECK (has_large_hdb IN (0,1)),
    has_subscriber_config       INTEGER NOT NULL DEFAULT 0 CHECK (has_subscriber_config IN (0,1)),
    has_matba_rofex_table       INTEGER NOT NULL DEFAULT 0 CHECK (has_matba_rofex_table IN (0,1)),
    has_cme_futures_table       INTEGER NOT NULL DEFAULT 0 CHECK (has_cme_futures_table IN (0,1)),
    has_us_equity_table         INTEGER NOT NULL DEFAULT 0 CHECK (has_us_equity_table IN (0,1)),
    has_crypto_data             INTEGER NOT NULL DEFAULT 0 CHECK (has_crypto_data IN (0,1)),
    has_cross_venue_arb         INTEGER NOT NULL DEFAULT 0 CHECK (has_cross_venue_arb IN (0,1)),
    has_hft_pattern             INTEGER NOT NULL DEFAULT 0 CHECK (has_hft_pattern IN (0,1)),
    has_qrc_autoload            INTEGER NOT NULL DEFAULT 0 CHECK (has_qrc_autoload IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_kdb_password
    ON host_arg_kdb(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_kdb_license
    ON host_arg_kdb(license_class, file_path) WHERE has_kx_license = 1;

CREATE INDEX IF NOT EXISTS idx_kdb_q_script
    ON host_arg_kdb(file_path) WHERE has_q_script = 1;

CREATE INDEX IF NOT EXISTS idx_kdb_tick_db
    ON host_arg_kdb(kdb_node_role, period_yyyymm) WHERE has_tick_db = 1;

CREATE INDEX IF NOT EXISTS idx_kdb_large_hdb
    ON host_arg_kdb(file_path, hdb_total_bytes) WHERE has_large_hdb = 1;

CREATE INDEX IF NOT EXISTS idx_kdb_subscriber
    ON host_arg_kdb(kdb_node_role) WHERE has_subscriber_config = 1;

CREATE INDEX IF NOT EXISTS idx_kdb_matba
    ON host_arg_kdb(kdb_node_role, period_yyyymm) WHERE has_matba_rofex_table = 1;

CREATE INDEX IF NOT EXISTS idx_kdb_arb
    ON host_arg_kdb(kdb_node_role, period_yyyymm) WHERE has_cross_venue_arb = 1;

CREATE INDEX IF NOT EXISTS idx_kdb_qrc
    ON host_arg_kdb(file_path, autoload_chain_depth) WHERE has_qrc_autoload = 1;

CREATE INDEX IF NOT EXISTS idx_kdb_cliente
    ON host_arg_kdb(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_kdb_exposure
    ON host_arg_kdb(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_kdb_drift
    ON host_arg_kdb(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_kdb_kind
    ON host_arg_kdb(artifact_kind, account_class);
