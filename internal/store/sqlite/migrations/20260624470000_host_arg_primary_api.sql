-- host_arg_primary_api inventories Primary REST/WebSocket API
-- client + pyRofex Python library files cached on Argentine
-- prop-desk, retail-broker (Cocos/IOL/Balanz/PPI), and quant
-- workstations.
--
-- Primary is the REST + WebSocket gateway operated by MATba-
-- Rofex (api.primary.com.ar) that lets Python / JavaScript /
-- C# algo traders place orders, subscribe to market data, and
-- pull instrument metadata without speaking raw FIX. Every
-- Argentine retail broker (IOL, Cocos Capital, Balanz, PPI,
-- Bull Market) and most prop desks bridge to Primary.
--
-- The Python client library is `pyRofex`. It stores:
--
--   ~/.primary/credentials.json     bearer token cache
--   ~/.pyrofex/config.ini           client config
--   ~/.pyrofex/instruments.json     instrument metadata cache
--   ~/.pyrofex/orders_<date>.log    order audit log
--   ~/.pyrofex/ws_state.json        websocket subscription state
--   ~/.pyrofex/refresh_token        long-lived refresh token
--   *.py                            strategy script using pyRofex
--   backtest_history_<sym>.parquet  OHLCV backtest history
--
-- **The Primary REST/WS gateway layer.** Distinct from:
--   - iter 109 winargmatbarofex MATba-Rofex positions files
--   - iter 113 winargfix        raw FIX session logs
--   - iter 108 winalgotrading   generic EA/Jupyter cover
--   - iter 136 winargsiopel     SIOPEL/MAE OTC terminal
--   - iter 137 winargbyma       BYMA equity terminal
--
-- Algotrading-risk context:
--   * Bearer-token leak → full account-flow impersonation
--     across REST + WebSocket.
--   * Production endpoint vs `remarkets` sandbox — token in
--     prod = real money exposure.
--   * Order audit log > 100 orders/min = HFT (CNV RG 731
--     monitoring threshold).
--   * Strategy script (.py) calling pyRofex is algorithmic
--     IP — trade-secret exfil surface.
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes
--   CNV RG 622       Operativa
--   CNV RG 1023      Tecnología + ciberseguridad
--   MATba-Rofex Manual de Conexión Primary API
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials (bearer tokens)
--   T1078    Valid Accounts (compromised API key)
--   T1071    Application Layer Protocol (REST/WS C2)
--   CWE-200, CWE-359, CWE-532, CWE-798
--   Ley 25.326 (cliente cuenta-comitente number)
--
-- Headline finding shapes:
--   has_bearer_token       — credentials.json carries an
--                            access_token / Bearer value.
--   has_refresh_token      — long-lived refresh token on disk.
--   has_account_password   — pyrofex.ini has Password= row.
--   has_production_endpoint — endpoint points to api.primary
--                            .com.ar (vs api.remarkets...).
--   is_high_frequency      — order log shows > 100 orders/min.
--   has_strategy_script    — .py script imports pyRofex.
--   is_credential_exposure_risk — readable file + bearer or
--                            password + production endpoint.
--
-- Bearer tokens NEVER persisted — only SHA-256 hash of the
-- token fragment retained. Account cuentas reduced to last 4.

CREATE TABLE IF NOT EXISTS host_arg_primary_api (
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
            'primary-credentials-json','primary-pyrofex-config',
            'primary-ws-subscriptions','primary-order-audit',
            'primary-instrument-cache','primary-strategy-script',
            'primary-backtest-history','primary-token-cache',
            'primary-installer','other','unknown'
        )),
    environment                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (environment IN (
            'remarkets','production','demo','other','unknown'
        )),
    broker_route                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (broker_route IN (
            'cocos','iol','balanz','ppi','bullmarket','allaria',
            'comafi','direct','other','unknown'
        )),
    account_cuenta_suffix4      TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    bearer_token_hash           TEXT    NOT NULL DEFAULT '',
    refresh_token_hash          TEXT    NOT NULL DEFAULT '',
    order_count                 INTEGER NOT NULL DEFAULT 0,
    order_per_minute_max        INTEGER NOT NULL DEFAULT 0,
    instrument_count            INTEGER NOT NULL DEFAULT 0,
    ws_subscription_count       INTEGER NOT NULL DEFAULT 0,
    max_order_notional_ars_cents INTEGER NOT NULL DEFAULT 0,
    session_first_seen          TEXT    NOT NULL DEFAULT '',
    session_last_seen           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_bearer_token            INTEGER NOT NULL DEFAULT 0 CHECK (has_bearer_token IN (0,1)),
    has_refresh_token           INTEGER NOT NULL DEFAULT 0 CHECK (has_refresh_token IN (0,1)),
    has_account_password        INTEGER NOT NULL DEFAULT 0 CHECK (has_account_password IN (0,1)),
    has_production_endpoint     INTEGER NOT NULL DEFAULT 0 CHECK (has_production_endpoint IN (0,1)),
    has_strategy_script         INTEGER NOT NULL DEFAULT 0 CHECK (has_strategy_script IN (0,1)),
    is_high_frequency           INTEGER NOT NULL DEFAULT 0 CHECK (is_high_frequency IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_primary_bearer
    ON host_arg_primary_api(file_path) WHERE has_bearer_token = 1;

CREATE INDEX IF NOT EXISTS idx_primary_refresh
    ON host_arg_primary_api(file_path) WHERE has_refresh_token = 1;

CREATE INDEX IF NOT EXISTS idx_primary_password
    ON host_arg_primary_api(file_path) WHERE has_account_password = 1;

CREATE INDEX IF NOT EXISTS idx_primary_production
    ON host_arg_primary_api(broker_route) WHERE has_production_endpoint = 1;

CREATE INDEX IF NOT EXISTS idx_primary_hft
    ON host_arg_primary_api(broker_route, period_yyyymm) WHERE is_high_frequency = 1;

CREATE INDEX IF NOT EXISTS idx_primary_strategy
    ON host_arg_primary_api(file_path) WHERE has_strategy_script = 1;

CREATE INDEX IF NOT EXISTS idx_primary_cliente
    ON host_arg_primary_api(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_primary_exposure
    ON host_arg_primary_api(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_primary_drift
    ON host_arg_primary_api(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_primary_env
    ON host_arg_primary_api(environment, artifact_kind);

CREATE INDEX IF NOT EXISTS idx_primary_broker
    ON host_arg_primary_api(broker_route, environment);
