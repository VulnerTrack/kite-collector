-- host_arg_homebroker inventories Decsis HomeBroker (HB)
-- white-label terminal artifact files cached on Argentine
-- retail, prop-desk, and small-ALYC workstations.
--
-- Decsis HomeBroker is the dominant white-label trading
-- terminal used by 100+ small/medium Argentine ALYCs, e.g.:
--
--   Adcap, Maxinver, Bull Market Brokers, Servicio de
--   Comercio Bursátil (SCB), Invertir en Bolsa, Industrial
--   Valores, Allaria-MegaQM retail, Buenos Aires Valores,
--   Tavelli, Adcap Securities, Soluciones Mobiliarias.
--
-- The same `HomeBroker.exe` / `HB.exe` binary boots with a
-- per-ALYC branding skin downloaded at first launch. The
-- backing protocol is SignalR (Microsoft) + REST. Many
-- algotrading retail desks pivot off the SignalR endpoint
-- via `pyhomebroker` (iter 150).
--
-- **The HomeBroker-terminal layer.** Distinct from:
--   - iter 150 winargpyhomebroker      pyhomebroker scraper
--   - iter 151 winargiolinvertironline IOL direct
--   - iter 152 winargcocoscapital      Cocos fintech
--   - iter 153 winargecotrader         ROFEX TraderPro
--   - iter 154 winargbalanz            Balanz direct
--
-- Workstation cache footprint:
--
--   C:\HomeBroker\config.json             terminal cfg
--   C:\HomeBroker\skin\<alyc>.css         broker skin
--   C:\HomeBroker\users\<user>\saved.xml  user prefs
--   %APPDATA%\HomeBroker\session.tok      SignalR token
--   %APPDATA%\HomeBroker\watchlist.json   watchlist cache
--   %APPDATA%\HomeBroker\positions.json   positions cache
--   %APPDATA%\HomeBroker\orders.json      orders cache
--   %APPDATA%\HomeBroker\charts\*.chart   chart templates
--   %APPDATA%\HomeBroker\logs\signalr.log SignalR session log
--
-- HomeBroker-specific risk signals:
--   * Cleartext password in config.json = T1552
--   * SignalR access token leak (bearer) = T1078 (Valid Accts)
--   * ALYC-branding skin identifies the white-label broker
--   * High-frequency cancellation log markers = CNV RG 731
--     Art. 23 (manipulación de mercado) concern
--   * Cliente CUIT in positions/orders = Ley 25.326 PII
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes (ALYC)
--   CNV RG 622       Operativa + transparencia
--   CNV RG 1023      Ciberresiliencia
--   Ley 25.326       Protección de Datos Personales
--   UIF Resol. 30    PEP / AML
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1056.4  Credential API Hooking (SignalR token reuse)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_password_in_config       — config.json cleartext.
--   has_signalr_token            — SignalR bearer leak.
--   has_alyc_branding            — known ALYC skin present.
--   has_distinct_alyc_count      — # of distinct branded skins.
--   has_high_cancel_rate         — SignalR log shows >50% cancels.
--   has_cliente_cuit             — cliente CUIT detected.
--   is_credential_exposure_risk  — readable + (password OR
--                                  SignalR token OR cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_homebroker (
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
            'homebroker-config','homebroker-credentials',
            'homebroker-watchlist','homebroker-positions-cache',
            'homebroker-orders-cache','homebroker-chart-template',
            'homebroker-signalr-log','homebroker-skin',
            'homebroker-installer','other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'retail','wealth','corporate','api-scraper',
            'demo','other','unknown'
        )),
    alyc_branding               TEXT    NOT NULL DEFAULT '',
    broker_matricula            TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    signalr_token_hash          TEXT    NOT NULL DEFAULT '',
    username_hash               TEXT    NOT NULL DEFAULT '',
    session_first_seen          TEXT    NOT NULL DEFAULT '',
    session_last_seen           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    distinct_symbols_count      INTEGER NOT NULL DEFAULT 0,
    order_event_count           INTEGER NOT NULL DEFAULT 0,
    cancel_event_count          INTEGER NOT NULL DEFAULT 0,
    fill_event_count            INTEGER NOT NULL DEFAULT 0,
    cancel_rate_bps             INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_signalr_token           INTEGER NOT NULL DEFAULT 0 CHECK (has_signalr_token IN (0,1)),
    has_alyc_branding           INTEGER NOT NULL DEFAULT 0 CHECK (has_alyc_branding IN (0,1)),
    has_high_cancel_rate        INTEGER NOT NULL DEFAULT 0 CHECK (has_high_cancel_rate IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_homebroker_password
    ON host_arg_homebroker(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_homebroker_signalr
    ON host_arg_homebroker(file_path) WHERE has_signalr_token = 1;

CREATE INDEX IF NOT EXISTS idx_homebroker_branding
    ON host_arg_homebroker(alyc_branding, period_yyyymm) WHERE has_alyc_branding = 1;

CREATE INDEX IF NOT EXISTS idx_homebroker_cancel
    ON host_arg_homebroker(alyc_branding, period_yyyymm) WHERE has_high_cancel_rate = 1;

CREATE INDEX IF NOT EXISTS idx_homebroker_cliente
    ON host_arg_homebroker(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_homebroker_exposure
    ON host_arg_homebroker(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_homebroker_drift
    ON host_arg_homebroker(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_homebroker_kind
    ON host_arg_homebroker(artifact_kind, account_class);
