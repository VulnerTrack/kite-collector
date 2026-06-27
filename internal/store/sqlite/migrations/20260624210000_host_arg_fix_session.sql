-- host_arg_fix_session inventories FIX-protocol session-log
-- files cached on Argentine broker, prop-desk, and algotrading
-- workstations.
--
-- FIX (Financial Information eXchange) is the wire protocol
-- spoken by every Argentine venue gateway:
--
--   MATba-Rofex   FIX 4.4  futures + options
--   BYMA Aries    FIX 5.0  equities + sovereign bonds
--   MAE           FIX 4.4  OTC fixed-income
--   Primary API   REST     (bridged to FIX via QuickFIX)
--
-- Files cached on workstations:
--
--   FIX.4.4-SENDER-TARGET.event.log   QuickFIX/J event log
--   FIX.4.4-SENDER-TARGET.messages.log inbound + outbound msgs
--   <session>.cfg                     QuickFIX session config
--   primary_session_YYYYMMDD.log      Primary REST audit log
--
-- **The wire-protocol session-log layer.** Pairs with:
--   - iter 107 winargcnvalyc       ALYC broker-dealer disclosure
--   - iter 108 winalgotrading      strategy + bot binaries
--   - iter 109 winargmatbarofex    derivatives position files
--   - iter 112 winargbcraforex     BCRA forex declaration cache
--
-- Algotrading-risk context:
--   * Cancel-to-order ratio > 50 % is a spoofing signature.
--   * Sub-second order rate is HFT (CNV monitoring threshold).
--   * Sessions active outside venue hours = improper trading.
--
-- Regulatory base:
--   CNV RG 731 — Régimen de Agentes
--   CNV RG 622 — Mercado de Capitales
--   Ley 26.831 — Mercado de Capitales
--   BCRA Com. A 7916 — operaciones cambiarias FIX
--   MATba-Rofex Reglamento Operativo (sesiones FIX)
--   BYMA Aries Manual de Conexión
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1056    Input Capture (FIX message body)
--   T1552    Unsecured Credentials (FIX tag 554)
--   CWE-200, CWE-359, CWE-532 (logging sensitive info)
--   CWE-798 (hardcoded credentials in .cfg)
--   Ley 25.326 (account CUIT in session metadata)
--
-- Headline finding shapes:
--   has_password_tag           — FIX tag 554 found in cleartext.
--   has_spoofing_pattern       — cancel-to-order ratio > 50 %.
--   is_after_hours             — session entries outside venue
--                                hours (Mon–Fri 11:00–17:00 ART
--                                BYMA; 09:00–16:00 ART MATba).
--   has_account_cuit           — Account tag (1) contains
--                                CUIT pattern.
--   is_credential_exposure_risk — readable file + account CUIT
--                                + (password OR message body).
--
-- All CUITs reduced to entity-type prefix + last 4.
-- SenderCompID / TargetCompID retained only as alphanumeric
-- suffix4 (truncated 4 trailing alphanumerics).

CREATE TABLE IF NOT EXISTS host_arg_fix_session (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    session_kind                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (session_kind IN (
            'rofex-fix44','byma-fix50','mae-fix44',
            'primary-rest','quickfix-bridge','config',
            'other','unknown'
        )),
    venue                       TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (venue IN (
            'rofex','byma','mae','mtba','other','unknown'
        )),
    sender_comp_suffix4         TEXT    NOT NULL DEFAULT '',
    target_comp_suffix4         TEXT    NOT NULL DEFAULT '',
    broker_matricula            TEXT    NOT NULL DEFAULT '',
    account_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (account_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    account_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    message_count               INTEGER NOT NULL DEFAULT 0,
    order_count                 INTEGER NOT NULL DEFAULT 0,
    cancel_count                INTEGER NOT NULL DEFAULT 0,
    exec_count                  INTEGER NOT NULL DEFAULT 0,
    session_first_seen          TEXT    NOT NULL DEFAULT '',
    session_last_seen           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_password_tag            INTEGER NOT NULL DEFAULT 0 CHECK (has_password_tag IN (0,1)),
    has_spoofing_pattern        INTEGER NOT NULL DEFAULT 0 CHECK (has_spoofing_pattern IN (0,1)),
    is_after_hours              INTEGER NOT NULL DEFAULT 0 CHECK (is_after_hours IN (0,1)),
    has_account_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_account_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_fix_password
    ON host_arg_fix_session(file_path) WHERE has_password_tag = 1;

CREATE INDEX IF NOT EXISTS idx_fix_spoofing
    ON host_arg_fix_session(venue, period_yyyymm) WHERE has_spoofing_pattern = 1;

CREATE INDEX IF NOT EXISTS idx_fix_after_hours
    ON host_arg_fix_session(venue, period_yyyymm) WHERE is_after_hours = 1;

CREATE INDEX IF NOT EXISTS idx_fix_account_cuit
    ON host_arg_fix_session(account_cuit_prefix, account_cuit_suffix4) WHERE has_account_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_fix_exposure
    ON host_arg_fix_session(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_fix_drift
    ON host_arg_fix_session(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_fix_venue
    ON host_arg_fix_session(venue, session_kind);

CREATE INDEX IF NOT EXISTS idx_fix_broker
    ON host_arg_fix_session(broker_matricula, venue);
