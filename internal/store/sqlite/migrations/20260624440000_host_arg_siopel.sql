-- host_arg_siopel inventories SIOPEL trading-terminal files
-- cached on Argentine bank, broker, prop-desk, and back-
-- office workstations.
--
-- SIOPEL (Sistema Integrado de Operaciones Electrónicas) is
-- the official trading terminal of:
--
--   MAE  Mercado Abierto Electrónico (OTC fixed income, FX,
--        Leliq/Lecap, sovereign-bond rounds)
--   MAV  Mercado Argentino de Valores (PYME ChPD/Pagarés,
--        bridged through SIOPEL gateways)
--   BCRA forex auctions (Subastas BCRA MAE)
--
-- A SIOPEL workstation cache typically lives at:
--
--   C:\SIOPEL\config\siopel.ini       terminal config
--   C:\SIOPEL\datos\rueda_*.dat       market-data cache
--   C:\SIOPEL\logs\sesion_*.log       session log
--   C:\SIOPEL\operadores\*.usr        operator/dealer profile
--   C:\SIOPEL\ruedas\<rueda>.xml      concertación record
--   C:\SIOPEL\precierre\*.csv         pre-close match data
--   C:\MAE\SIOPEL\maeclear\*.xml      MAEClear settlement
--   %APPDATA%\SIOPEL\                 per-user terminal data
--
-- **The OTC-terminal layer.** Distinct from:
--   - iter 107 winargcnvalyc       ALYC broker disclosure
--   - iter 108 winalgotrading      FIX/EA technical layer
--   - iter 109 winargmatbarofex    derivatives positions
--   - iter 110 winargfci           FCI mutual-fund layer
--   - iter 111 winargpymebursatil  PyME instrument-level
--   - iter 113 winargfix           wire-protocol session logs
--   - iter 117 winargcvsa          CVSA custody layer
--
-- SIOPEL-specific risk signals matter for:
--   * MEP / CCL dollar arbitrage outside BCRA Com. A 7916
--     windows.
--   * Caución bursátil > 30-day tenor (regulatory cap).
--   * Concertación outside venue hours (Mon-Fri 10:00-15:00
--     ART for MAE; 09:30-15:00 ART for MAV).
--   * Operator cleartext password in siopel.ini.
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes
--   CNV RG 622       Mercado de Capitales (operativa)
--   BCRA Com. A 7916 operaciones cambiarias MAE
--   BCRA Com. A 7724 ciberseguridad SF
--   MAE Reglamento Operativo
--   MAV Reglamento Operativo
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1056    Input Capture (operator credentials)
--   T1552    Unsecured Credentials (siopel.ini Password=)
--   CWE-200, CWE-359, CWE-532 (logging sensitive info)
--   CWE-798 (hardcoded credentials in .ini)
--   Ley 25.326 (cliente CUIT in concertación record)
--   Ley 27.260 (data protection - AAIP)
--
-- Headline finding shapes:
--   has_password_in_config     — siopel.ini has cleartext
--                                Password=/Clave=/PasswordOp.
--   has_caucion_repo           — rueda-caución entry > 30
--                                days tenor (regulatory cap).
--   has_mep_ccl_arbitrage      — paired MEP buy + CCL sell
--                                in the same session.
--   is_after_hours             — concertación outside venue
--                                hours.
--   has_operator_cuit          — operador CUIT detected.
--   is_credential_exposure_risk — readable file + operator
--                                CUIT + (password OR trade
--                                body OR concertación).
--
-- All CUITs reduced to entity-type prefix + last 4 digits.
-- Dealer codes (4-char alpha) retained verbatim — non-PII.

CREATE TABLE IF NOT EXISTS host_arg_siopel (
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
            'siopel-config','siopel-rueda-data',
            'siopel-session-log','siopel-operator-profile',
            'siopel-precierre','siopel-cache',
            'maeclear-export','mae-bcra-forex',
            'siopel-installer','other','unknown'
        )),
    venue                       TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (venue IN (
            'mae','mav','bcra','other','unknown'
        )),
    rueda_kind                  TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (rueda_kind IN (
            'rueda-cambio','rueda-mep','rueda-bono',
            'rueda-leliq','rueda-rofex-bridge','rueda-caucion',
            'rueda-cheque','rueda-letes','rueda-pmd',
            'other','unknown'
        )),
    operator_matricula          TEXT    NOT NULL DEFAULT '',
    operator_cuit_prefix        TEXT    NOT NULL DEFAULT ''
        CHECK (operator_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    operator_cuit_suffix4       TEXT    NOT NULL DEFAULT '',
    dealer_code                 TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    trade_count                 INTEGER NOT NULL DEFAULT 0,
    concertacion_count          INTEGER NOT NULL DEFAULT 0,
    baja_count                  INTEGER NOT NULL DEFAULT 0,
    max_notional_ars_cents      INTEGER NOT NULL DEFAULT 0,
    caucion_max_tenor_days      INTEGER NOT NULL DEFAULT 0,
    session_first_seen          TEXT    NOT NULL DEFAULT '',
    session_last_seen           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_caucion_repo            INTEGER NOT NULL DEFAULT 0 CHECK (has_caucion_repo IN (0,1)),
    has_mep_ccl_arbitrage       INTEGER NOT NULL DEFAULT 0 CHECK (has_mep_ccl_arbitrage IN (0,1)),
    has_concertacion            INTEGER NOT NULL DEFAULT 0 CHECK (has_concertacion IN (0,1)),
    is_after_hours              INTEGER NOT NULL DEFAULT 0 CHECK (is_after_hours IN (0,1)),
    has_operator_cuit           INTEGER NOT NULL DEFAULT 0 CHECK (has_operator_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_siopel_password
    ON host_arg_siopel(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_siopel_caucion
    ON host_arg_siopel(venue, period_yyyymm) WHERE has_caucion_repo = 1;

CREATE INDEX IF NOT EXISTS idx_siopel_mep_ccl
    ON host_arg_siopel(venue, period_yyyymm) WHERE has_mep_ccl_arbitrage = 1;

CREATE INDEX IF NOT EXISTS idx_siopel_after_hours
    ON host_arg_siopel(venue, period_yyyymm) WHERE is_after_hours = 1;

CREATE INDEX IF NOT EXISTS idx_siopel_operator
    ON host_arg_siopel(operator_cuit_prefix, operator_cuit_suffix4) WHERE has_operator_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_siopel_exposure
    ON host_arg_siopel(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_siopel_drift
    ON host_arg_siopel(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_siopel_venue
    ON host_arg_siopel(venue, artifact_kind);

CREATE INDEX IF NOT EXISTS idx_siopel_rueda
    ON host_arg_siopel(venue, rueda_kind, period_yyyymm);

CREATE INDEX IF NOT EXISTS idx_siopel_dealer
    ON host_arg_siopel(dealer_code, venue);
