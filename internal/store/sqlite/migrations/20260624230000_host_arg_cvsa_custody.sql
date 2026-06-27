-- host_arg_cvsa_custody inventories Caja de Valores S.A.
-- (CVSA) custody-account files cached on ALYC broker,
-- custodian, and back-office workstations.
--
-- CVSA is Argentina's central securities depository (CSD)
-- under CNV oversight. Every BYMA equity, sovereign bond,
-- ON corporativa, FCI cuotaparte, and CEDEAR is held in
-- a CVSA "cuenta comitente". Each ALYC broker maintains
-- client custody accounts; the daily reconciliation drops
-- account-level XML / CSV / .cda files on operator
-- workstations.
--
-- Files cached on workstations:
--
--   cuenta_comitente_<num>_<broker>.xml   client holdings
--   tenencias_<broker>_<period>.xml       broker aggregate
--   saldos_clientes_<period>.csv          client balance dump
--   liquidacion_titulos_<period>.csv      settlement record
--   transferencia_<id>.xml                DvP transfer
--   DRR_<period>.xml                      cuentas restringidas
--   titulares_<num>.xml                   account-holder list
--   *.cda                                 Caja Doc Archive
--
-- **The central-depositary layer.** Distinct from:
--   - iter 107 winargcnvalyc   ALYC broker disclosure
--   - iter 109 winargmatbarofex derivatives positions
--   - iter 110 winargfci        FCI mutual-fund layer
--   - iter 111 winargpymebursatil PyME instrument-level
--   - iter 113 winargfix        wire-protocol session logs
--
-- Account-level signals matter for:
--   * AML / FATCA (cliente CUIT + foreign-residence flag).
--   * Concentration risk (single ticker > 50 % of account).
--   * Insider-trading recon (large discretionary positions).
--
-- Regulatory base:
--   Ley 26.831 — Mercado de Capitales
--   CNV RG 622, RG 731, RG 813
--   CVSA Reglamento Operativo
--   BCRA Com. A 7916 — operaciones cambiarias
--   FATCA / CRS — financial-account reporting
--
-- MITRE / CWE:
--   T1213   Data from Information Repositories
--   T1592   Gather Victim Org Information (custody dump)
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 (cliente cotitular CUIT)
--
-- Headline finding shapes:
--   has_foreign_owner          — cliente CUIT carries
--                                foreign-residence marker.
--   has_high_concentration     — single instrument > 50 %
--                                of account market value.
--   has_large_holdings         — total > 100 M ARS.
--   has_cotitulares            — > 1 account holder.
--   is_credential_exposure_risk — readable file + cliente
--                                CUIT + holdings detail.
--
-- All CUITs reduced to entity-type prefix + last 4 digits.

CREATE TABLE IF NOT EXISTS host_arg_cvsa_custody (
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
            'cuenta-comitente','tenencias-broker',
            'saldos-clientes','liquidacion-titulos',
            'transferencia-dvp','drr-restringidas',
            'titulares','cda-archive',
            'other','unknown'
        )),
    broker_matricula            TEXT    NOT NULL DEFAULT '',
    broker_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (broker_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    broker_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    cuenta_comitente_suffix4    TEXT    NOT NULL DEFAULT '',
    instrument_count            INTEGER NOT NULL DEFAULT 0,
    cotitulares_count           INTEGER NOT NULL DEFAULT 0,
    max_position_ars_cents      INTEGER NOT NULL DEFAULT 0,
    total_position_ars_cents    INTEGER NOT NULL DEFAULT 0,
    max_position_pct            INTEGER NOT NULL DEFAULT 0
        CHECK (max_position_pct BETWEEN 0 AND 100),
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_foreign_owner           INTEGER NOT NULL DEFAULT 0 CHECK (has_foreign_owner IN (0,1)),
    has_high_concentration      INTEGER NOT NULL DEFAULT 0 CHECK (has_high_concentration IN (0,1)),
    has_large_holdings          INTEGER NOT NULL DEFAULT 0 CHECK (has_large_holdings IN (0,1)),
    has_cotitulares             INTEGER NOT NULL DEFAULT 0 CHECK (has_cotitulares IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_cvsa_foreign
    ON host_arg_cvsa_custody(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_foreign_owner = 1;

CREATE INDEX IF NOT EXISTS idx_cvsa_concentration
    ON host_arg_cvsa_custody(broker_matricula) WHERE has_high_concentration = 1;

CREATE INDEX IF NOT EXISTS idx_cvsa_large
    ON host_arg_cvsa_custody(broker_matricula, period_yyyymm) WHERE has_large_holdings = 1;

CREATE INDEX IF NOT EXISTS idx_cvsa_cotitulares
    ON host_arg_cvsa_custody(cuenta_comitente_suffix4) WHERE has_cotitulares = 1;

CREATE INDEX IF NOT EXISTS idx_cvsa_exposure
    ON host_arg_cvsa_custody(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_cvsa_drift
    ON host_arg_cvsa_custody(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_cvsa_broker
    ON host_arg_cvsa_custody(broker_matricula, broker_cuit_prefix, broker_cuit_suffix4);

CREATE INDEX IF NOT EXISTS idx_cvsa_cliente
    ON host_arg_cvsa_custody(cliente_cuit_prefix, cliente_cuit_suffix4);
