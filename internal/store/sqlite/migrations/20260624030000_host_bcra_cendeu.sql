-- host_bcra_cendeu inventories BCRA "Central de Deudores del
-- Sistema Financiero" snapshot files cached on Argentine
-- banking / consultoría workstations. BCRA publishes the
-- monthly aggregate of every CUIT's debt position across
-- regulated financial institutions; banks, risk departments,
-- and rating consultoras download CSV / TXT extracts to feed
-- credit-risk pipelines.
--
-- BCRA "Situación" scale (Comunicación A 2729 / Texto Ordenado
-- Clasificación de Deudores):
--   1  Normal / cumplimiento puntual
--   2  Con seguimiento especial / riesgo bajo
--   3  Con problemas
--   4  Alto riesgo de insolvencia
--   5  Irrecuperable
--   6  Irrecuperable por disposición técnica
--
-- Situación >= 4 = the entity is functionally insolvent — the
-- headline capital-entity-solvency signal for this collector.
--
-- Capital-entity & PII context:
--   T1592    Gather Victim Org Information (financial-strength
--            recon)
--   T1213    Data from Information Repositories
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 (Protección de Datos Personales — Deudores
--            del Sistema Financiero)
--   BCRA Com. A 2729, A 8137 (Régimen de Información)
--
-- Headline finding shapes:
--   has_high_risk_debtors  — at least one row with
--                            situación >= 4 (insolvency risk).
--   has_cheques_rechazados — file references rejected-cheque
--                            counters.
--   is_high_value_file     — file > 1 MiB (operative snapshot).
--   is_credential_exposure_risk — readable file + sensitive
--                            snapshot (consolidated or padrón)
--                            carrying CUIT-level debt PII.
--
-- CUIT (when discoverable from filename for per-entity
-- extracts) is NEVER stored verbatim — only entity-type prefix
-- (20/23/24/27/30/33/34) and the last 4 digits.

CREATE TABLE IF NOT EXISTS host_bcra_cendeu (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    snapshot_kind               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (snapshot_kind IN ('consolidated','per-entity','padron','unknown')),
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    target_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (target_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    target_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    record_count                INTEGER NOT NULL DEFAULT 0,
    distinct_entity_count       INTEGER NOT NULL DEFAULT 0,
    max_situacion               INTEGER NOT NULL DEFAULT 0
        CHECK (max_situacion BETWEEN 0 AND 6),
    has_cheques_rechazados      INTEGER NOT NULL DEFAULT 0 CHECK (has_cheques_rechazados IN (0,1)),
    has_high_risk_debtors       INTEGER NOT NULL DEFAULT 0 CHECK (has_high_risk_debtors IN (0,1)),
    is_high_value_file          INTEGER NOT NULL DEFAULT 0 CHECK (is_high_value_file IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_bcra_cendeu_high_risk
    ON host_bcra_cendeu(period_yyyymm) WHERE has_high_risk_debtors = 1;

CREATE INDEX IF NOT EXISTS idx_bcra_cendeu_cheques
    ON host_bcra_cendeu(period_yyyymm) WHERE has_cheques_rechazados = 1;

CREATE INDEX IF NOT EXISTS idx_bcra_cendeu_exposure
    ON host_bcra_cendeu(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_bcra_cendeu_drift
    ON host_bcra_cendeu(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_bcra_cendeu_entity
    ON host_bcra_cendeu(target_cuit_prefix, target_cuit_suffix4);
