-- host_pjn_notifications inventories PJN (Poder Judicial de
-- la Nación) electronic-notification files cached on Argentine
-- lawyer / contador / risk-team workstations. PJN's "Sistema
-- de Notificaciones Electrónicas" delivers each providencia,
-- sentencia, cédula, or oficio as a PDF + XML/HTML metadata
-- bundle that lands in:
--
--   %USERPROFILE%\Downloads\notif_*.pdf
--   C:\LexDoctor\Notificaciones\
--   C:\AbogadosOnline\
--   C:\PJN\Cedulas\
--   ~/Documents/PJN/
--
-- Each file carries: carátula de causa (parties + tipo de
-- proceso), CUIJ (Código Único de Identificación de Juzgados),
-- party CUITs, juzgado, secretaría.
--
-- Capital-entity & solvency context:
--   T1592    Gather Victim Org Information (litigation recon)
--   T1213    Data from Information Repositories
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 (Protección de Datos Personales — judicial PII)
--   Ley 26.685 (Expediente Electrónico)
--   Ley 24.522 (Concursos y Quiebras)
--
-- Capital-entity signals (the headline reason for collecting
-- this artifact):
--   tipo_proceso='concurso-preventivo' — Ley 24.522 art.5:
--                 voluntary reorganisation; equivalent to
--                 Chapter 11. Lender alert.
--   tipo_proceso='quiebra'             — Ley 24.522 art.77:
--                 involuntary or voluntary bankruptcy.
--                 Trade-credit cut-off.
--   tipo_proceso='embargo'             — judicial asset seizure
--                 (real estate, bank accounts, receivables).
--   tipo_proceso='inhibicion'          — Ley 17.801 art.39 /
--                 CPCC: inhibición general de bienes;
--                 debtor cannot dispose of assets.
--
-- Headline finding shapes:
--   is_insolvency_proceeding  — concurso-preventivo / quiebra.
--   is_asset_seizure          — embargo / inhibicion.
--   is_credential_exposure_risk — readable file + judicial-PII
--                              (CUIT or carátula present).
--
-- Party CUITs (when discoverable from filename or metadata)
-- are NEVER stored verbatim — only entity-type prefix + last 4.
-- CUIJ likewise stored only as its trailing 4-digit
-- correlativo + year.

CREATE TABLE IF NOT EXISTS host_pjn_notifications (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    notification_kind           TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (notification_kind IN (
            'cedula','providencia','sentencia','oficio',
            'requerimiento','demanda','contestacion','other','unknown'
        )),
    tipo_proceso                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (tipo_proceso IN (
            'concurso-preventivo','quiebra','ejecucion',
            'embargo','inhibicion','alimentos','laboral',
            'civil','comercial','penal','otro','unknown'
        )),
    target_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (target_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    target_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    cuij_year                   TEXT    NOT NULL DEFAULT '',
    cuij_suffix4                TEXT    NOT NULL DEFAULT '',
    juzgado                     TEXT    NOT NULL DEFAULT '',
    secretaria                  TEXT    NOT NULL DEFAULT '',
    notification_date           TEXT    NOT NULL DEFAULT '',
    is_insolvency_proceeding    INTEGER NOT NULL DEFAULT 0 CHECK (is_insolvency_proceeding IN (0,1)),
    is_asset_seizure            INTEGER NOT NULL DEFAULT 0 CHECK (is_asset_seizure IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_pjn_insolvency
    ON host_pjn_notifications(target_cuit_prefix, target_cuit_suffix4) WHERE is_insolvency_proceeding = 1;

CREATE INDEX IF NOT EXISTS idx_pjn_seizure
    ON host_pjn_notifications(target_cuit_prefix, target_cuit_suffix4) WHERE is_asset_seizure = 1;

CREATE INDEX IF NOT EXISTS idx_pjn_exposure
    ON host_pjn_notifications(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_pjn_drift
    ON host_pjn_notifications(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_pjn_entity
    ON host_pjn_notifications(target_cuit_prefix, target_cuit_suffix4);
