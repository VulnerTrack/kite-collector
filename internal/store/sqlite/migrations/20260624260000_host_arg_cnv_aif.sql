-- host_arg_cnv_aif inventories CNV AIF (Autopista de la
-- Información Financiera) issuer-side filings cached on
-- emisor compliance, abogado, and back-office workstations.
--
-- AIF is CNV's online filing portal for every public issuer
-- in Argentina. Beyond hechos relevantes (iter 97) and XBRL
-- financial statements (iter 90), AIF accumulates the
-- *issuer-disclosure* artifacts:
--
--   prospecto_emision_<emisor>_<id>.pdf|.xml   prospecto
--   suplemento_prospecto_<id>.pdf|.xml         suplemento
--   acta_asamblea_<emisor>_<id>.xml            AGO/AGE acta
--   designacion_directorio_<id>.xml            board change
--   convocatoria_asamblea_<id>.xml             convocatoria
--   ddjj_autoridades_<id>.xml                  DDJJ tipo 1
--   ddjj_accionistas_<id>.xml                  DDJJ tipo 2
--   ddjj_beneficiarios_<id>.xml                DDJJ tipo 3
--                                              (beneficial
--                                              owner ≥ 10 %)
--   contrato_fideicomiso_<id>.xml              fideicomiso
--   reglamento_gestion_<fci>.xml               FCI reglamento
--   adenda_<doc>_<id>.xml                      adenda
--
-- **The issuer-disclosure layer.** Distinct from:
--   - iter 90  winargxbrl       — XBRL financial statements
--   - iter 97  winargcnvhr      — hechos relevantes
--   - iter 107 winargcnvalyc    — ALYC broker-dealer
--   - iter 110 winargfci         — FCI mutual-fund layer
--
-- Beneficial-ownership disclosure context:
--   * Resolución CNV 218/2015 + 1004/2024 require every
--     issuer to identify beneficial owners ≥ 10 %.
--   * DDJJ tipo 3 carries CUIT + ownership % per persona
--     física controlante — direct PII (Ley 25.326).
--
-- Regulatory base:
--   Ley 26.831 — Mercado de Capitales
--   CNV RG 622 — Texto ordenado disclosure
--   CNV RG 218/2015 — Beneficiarios finales
--   CNV RG 1004/2024 — Actualización beneficiarios
--   CNV RG 731 — Régimen de agentes
--   AFIP RG 4697 — Beneficiarios finales fiscales
--   GAFI Recomendación 24 — beneficial-ownership
--   UIF Res. 156/2023 — sujetos obligados mercado
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information (board roster)
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 (beneficiario final natural-person CUIT)
--
-- Headline finding shapes:
--   has_directorio_change      — file declares board change.
--   has_capital_change         — emisión / aumento / reducción.
--   has_beneficial_owner       — DDJJ tipo 3 / beneficiario
--                                final data present.
--   is_active_offering         — prospecto vigencia covers
--                                clock time (time-injectable).
--   is_credential_exposure_risk — readable file + emisor +
--                                (beneficial owner OR
--                                directorio change PII).
--
-- All CUITs reduced to entity-type prefix + last 4 digits.

CREATE TABLE IF NOT EXISTS host_arg_cnv_aif (
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
            'prospecto-emision','suplemento-prospecto',
            'acta-asamblea','designacion-directorio',
            'convocatoria-asamblea',
            'ddjj-autoridades','ddjj-accionistas',
            'ddjj-beneficiarios','contrato-fideicomiso',
            'reglamento-gestion','adenda',
            'other','unknown'
        )),
    emisor_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (emisor_cuit_prefix IN ('','30','33','34')),
    emisor_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    emisor_ticker               TEXT    NOT NULL DEFAULT '',
    documento_aif_id            TEXT    NOT NULL DEFAULT '',
    tipo_emision                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (tipo_emision IN (
            'on-corporativa','fci','fideicomiso',
            'acciones','pagare','cedear',
            'other','unknown'
        )),
    monto_emision_ars_cents     INTEGER NOT NULL DEFAULT 0,
    monto_emision_usd_cents     INTEGER NOT NULL DEFAULT 0,
    fecha_aprobacion            TEXT    NOT NULL DEFAULT '',
    vigencia_desde              TEXT    NOT NULL DEFAULT '',
    vigencia_hasta              TEXT    NOT NULL DEFAULT '',
    beneficial_owner_count      INTEGER NOT NULL DEFAULT 0,
    has_directorio_change       INTEGER NOT NULL DEFAULT 0 CHECK (has_directorio_change IN (0,1)),
    has_capital_change          INTEGER NOT NULL DEFAULT 0 CHECK (has_capital_change IN (0,1)),
    has_beneficial_owner        INTEGER NOT NULL DEFAULT 0 CHECK (has_beneficial_owner IN (0,1)),
    is_active_offering          INTEGER NOT NULL DEFAULT 0 CHECK (is_active_offering IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_aif_directorio
    ON host_arg_cnv_aif(emisor_cuit_prefix, emisor_cuit_suffix4) WHERE has_directorio_change = 1;

CREATE INDEX IF NOT EXISTS idx_aif_capital
    ON host_arg_cnv_aif(emisor_cuit_prefix, emisor_cuit_suffix4) WHERE has_capital_change = 1;

CREATE INDEX IF NOT EXISTS idx_aif_beneficial
    ON host_arg_cnv_aif(emisor_cuit_prefix, emisor_cuit_suffix4) WHERE has_beneficial_owner = 1;

CREATE INDEX IF NOT EXISTS idx_aif_active
    ON host_arg_cnv_aif(emisor_ticker, vigencia_hasta) WHERE is_active_offering = 1;

CREATE INDEX IF NOT EXISTS idx_aif_exposure
    ON host_arg_cnv_aif(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_aif_drift
    ON host_arg_cnv_aif(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_aif_emisor
    ON host_arg_cnv_aif(emisor_cuit_prefix, emisor_cuit_suffix4, artifact_kind);

CREATE INDEX IF NOT EXISTS idx_aif_ticker
    ON host_arg_cnv_aif(emisor_ticker, fecha_aprobacion);
