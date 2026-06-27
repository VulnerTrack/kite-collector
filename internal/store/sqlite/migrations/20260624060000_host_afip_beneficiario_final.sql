-- host_afip_beneficiario_final inventories Argentine AFIP /
-- UIF "Beneficiario Final" (Ultimate Beneficial Owner)
-- declaration files cached on accounting / compliance / risk
-- workstations.
--
-- Every Argentine sociedad must file an annual UBO declaration
-- naming the natural persons controlling ≥10 % of capital or
-- votes. These filings are the canonical capital-entity
-- ownership artifact — they reveal the natural-person owners
-- behind every juridical entity, which is exactly the chain
-- of custody every AML investigation needs.
--
-- Regulatory base:
--   AFIP RG 4697/2020 — Régimen de información societaria
--                       (Beneficiario Final)
--   UIF Res. 112/2021 — Identificación del Beneficiario Final
--   UIF Res. 30-E/2017 — Sujetos obligados (alcance)
--   Ley 27.430 art.166 — modificaciones a Ley 19.550 LGS
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information
--   CWE-200, CWE-359, CWE-732 (UBO PII = highest-PII tier)
--   Ley 25.326 — Protección de Datos Personales
--
-- Headline finding shapes:
--   is_high_concentration   — at least one beneficiario with
--                             >50 % capital/control. Single-
--                             owner entity; concentrated
--                             control = elevated AML risk.
--   has_indirect_control_chain — declaration includes
--                             intermediate juridical entities
--                             between the obligado and the
--                             final natural-person beneficiario.
--   has_extranjero_beneficiario — UBO identified by DNI /
--                             pasaporte extranjero rather than
--                             AFIP CUIL → cross-border control.
--   is_borrador             — file is an unfiled DRAFT (estado=
--                             borrador). Compliance gap.
--   is_credential_exposure_risk — readable file + UBO-PII
--                             (natural-person CUIL or DNI
--                             present) = highest-tier Ley
--                             25.326 exposure.
--
-- UBO natural-person CUILs are NEVER stored verbatim — only
-- entity-type prefix (20/23/24/27 for personas físicas) + last
-- 4 digits. Obligado CUIT (juridical 30/33) likewise reduced.

CREATE TABLE IF NOT EXISTS host_afip_beneficiario_final (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    filing_kind                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (filing_kind IN (
            'beneficiario-final-anual','beneficiario-final-modificacion',
            'ddjj-borrador','f8127','ris-bf','other','unknown'
        )),
    estado                      TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (estado IN ('presentada','rectificada','borrador','unknown')),
    obligado_cuit_prefix        TEXT    NOT NULL DEFAULT ''
        CHECK (obligado_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    obligado_cuit_suffix4       TEXT    NOT NULL DEFAULT '',
    obligado_denominacion       TEXT    NOT NULL DEFAULT '',
    period_yyyy                 TEXT    NOT NULL DEFAULT '',
    beneficiarios_count         INTEGER NOT NULL DEFAULT 0,
    max_participacion_pct       INTEGER NOT NULL DEFAULT 0
        CHECK (max_participacion_pct BETWEEN 0 AND 100),
    has_indirect_control_chain  INTEGER NOT NULL DEFAULT 0 CHECK (has_indirect_control_chain IN (0,1)),
    has_extranjero_beneficiario INTEGER NOT NULL DEFAULT 0 CHECK (has_extranjero_beneficiario IN (0,1)),
    is_high_concentration       INTEGER NOT NULL DEFAULT 0 CHECK (is_high_concentration IN (0,1)),
    is_borrador                 INTEGER NOT NULL DEFAULT 0 CHECK (is_borrador IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_bf_high_concentration
    ON host_afip_beneficiario_final(obligado_cuit_prefix, obligado_cuit_suffix4) WHERE is_high_concentration = 1;

CREATE INDEX IF NOT EXISTS idx_bf_borrador
    ON host_afip_beneficiario_final(obligado_cuit_prefix, obligado_cuit_suffix4) WHERE is_borrador = 1;

CREATE INDEX IF NOT EXISTS idx_bf_extranjero
    ON host_afip_beneficiario_final(obligado_cuit_prefix, obligado_cuit_suffix4) WHERE has_extranjero_beneficiario = 1;

CREATE INDEX IF NOT EXISTS idx_bf_exposure
    ON host_afip_beneficiario_final(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_bf_drift
    ON host_afip_beneficiario_final(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_bf_entity
    ON host_afip_beneficiario_final(obligado_cuit_prefix, obligado_cuit_suffix4);
