-- host_afip_sicore inventories AFIP SICORE / SIRE retention-
-- agent files cached on payroll, treasury, and compliance
-- workstations of retention agents (agentes de retención).
--
-- SICORE (Sistema de Control de Retenciones — RG 738, 2415,
-- 4523) and successor SIRE (Sistema Integrado de Retenciones
-- Electrónicas — RG 5470) require every retention agent to
-- declare, per period, the universe of CUITs they withheld
-- from and the amounts withheld, by régimen (ganancias / IVA
-- / SUSS / IIBB CM, etc.).
--
-- Files cached on workstations:
--
--   SICORE_DDJJ_<period>_<cuit>.txt   F744 aplicativo dump
--   F744_<period>.xml                 XML F744
--   retenciones_<period>.csv          detail per retenido
--   percepciones_<period>.csv         detail per percibido
--   pagos_retenciones_<period>.csv    volante de pago
--   SIRE_CGS_<cuit>_<period>.txt     SIRE CGS comprobantes
--
-- **The retention-agent layer.** Distinct from:
--   - iter 89  winafipwsfev1  outbound invoices (factura E)
--   - iter 100 winafipexport  export factura E
--   - iter 87+ general AFIP collectors
--
-- Why this matters operationally:
--   * The retained-party CUIT list ≈ the agent's vendor /
--     payroll roster — sensitive commercial-intelligence asset.
--   * Natural-person retained (prefix 20/23/24/27) means
--     PII under Ley 25.326.
--   * High retention volume (> 1000 entries) implies a large
--     agent (likely listed entity or major employer).
--
-- Regulatory base:
--   AFIP RG 738   — SICORE original
--   AFIP RG 2415  — Régimen General de Retención
--   AFIP RG 4523  — SIRE para Ganancias
--   AFIP RG 5470  — SIRE integrado
--   AFIP RG 3685  — CITI Compras/Ventas
--   Ley 27.430    — reforma tributaria
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information (vendor list)
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 (retenido natural-person CUIT)
--
-- Headline finding shapes:
--   has_natural_person_retained — at least one retenido CUIT
--                                 has natural-person prefix.
--   has_high_volume             — retained_count > 1000.
--   has_large_retention_total   — total > 100 M ARS.
--   is_credential_exposure_risk — readable file + agent CUIT
--                                 + (natural-person retained OR
--                                 large total).
--
-- All CUITs reduced to entity-type prefix + last 4 digits.

CREATE TABLE IF NOT EXISTS host_afip_sicore (
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
            'sicore-ddjj','f744-xml','retenciones-csv',
            'percepciones-csv','pagos-csv','sire-cgs',
            'other','unknown'
        )),
    regimen_kind                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (regimen_kind IN (
            'ganancias-r6','iva-r1','iva-r2','iva-r3',
            'ssocial-r5','suss-r10','iibb-cm',
            'monotributo','other','unknown'
        )),
    agent_cuit_prefix           TEXT    NOT NULL DEFAULT ''
        CHECK (agent_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    agent_cuit_suffix4          TEXT    NOT NULL DEFAULT '',
    retained_count              INTEGER NOT NULL DEFAULT 0,
    max_retention_ars_cents     INTEGER NOT NULL DEFAULT 0,
    total_retention_ars_cents   INTEGER NOT NULL DEFAULT 0,
    natural_person_retained_count INTEGER NOT NULL DEFAULT 0,
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_natural_person_retained INTEGER NOT NULL DEFAULT 0 CHECK (has_natural_person_retained IN (0,1)),
    has_high_volume             INTEGER NOT NULL DEFAULT 0 CHECK (has_high_volume IN (0,1)),
    has_large_retention_total   INTEGER NOT NULL DEFAULT 0 CHECK (has_large_retention_total IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_sicore_natural
    ON host_afip_sicore(agent_cuit_prefix, agent_cuit_suffix4) WHERE has_natural_person_retained = 1;

CREATE INDEX IF NOT EXISTS idx_sicore_volume
    ON host_afip_sicore(period_yyyymm) WHERE has_high_volume = 1;

CREATE INDEX IF NOT EXISTS idx_sicore_large
    ON host_afip_sicore(agent_cuit_prefix, agent_cuit_suffix4) WHERE has_large_retention_total = 1;

CREATE INDEX IF NOT EXISTS idx_sicore_exposure
    ON host_afip_sicore(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_sicore_drift
    ON host_afip_sicore(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_sicore_agent
    ON host_afip_sicore(agent_cuit_prefix, agent_cuit_suffix4, period_yyyymm);

CREATE INDEX IF NOT EXISTS idx_sicore_regimen
    ON host_afip_sicore(regimen_kind, period_yyyymm);
