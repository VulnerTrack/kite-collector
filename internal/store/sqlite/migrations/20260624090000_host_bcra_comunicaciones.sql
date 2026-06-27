-- host_bcra_comunicaciones inventories BCRA (Banco Central de
-- la República Argentina) Comunicaciones cached on banking /
-- compliance / risk workstations. BCRA publishes mandatory
-- regulatory advisories as "Comunicaciones" with type prefix:
--
--   A — Normativa (rules) — sujetos obligados to follow
--   B — Operativa Monetaria
--   C — Información General
--   P — Política
--
-- Compliance teams cache these as PDF / HTML / XML for active
-- regulatory tracking. Filename patterns: `Coma8137.pdf`,
-- `comunicacion_a_8137.xml`, `BCRA_A8137.pdf`.
--
-- BCRA comunicaciones are PUBLIC documents (no PII concern).
-- The audit value is **regulatory-compliance-posture
-- discovery**: which advisories does this workstation
-- actively track? Especially forex (MULC, COTI, comercio
-- exterior) and AML (UIF compliance for sujetos obligados).
--
-- Regulatory base:
--   BCRA Carta Orgánica Ley 24.144
--   BCRA Texto Ordenado (consolidated rules)
--   Each Com. cross-refs via "sustituye a" / "modifica a"
--
-- Headline finding shapes:
--   is_forex_regulation     — materia in {cambios,
--                             comercio-exterior}; relevant to
--                             MULC / COTI / liquidación de
--                             divisas posture.
--   is_aml_regulation       — materia=prevencion-lavado;
--                             pairs with iter 99 winargros.
--   is_recent               — file modified within 90 days.
--   is_credential_exposure_risk — INFORMATIONAL only for
--                             these public docs (kept for
--                             cross-collector reporting parity).

CREATE TABLE IF NOT EXISTS host_bcra_comunicaciones (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    comunicacion_kind           TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (comunicacion_kind IN ('tipo-a','tipo-b','tipo-c','tipo-p','other','unknown')),
    numero                      TEXT    NOT NULL DEFAULT '',
    numero_serie                INTEGER NOT NULL DEFAULT 0,
    materia                     TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (materia IN (
            'cambios','depositos','creditos','normativa-general',
            'monetaria','prevencion-lavado','comercio-exterior',
            'encajes','tasas','capital-minimo','seguros',
            'cooperativas','other','unknown'
        )),
    fecha_emision               TEXT    NOT NULL DEFAULT '',
    fecha_vigencia              TEXT    NOT NULL DEFAULT '',
    sustituye_a                 TEXT    NOT NULL DEFAULT '',
    modifica_a                  TEXT    NOT NULL DEFAULT '',
    asunto                      TEXT    NOT NULL DEFAULT '',
    is_forex_regulation         INTEGER NOT NULL DEFAULT 0 CHECK (is_forex_regulation IN (0,1)),
    is_aml_regulation           INTEGER NOT NULL DEFAULT 0 CHECK (is_aml_regulation IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_bcra_com_forex
    ON host_bcra_comunicaciones(numero_serie) WHERE is_forex_regulation = 1;

CREATE INDEX IF NOT EXISTS idx_bcra_com_aml
    ON host_bcra_comunicaciones(numero_serie) WHERE is_aml_regulation = 1;

CREATE INDEX IF NOT EXISTS idx_bcra_com_recent
    ON host_bcra_comunicaciones(fecha_emision) WHERE is_recent = 1;

CREATE INDEX IF NOT EXISTS idx_bcra_com_drift
    ON host_bcra_comunicaciones(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_bcra_com_numero
    ON host_bcra_comunicaciones(numero);

CREATE INDEX IF NOT EXISTS idx_bcra_com_kind_serie
    ON host_bcra_comunicaciones(comunicacion_kind, numero_serie);
