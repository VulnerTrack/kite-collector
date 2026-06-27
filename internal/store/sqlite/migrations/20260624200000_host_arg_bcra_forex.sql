-- host_arg_bcra_forex inventories Argentine BCRA Comunicación
-- "A" 8137 forex-operations files cached on broker, treasury,
-- and compliance workstations. Comunicación A 8137 (and
-- successor Coms) govern the operational forex layer:
--
--   MULC  — Mercado Único y Libre de Cambios
--   CCL   — Contado con Liquidación (USD-arbitrage)
--   MEP   — Mercado Electrónico de Pagos (Bonar/AL30 etc)
--   Liquidación de Divisas — formal divisa-settlement
--   Dólar Soja / agroexportador — sector-specific régimen
--   RIPCAA — Régimen Informativo Pagos Cambiarios al Exterior
--
-- **Distinct from**:
--   iter 100 winafipexport     — AFIP-side export-invoice receipt
--   iter 95  winbcracendeu     — BCRA banking-solvency CENDEU
--   iter 101 winbcracomunic    — BCRA regulatory advisories cache
--
-- This is the operational BCRA forex declaration of capital
-- flow (active transactions, not passive regulator advisories).
--
-- Regulatory base:
--   BCRA Comunicación "A" 8137 — régimen cambiario 2025
--   BCRA Com. A 7918, 7916 — restricciones cambiarias previas
--   BCRA Com. A 6500 — RIPCAA pagos al exterior
--   AFIP RG 5135 — registro operaciones cambiarias
--   Ley 19.359 — Régimen Penal Cambiario
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information (capital-flight recon)
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 (declarante CUIT)
--
-- Headline finding shapes:
--   is_high_value_usd          — monto > 1 M USD.
--   is_fatf_grey_destination   — counterparty country on FATF
--                                grey list.
--   has_concepto_speculative   — BCRA concepto for "atesoramiento"
--                                (FX hoarding) or "turismo
--                                exterior" (capital-flight via
--                                tourism quota).
--   is_credential_exposure_risk — readable file + declarant CUIT
--                                + monetary detail = financial-
--                                surveillance leak surface.
--
-- All CUITs reduced to entity-type prefix + last 4.

CREATE TABLE IF NOT EXISTS host_arg_bcra_forex (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    declaration_kind            TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (declaration_kind IN (
            'mulc-operacion','ccl-operacion','mep-operacion',
            'liquidacion-divisas','dolar-soja','ripcaa',
            'other','unknown'
        )),
    operacion_type              TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (operacion_type IN (
            'compra','venta','transferencia',
            'liquidacion-exportacion','pago-importacion',
            'dividendos-exterior','intereses-exterior',
            'atesoramiento','turismo-exterior','other','unknown'
        )),
    declarant_cuit_prefix       TEXT    NOT NULL DEFAULT ''
        CHECK (declarant_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    declarant_cuit_suffix4      TEXT    NOT NULL DEFAULT '',
    broker_matricula            TEXT    NOT NULL DEFAULT '',
    counterparty_country        TEXT    NOT NULL DEFAULT '',
    moneda                      TEXT    NOT NULL DEFAULT ''
        CHECK (moneda IN ('','ars','usd','eur','brl','other')),
    monto_usd_cents             INTEGER NOT NULL DEFAULT 0,
    monto_ars_cents             INTEGER NOT NULL DEFAULT 0,
    concepto_bcra               TEXT    NOT NULL DEFAULT '',
    fecha_operacion             TEXT    NOT NULL DEFAULT '',
    is_high_value_usd           INTEGER NOT NULL DEFAULT 0 CHECK (is_high_value_usd IN (0,1)),
    is_fatf_grey_destination    INTEGER NOT NULL DEFAULT 0 CHECK (is_fatf_grey_destination IN (0,1)),
    has_concepto_speculative    INTEGER NOT NULL DEFAULT 0 CHECK (has_concepto_speculative IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_bcra_forex_high_value
    ON host_arg_bcra_forex(fecha_operacion) WHERE is_high_value_usd = 1;

CREATE INDEX IF NOT EXISTS idx_bcra_forex_fatf
    ON host_arg_bcra_forex(counterparty_country) WHERE is_fatf_grey_destination = 1;

CREATE INDEX IF NOT EXISTS idx_bcra_forex_speculative
    ON host_arg_bcra_forex(declarant_cuit_prefix, declarant_cuit_suffix4) WHERE has_concepto_speculative = 1;

CREATE INDEX IF NOT EXISTS idx_bcra_forex_exposure
    ON host_arg_bcra_forex(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_bcra_forex_drift
    ON host_arg_bcra_forex(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_bcra_forex_declarant
    ON host_arg_bcra_forex(declarant_cuit_prefix, declarant_cuit_suffix4);

CREATE INDEX IF NOT EXISTS idx_bcra_forex_concepto
    ON host_arg_bcra_forex(concepto_bcra);
