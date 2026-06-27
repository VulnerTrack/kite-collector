-- host_afip_citi inventories AFIP CITI Compras/Ventas
-- (RG 3685 / RG 1361) and F2002 IVA files cached on
-- accounting, treasury, and compliance workstations.
--
-- CITI Compras/Ventas are the AFIP IVA cross-check files
-- that every IVA-registered taxpayer dumps monthly:
--
--   CITI_VENTAS_<period>_<cuit>.txt   sales detail per CUIT
--   CITI_COMPRAS_<period>_<cuit>.txt  purchases detail
--   CITI_ALICUOTAS_<period>.txt       IVA aliquot breakdown
--   F2002_<period>.xml                IVA DDJJ summary
--   F2002_alicuotas_<period>.xml      alicuota detail
--
-- A leaked CITI Ventas file = full customer list with
-- revenue. A leaked CITI Compras = full vendor list with
-- spend. Together they reconstruct the entity's B2B
-- transaction graph — the single most sensitive AFIP
-- disclosure surface after WSAA private keys.
--
-- **Distinct from**:
--   - iter 89  winafipwsfev1   AFIP CAE / wsfev1 invoices (individual)
--   - iter 100 winafipexport    AFIP factura E (export)
--   - iter 114 winafipsicore    SICORE retenciones (cross-cutting)
--
-- This is the *aggregated monthly IVA-detail* layer.
--
-- Regulatory base:
--   AFIP RG 1361 — CITI Compras/Ventas original
--   AFIP RG 3685 — Régimen Informativo de Compras y Ventas
--   AFIP RG 2485 — Mis Comprobantes
--   AFIP RG 5616 — IVA Digital
--   Ley 23.349  — Ley de IVA
--   Ley 27.430  — Reforma Tributaria
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information (vendor/customer list)
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 (counterparty natural-person CUIT)
--
-- Headline finding shapes:
--   has_natural_person_counterparty — at least one
--                                     counterparty CUIT
--                                     is natural person.
--   has_high_invoice_count          — counterparty_count
--                                     > 1000.
--   has_large_total                 — total_neto > 500 M ARS.
--   is_credential_exposure_risk     — readable file +
--                                     declarant CUIT +
--                                     (natural person OR
--                                     large total).
--
-- All CUITs reduced to entity-type prefix + last 4 digits.

CREATE TABLE IF NOT EXISTS host_afip_citi (
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
            'citi-ventas','citi-compras','citi-alicuotas',
            'f2002-iva','f2002-alicuotas','comprobantes-export',
            'other','unknown'
        )),
    declarant_cuit_prefix       TEXT    NOT NULL DEFAULT ''
        CHECK (declarant_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    declarant_cuit_suffix4      TEXT    NOT NULL DEFAULT '',
    counterparty_count          INTEGER NOT NULL DEFAULT 0,
    natural_person_counterparty_count INTEGER NOT NULL DEFAULT 0,
    total_neto_ars_cents        INTEGER NOT NULL DEFAULT 0,
    total_iva_ars_cents         INTEGER NOT NULL DEFAULT 0,
    max_invoice_ars_cents       INTEGER NOT NULL DEFAULT 0,
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_natural_person_counterparty INTEGER NOT NULL DEFAULT 0 CHECK (has_natural_person_counterparty IN (0,1)),
    has_high_invoice_count      INTEGER NOT NULL DEFAULT 0 CHECK (has_high_invoice_count IN (0,1)),
    has_large_total             INTEGER NOT NULL DEFAULT 0 CHECK (has_large_total IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_citi_natural
    ON host_afip_citi(declarant_cuit_prefix, declarant_cuit_suffix4) WHERE has_natural_person_counterparty = 1;

CREATE INDEX IF NOT EXISTS idx_citi_high_count
    ON host_afip_citi(period_yyyymm) WHERE has_high_invoice_count = 1;

CREATE INDEX IF NOT EXISTS idx_citi_large
    ON host_afip_citi(declarant_cuit_prefix, declarant_cuit_suffix4) WHERE has_large_total = 1;

CREATE INDEX IF NOT EXISTS idx_citi_exposure
    ON host_afip_citi(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_citi_drift
    ON host_afip_citi(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_citi_declarant
    ON host_afip_citi(declarant_cuit_prefix, declarant_cuit_suffix4, period_yyyymm);

CREATE INDEX IF NOT EXISTS idx_citi_kind
    ON host_afip_citi(artifact_kind, period_yyyymm);
