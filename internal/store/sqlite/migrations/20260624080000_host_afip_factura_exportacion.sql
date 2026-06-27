-- host_afip_factura_exportacion inventories Argentine AFIP
-- factura electrónica de exportación (Factura E) XML files
-- cached on workstations that issue Comprobantes para
-- operaciones de exportación. Distinct from the domestic
-- WSFEv1 / CAE collector (iter 89): these files come from
-- WSMTXCA (mercado externo) or WSCT (otros — turismo,
-- bonos fiscales) and carry export-only fields the
-- domestic schema doesn't have:
--
--   - incoterm (FOB / CIF / EXW / FAS / CFR / CPT / CIP /
--     DAP / DPU / DDP)
--   - destino_country (ISO 3-letter)
--   - moneda_extranjera with cotización ARS
--   - idioma (es / en / pt)
--   - cotización al cierre BCRA
--
-- Capital-outflow context: every Factura E represents
-- foreign-currency revenue flowing through the entity.
-- High-value or FATF-grey-country invoices materially shift
-- AML risk posture.
--
-- Regulatory base:
--   AFIP RG 2758 — Factura electrónica exportación
--   AFIP RG 3884 — Operaciones cambiarias
--   AFIP RG 4291 — Comprobantes tipo C / E
--   BCRA Com. A 8137 — Liquidación de divisas
--   GAFI / FATF Recomendación 16 (cross-border wire transfers)
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 — PII (recipient counterparty if natural-person)
--
-- Headline finding shapes:
--   is_export_factura       — file is a Factura E / Factura T
--                             (export class).
--   is_high_value_usd       — imp_total_usd_cents > 100 M
--                             (US$ 1 000 000). Materially
--                             interesting capital flow.
--   is_fatf_grey_country    — destino_country is on the curated
--                             FATF grey-list snapshot. AML
--                             review hook.
--   is_incoterm_cif_cfr     — Argentine exporter handles
--                             international freight — more
--                             capital-flight latitude than
--                             FOB / EXW.
--   is_credential_exposure_risk — readable file + CAE present
--                             + counterparty identifier on disk.

CREATE TABLE IF NOT EXISTS host_afip_factura_exportacion (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    ws_kind                     TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (ws_kind IN ('wsmtxca','wsct','wsbfev1','other','unknown')),
    cuit_emisor_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (cuit_emisor_prefix IN ('','20','23','24','27','30','33','34')),
    cuit_emisor_suffix4         TEXT    NOT NULL DEFAULT '',
    cae_code                    TEXT    NOT NULL DEFAULT '',
    cbte_tipo                   INTEGER NOT NULL DEFAULT 0,
    cbte_fch                    TEXT    NOT NULL DEFAULT '',
    pto_vta                     INTEGER NOT NULL DEFAULT 0,
    cbte_nro                    INTEGER NOT NULL DEFAULT 0,
    incoterm                    TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (incoterm IN (
            'fob','cif','exw','fas','cfr','cpt','cip',
            'dap','dpu','ddp','fca','other','unknown'
        )),
    destino_country             TEXT    NOT NULL DEFAULT '',
    moneda                      TEXT    NOT NULL DEFAULT '',
    cotizacion_ars              INTEGER NOT NULL DEFAULT 0,
    imp_total_cents             INTEGER NOT NULL DEFAULT 0,
    imp_total_usd_cents         INTEGER NOT NULL DEFAULT 0,
    idioma                      TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    is_export_factura           INTEGER NOT NULL DEFAULT 0 CHECK (is_export_factura IN (0,1)),
    is_high_value_usd           INTEGER NOT NULL DEFAULT 0 CHECK (is_high_value_usd IN (0,1)),
    is_fatf_grey_country        INTEGER NOT NULL DEFAULT 0 CHECK (is_fatf_grey_country IN (0,1)),
    is_incoterm_cif_cfr         INTEGER NOT NULL DEFAULT 0 CHECK (is_incoterm_cif_cfr IN (0,1)),
    is_cae_present              INTEGER NOT NULL DEFAULT 0 CHECK (is_cae_present IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_exp_high_value
    ON host_afip_factura_exportacion(period_yyyymm) WHERE is_high_value_usd = 1;

CREATE INDEX IF NOT EXISTS idx_exp_fatf_grey
    ON host_afip_factura_exportacion(destino_country) WHERE is_fatf_grey_country = 1;

CREATE INDEX IF NOT EXISTS idx_exp_cif_cfr
    ON host_afip_factura_exportacion(period_yyyymm) WHERE is_incoterm_cif_cfr = 1;

CREATE INDEX IF NOT EXISTS idx_exp_exposure
    ON host_afip_factura_exportacion(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_exp_drift
    ON host_afip_factura_exportacion(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_exp_entity
    ON host_afip_factura_exportacion(cuit_emisor_prefix, cuit_emisor_suffix4);

CREATE INDEX IF NOT EXISTS idx_exp_destino
    ON host_afip_factura_exportacion(destino_country, period_yyyymm);
