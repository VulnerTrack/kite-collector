-- host_afip_cae_receipts inventories Argentine AFIP/ARCA
-- CAE (Comprobante Autorizado Electrónicamente) receipt XMLs
-- cached on billing/accounting workstations. Every WSFEv1
-- response carries one — the 14-digit CAE is the public
-- authorisation code printed on the invoice, but the file
-- ALSO carries the recipient's DocTipo (DNI/CUIT/Pasaporte)
-- + DocNro and the invoice amount, which together are PII
-- under Argentina's Ley 25.326 (Protección de Datos
-- Personales).
--
-- Capital-flight & money-laundering monitoring context:
--   T1078     Valid Accounts — issued invoices are entity
--             evidence
--   T1078.004 Cloud Accounts — multi-CUIT issuance from one
--             workstation
--   CWE-200, CWE-359, CWE-732 (PII exposure on disk)
--   UIF Res. 30-E/2017 — operaciones de alto monto
--   AFIP RG 2904 / RG 4291 — factura electrónica
--   AFIP RG 1575 — régimen especial Factura M
--
-- Headline finding shapes:
--   is_cae_present        — `<CAE>` non-empty (= a real
--                           authorised invoice on disk).
--   is_foreign_currency   — `<MonId>` != "PES". Materially
--                           interesting for capital-flight
--                           detection.
--   is_high_value         — `<ImpTotal>` > 10,000,000 ARS.
--                           Hooks into UIF Res. 30-E reports.
--   is_factura_m          — Factura M (CbteTipo 51/52/53);
--                           AFIP's controlled-taxpayer régime.
--   is_credential_exposure_risk — CAE + readable file = PII
--                           leak surface (recipient DocNro is
--                           a person's tax ID).
--
-- DocNro is NEVER stored verbatim — only `doc_nro_suffix4`
-- (trailing 4 digits) so the audit pipeline can correlate
-- repeat-recipient activity without retaining the PII.

CREATE TABLE IF NOT EXISTS host_afip_cae_receipts (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    cae_code                    TEXT    NOT NULL DEFAULT '',
    cae_vencimiento             TEXT    NOT NULL DEFAULT '',
    cbte_tipo                   INTEGER NOT NULL DEFAULT 0,
    cbte_letter                 TEXT    NOT NULL DEFAULT 'X'
        CHECK (cbte_letter IN ('A','B','C','E','M','X')),
    cbte_fch                    TEXT    NOT NULL DEFAULT '',
    pto_vta                     INTEGER NOT NULL DEFAULT 0,
    cbte_nro                    INTEGER NOT NULL DEFAULT 0,
    doc_tipo                    INTEGER NOT NULL DEFAULT 0,
    doc_tipo_label              TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (doc_tipo_label IN ('cuit','cuil','dni','pasaporte','cdi','le','lc','other','unknown')),
    doc_nro_suffix4             TEXT    NOT NULL DEFAULT '',
    imp_total_cents             INTEGER NOT NULL DEFAULT 0,
    mon_id                      TEXT    NOT NULL DEFAULT '',
    is_cae_present              INTEGER NOT NULL DEFAULT 0 CHECK (is_cae_present IN (0,1)),
    is_foreign_currency         INTEGER NOT NULL DEFAULT 0 CHECK (is_foreign_currency IN (0,1)),
    is_high_value               INTEGER NOT NULL DEFAULT 0 CHECK (is_high_value IN (0,1)),
    is_factura_m                INTEGER NOT NULL DEFAULT 0 CHECK (is_factura_m IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_afip_cae_high_value
    ON host_afip_cae_receipts(cbte_fch) WHERE is_high_value = 1;

CREATE INDEX IF NOT EXISTS idx_afip_cae_foreign
    ON host_afip_cae_receipts(mon_id, cbte_fch) WHERE is_foreign_currency = 1;

CREATE INDEX IF NOT EXISTS idx_afip_cae_factura_m
    ON host_afip_cae_receipts(cbte_fch) WHERE is_factura_m = 1;

CREATE INDEX IF NOT EXISTS idx_afip_cae_exposure
    ON host_afip_cae_receipts(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_afip_cae_drift
    ON host_afip_cae_receipts(file_path, file_hash);
