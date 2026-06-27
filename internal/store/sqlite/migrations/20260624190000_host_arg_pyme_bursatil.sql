-- host_arg_pyme_bursatil inventories Argentine PyME bursátil
-- financing-instrument files cached on broker, SGR
-- (Sociedad de Garantía Recíproca), and PyME-advisor
-- workstations.
--
-- Argentine PyMEs access capital markets via specific
-- bursátil-tradeable instruments:
--
--   ChPD avalados        — Cheque de Pago Diferido + SGR aval
--   Pagaré Bursátil      — promissory notes (with/without aval)
--   ON PyME              — Obligaciones Negociables PyME (bonds)
--   FCE MiPyME           — Factura de Crédito Electrónica
--                          (tradeable supplier invoice)
--   Letra Tesoro Prov.   — provincial Treasury bills
--
-- **The PyME-issuer side of capital-markets financing.**
-- Complements:
--   iter 107 winargcnvalyc   — ALYC broker-side
--   iter 108 winalgotrading  — algotrading capability
--   iter 109 winargmatbarofex — derivatives positions
--   iter 110 winargfci        — mutual-fund layer
--
-- Regulatory base:
--   Ley 26.831 — Mercado de Capitales
--   CNV RG 731 — régimen PyME bursátil
--   CNV RG 992 — Factura de Crédito Electrónica
--   AFIP RG 4367 — FCE MiPyME
--   Ley 26.860 — Pagaré Bursátil
--   BCRA Com. A 8137 — SGR
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 (librador/receptor CUIT)
--
-- Headline finding shapes:
--   has_sgr_aval         — instrument carries Sociedad de
--                          Garantía Recíproca aval (risk
--                          mitigation indicator).
--   has_default_risk     — vencimiento past + estado activo;
--                          libradr default surface.
--   is_high_value        — monto > 10 M ARS.
--   is_foreign_currency  — moneda != ARS.
--   is_credential_exposure_risk — readable file + librador or
--                          receptor CUIT present.
--
-- All CUITs reduced to entity-type prefix + last 4.

CREATE TABLE IF NOT EXISTS host_arg_pyme_bursatil (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    instrument_kind             TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (instrument_kind IN (
            'chpd-avalado','pagare-bursatil','on-pyme',
            'fce-mipyme','letra-tesoro','negociacion-mensual',
            'other','unknown'
        )),
    sgr_matricula               TEXT    NOT NULL DEFAULT '',
    emisor_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (emisor_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    emisor_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    receptor_cuit_prefix        TEXT    NOT NULL DEFAULT ''
        CHECK (receptor_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    receptor_cuit_suffix4       TEXT    NOT NULL DEFAULT '',
    monto_ars_cents             INTEGER NOT NULL DEFAULT 0,
    moneda                      TEXT    NOT NULL DEFAULT ''
        CHECK (moneda IN ('','ars','usd','eur','brl','other')),
    fecha_emision               TEXT    NOT NULL DEFAULT '',
    fecha_vencimiento           TEXT    NOT NULL DEFAULT '',
    days_to_vencimiento         INTEGER NOT NULL DEFAULT 0,
    has_sgr_aval                INTEGER NOT NULL DEFAULT 0 CHECK (has_sgr_aval IN (0,1)),
    has_default_risk            INTEGER NOT NULL DEFAULT 0 CHECK (has_default_risk IN (0,1)),
    is_high_value               INTEGER NOT NULL DEFAULT 0 CHECK (is_high_value IN (0,1)),
    is_foreign_currency         INTEGER NOT NULL DEFAULT 0 CHECK (is_foreign_currency IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_pyme_default
    ON host_arg_pyme_bursatil(emisor_cuit_prefix, emisor_cuit_suffix4) WHERE has_default_risk = 1;

CREATE INDEX IF NOT EXISTS idx_pyme_sgr
    ON host_arg_pyme_bursatil(sgr_matricula) WHERE has_sgr_aval = 1;

CREATE INDEX IF NOT EXISTS idx_pyme_high_value
    ON host_arg_pyme_bursatil(fecha_emision) WHERE is_high_value = 1;

CREATE INDEX IF NOT EXISTS idx_pyme_exposure
    ON host_arg_pyme_bursatil(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_pyme_drift
    ON host_arg_pyme_bursatil(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_pyme_emisor
    ON host_arg_pyme_bursatil(emisor_cuit_prefix, emisor_cuit_suffix4);

CREATE INDEX IF NOT EXISTS idx_pyme_receptor
    ON host_arg_pyme_bursatil(receptor_cuit_prefix, receptor_cuit_suffix4);
