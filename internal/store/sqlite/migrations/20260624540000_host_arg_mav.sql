-- host_arg_mav inventories MAV (Mercado Argentino de
-- Valores) terminal + SME-instrument files cached on
-- ALYC broker, SGR (Sociedad de Garantía Recíproca), PyME
-- issuer, fideicomiso administrator, and PyME-advisor
-- workstations.
--
-- MAV is the Argentine SME-focused exchange. It trades:
--
--   ChPD avalados        Cheques de Pago Diferido avalados
--                        por SGR
--   Pagaré bursátil      pagarés SGR-guaranteed
--   ON-PYME              SME corporate bonds
--   FCE MiPyME           Factura de Crédito Electrónica
--   Letras Provinciales  Letras de Tesoros Provinciales
--   ON Sustentables      Sustainable / green bonds
--   Fideicomisos Financieros  Financial trusts
--
-- **The SME-exchange terminal + instrument layer.**
-- Distinct from:
--   - iter 111 winargpymebursatil PyME instrument file form
--   - iter 136 winargsiopel       SIOPEL/MAE OTC terminal
--   - iter 137 winargbyma         BYMA equity terminal
--   - iter 110 winargfci          FCI mutual-fund layer
--
-- MAV is operated by Bolsa de Comercio de Rosario / Cordoba
-- and uses BYMA-style infrastructure but with its own
-- membership matrículas + SGR-aval ecosystem.
--
-- Workstation cache footprint:
--
--   C:\MAV\Terminal\config.ini
--   C:\MAV\ruedas\rueda_<dt>.xml
--   C:\MAV\instruments\catalogo_<dt>.csv
--   C:\MAV\SGR\carta_aval_<id>.pdf
--   C:\MAV\SGR\portfolio_sgr_<id>.csv
--   C:\MAV\PyMEListings\listing_<cuit>.xml
--   C:\MAV\Liquidacion\settlement_<dt>.xml
--   C:\MAV\Fideicomisos\ff_<id>.xml
--
-- MAV-specific risk signals matter for:
--   * SGR aval = SGR guarantees payment if librador defaults
--     (credit-risk transfer to SGR balance sheet).
--   * Default risk = vencido + still activo (librador in
--     pay-overdue, SGR must honor aval).
--   * Provincial Letras default = sub-sovereign credit risk
--     (provincia in default of Letra del Tesoro).
--   * Overdue libramiento for ChPD = ChPD past fecha de
--     libramiento without cobro.
--   * Concentration = single librador or SGR > 50% of
--     portfolio (CNV RG 622 monitoring).
--   * SGR with rating downgrade = systemic-risk signal.
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes
--   CNV RG 622       Operativa de mercado
--   CNV RG 813       MAV (régimen especial PyME)
--   Ley 24.467       SGR
--   Ley 27.444       Modernización Mercado de Capitales
--   MAV Reglamento Operativo
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information
--   CWE-200, CWE-359
--   Ley 25.326 (librador / receptor PII)
--
-- Headline finding shapes:
--   has_sgr_aval               — entry carries SGR aval.
--   has_default_risk           — vencido + activo flagged.
--   has_high_value             — total > 10 M ARS.
--   has_foreign_currency       — moneda != ARS.
--   has_provincial_default_risk — provincia in default mark.
--   has_overdue_libramiento    — ChPD past libramiento.
--   has_concentration          — single issuer/SGR > 50%.
--   has_cliente_cuit           — cliente CUIT detected.
--   is_credential_exposure_risk — readable file + cliente
--                              CUIT + (SGR aval OR PYME body).
--
-- Librador / receptor / cliente CUITs reduced to prefix +
-- last 4 digits.

CREATE TABLE IF NOT EXISTS host_arg_mav (
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
            'mav-terminal-config','mav-rueda-data',
            'mav-instrument-cache','mav-sgr-portfolio',
            'mav-aval-letter','mav-pyme-listing',
            'mav-settlement','mav-fideicomiso',
            'mav-installer','other','unknown'
        )),
    member_kind                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (member_kind IN (
            'alyc-broker','sgr','pyme-issuer',
            'fideicomiso-admin','other','unknown'
        )),
    instrument_class            TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (instrument_class IN (
            'chpd','pagare-bursatil','obligacion-negociable',
            'fce-mipyme','letra-provincial',
            'on-sustentable','fideicomiso',
            'other','unknown'
        )),
    member_matricula            TEXT    NOT NULL DEFAULT '',
    librador_cuit_prefix        TEXT    NOT NULL DEFAULT ''
        CHECK (librador_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    librador_cuit_suffix4       TEXT    NOT NULL DEFAULT '',
    receptor_cuit_prefix        TEXT    NOT NULL DEFAULT ''
        CHECK (receptor_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    receptor_cuit_suffix4       TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    sgr_name                    TEXT    NOT NULL DEFAULT '',
    provincia                   TEXT    NOT NULL DEFAULT '',
    moneda                      TEXT    NOT NULL DEFAULT ''
        CHECK (moneda IN ('','ARS','USD','EUR','UVA','CER','other')),
    monto_ars_cents             INTEGER NOT NULL DEFAULT 0,
    total_portfolio_ars_cents   INTEGER NOT NULL DEFAULT 0,
    max_concentration_pct       INTEGER NOT NULL DEFAULT 0
        CHECK (max_concentration_pct BETWEEN 0 AND 100),
    instrument_count            INTEGER NOT NULL DEFAULT 0,
    fecha_vencimiento           TEXT    NOT NULL DEFAULT '',
    fecha_libramiento           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_sgr_aval                INTEGER NOT NULL DEFAULT 0 CHECK (has_sgr_aval IN (0,1)),
    has_default_risk            INTEGER NOT NULL DEFAULT 0 CHECK (has_default_risk IN (0,1)),
    has_high_value              INTEGER NOT NULL DEFAULT 0 CHECK (has_high_value IN (0,1)),
    has_foreign_currency        INTEGER NOT NULL DEFAULT 0 CHECK (has_foreign_currency IN (0,1)),
    has_provincial_default_risk INTEGER NOT NULL DEFAULT 0 CHECK (has_provincial_default_risk IN (0,1)),
    has_overdue_libramiento     INTEGER NOT NULL DEFAULT 0 CHECK (has_overdue_libramiento IN (0,1)),
    has_concentration           INTEGER NOT NULL DEFAULT 0 CHECK (has_concentration IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_mav_sgr
    ON host_arg_mav(sgr_name) WHERE has_sgr_aval = 1;

CREATE INDEX IF NOT EXISTS idx_mav_default
    ON host_arg_mav(member_matricula, period_yyyymm) WHERE has_default_risk = 1;

CREATE INDEX IF NOT EXISTS idx_mav_high
    ON host_arg_mav(member_matricula) WHERE has_high_value = 1;

CREATE INDEX IF NOT EXISTS idx_mav_fx
    ON host_arg_mav(moneda) WHERE has_foreign_currency = 1;

CREATE INDEX IF NOT EXISTS idx_mav_prov_default
    ON host_arg_mav(provincia) WHERE has_provincial_default_risk = 1;

CREATE INDEX IF NOT EXISTS idx_mav_overdue
    ON host_arg_mav(member_matricula) WHERE has_overdue_libramiento = 1;

CREATE INDEX IF NOT EXISTS idx_mav_concentration
    ON host_arg_mav(member_matricula) WHERE has_concentration = 1;

CREATE INDEX IF NOT EXISTS idx_mav_cliente
    ON host_arg_mav(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_mav_exposure
    ON host_arg_mav(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_mav_drift
    ON host_arg_mav(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_mav_instrument
    ON host_arg_mav(instrument_class, period_yyyymm);

CREATE INDEX IF NOT EXISTS idx_mav_member
    ON host_arg_mav(member_kind, member_matricula);
