-- host_arg_fci inventories Argentine FCI (Fondos Comunes de
-- Inversión) mutual-fund files cached on Sociedad Gerente /
-- Sociedad Depositaria / asset-manager workstations.
--
-- CNV (Ley 24.083 + RG 622) regulates FCIs. Every fund's
-- daily lifecycle generates:
--
--   NAV diario             — daily valor cuotaparte
--   Composición de cartera — per-asset weights
--   Cuotapartistas         — investor list with CUIT +
--                            cuotaparte balances
--   Prospecto              — fund offering document
--   Régimen Informativo    — CNV monthly disclosure
--   .cda                   — Caja de Valores account files
--
-- **The mutual-fund regulatory layer.** Complements:
--   iter 90 winargxbrl    — issuer XBRL position
--   iter 107 winargcnvalyc — ALYC broker-dealer disclosures
--   iter 108 winalgotrading — algotrading capability
--   iter 109 winargmatbarofex — derivatives positions
--
-- Regulatory base:
--   Ley 24.083 — Fondos Comunes de Inversión
--   CNV RG 622, RG 731 — texto ordenado de fondos
--   CNV Capítulo II Título V — administración FCI
--   Caja de Valores S.A. Reglamento Operativo
--
-- MITRE / CWE / Ley:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 (cliente cuotapartista CUIT)
--
-- Headline finding shapes:
--   has_high_concentration       — single cuotapartista >
--                                  10 % AUM. KYC/AML concern.
--   has_foreign_dominated_portfolio — > 50 % portfolio in
--                                  USD/EUR. Capital-flight
--                                  signal.
--   has_cuotapartistas_list      — investor list present.
--                                  Materially raises blast
--                                  radius if readable.
--   is_credential_exposure_risk  — readable file + cuotapartistas
--                                  list = direct natural-person
--                                  investor breach (Ley 25.326).

CREATE TABLE IF NOT EXISTS host_arg_fci (
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
            'nav-diario','composicion-cartera','cuotapartistas',
            'prospecto','regimen-informativo','cda-account',
            'other','unknown'
        )),
    fci_matricula               TEXT    NOT NULL DEFAULT '',
    fci_denominacion            TEXT    NOT NULL DEFAULT '',
    sociedad_gerente_cuit_prefix TEXT   NOT NULL DEFAULT ''
        CHECK (sociedad_gerente_cuit_prefix IN ('','30','33','34')),
    sociedad_gerente_cuit_suffix4 TEXT  NOT NULL DEFAULT '',
    sociedad_depositaria_cuit_prefix TEXT NOT NULL DEFAULT ''
        CHECK (sociedad_depositaria_cuit_prefix IN ('','30','33','34')),
    sociedad_depositaria_cuit_suffix4 TEXT NOT NULL DEFAULT '',
    nav_ars_cents               INTEGER NOT NULL DEFAULT 0,
    aum_ars_cents               INTEGER NOT NULL DEFAULT 0,
    cuotapartistas_count        INTEGER NOT NULL DEFAULT 0,
    max_cuotapartista_pct       INTEGER NOT NULL DEFAULT 0
        CHECK (max_cuotapartista_pct BETWEEN 0 AND 100),
    foreign_currency_weight_pct INTEGER NOT NULL DEFAULT 0
        CHECK (foreign_currency_weight_pct BETWEEN 0 AND 100),
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    fecha_nav                   TEXT    NOT NULL DEFAULT '',
    has_high_concentration      INTEGER NOT NULL DEFAULT 0 CHECK (has_high_concentration IN (0,1)),
    has_foreign_dominated_portfolio INTEGER NOT NULL DEFAULT 0 CHECK (has_foreign_dominated_portfolio IN (0,1)),
    has_cuotapartistas_list     INTEGER NOT NULL DEFAULT 0 CHECK (has_cuotapartistas_list IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_fci_concentration
    ON host_arg_fci(fci_matricula) WHERE has_high_concentration = 1;

CREATE INDEX IF NOT EXISTS idx_fci_foreign
    ON host_arg_fci(fci_matricula) WHERE has_foreign_dominated_portfolio = 1;

CREATE INDEX IF NOT EXISTS idx_fci_cuotapartistas
    ON host_arg_fci(file_path) WHERE has_cuotapartistas_list = 1;

CREATE INDEX IF NOT EXISTS idx_fci_exposure
    ON host_arg_fci(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_fci_drift
    ON host_arg_fci(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_fci_matricula
    ON host_arg_fci(fci_matricula);

CREATE INDEX IF NOT EXISTS idx_fci_sgerente
    ON host_arg_fci(sociedad_gerente_cuit_prefix, sociedad_gerente_cuit_suffix4);
