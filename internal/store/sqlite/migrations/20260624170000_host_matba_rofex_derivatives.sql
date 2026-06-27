-- host_matba_rofex_derivatives inventories Argentine
-- MATba-Rofex (Mercado a Término de Buenos Aires - Rosario
-- Futures Exchange) commodity + financial-futures files
-- cached on broker, commodity-trader, and proprietary-desk
-- workstations.
--
-- MATba-Rofex handles:
--
--   Agropecuarios: Trigo (WK), Soja (SJN), Maíz (MZA),
--                  Girasol (GIR)
--   Financieros:   DLR / DOM (peso-dollar futures),
--                  ROS20 (índice acciones),
--                  Oro
--
-- Files cached on workstations:
--
--   MATBA_settlement_YYYYMMDD.csv     daily settlement prices
--   posiciones_<broker>_<period>.xml  open positions per cuenta
--   contratos_<futuro>_<period>.json  contract specs
--   garantia_<cuenta>.xml             margin requirements
--   *.con                             ROFEX contract files
--
-- **The agropecuarios + financial-derivatives layer.** Pairs
-- with iter 107 ALYC + iter 108 algotrading for the complete
-- broker-desk capital-market asset picture.
--
-- Capital-flow / hedge-vs-speculation context:
--   Hedger threshold (heuristic):
--     Trigo  ~50 contracts (2 500 t)
--     Soja   ~40 contracts (2 000 t)
--     Maíz   ~50 contracts (2 500 t)
--   Positions above these typically indicate speculation.
--
-- Regulatory base:
--   Ley 26.831 — Mercado de Capitales
--   CNV RG 622, RG 731 (regimen agentes)
--   BCRA Com. A 7916, 8137 (operaciones cambiarias)
--   MATba-Rofex Reglamento Operativo
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   CWE-200, CWE-359, CWE-732
--   Ley 25.326 (cliente CUIT in cuenta records)
--
-- Headline finding shapes:
--   is_speculative_size      — position contracts above
--                              hedge-typical threshold.
--   has_margin_call          — file contains margin-call /
--                              llamada-de-margen markers.
--   has_concentration        — single contract month
--                              concentrates the position.
--   has_foreign_currency_notional — DLR / DOM futures or
--                              USD-denominated underlying.
--   is_credential_exposure_risk — readable file + cliente
--                              cuenta CUIT present.
--
-- All CUITs reduced to entity-type prefix + last 4 digits.

CREATE TABLE IF NOT EXISTS host_matba_rofex_derivatives (
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
            'settlement-daily','position-report','contract-spec',
            'margin-requirement','trade-confirmation',
            'options-greeks','other','unknown'
        )),
    commodity                   TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (commodity IN (
            'trigo','soja','maiz','girasol','sorgo','cebada',
            'dlr','dom','ros20','oro','other','unknown'
        )),
    contract_month              TEXT    NOT NULL DEFAULT '',
    broker_matricula            TEXT    NOT NULL DEFAULT '',
    broker_cuit_prefix          TEXT    NOT NULL DEFAULT ''
        CHECK (broker_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    broker_cuit_suffix4         TEXT    NOT NULL DEFAULT '',
    account_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (account_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    account_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    open_position_contracts     INTEGER NOT NULL DEFAULT 0,
    notional_usd_cents          INTEGER NOT NULL DEFAULT 0,
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    is_speculative_size         INTEGER NOT NULL DEFAULT 0 CHECK (is_speculative_size IN (0,1)),
    has_margin_call             INTEGER NOT NULL DEFAULT 0 CHECK (has_margin_call IN (0,1)),
    has_concentration           INTEGER NOT NULL DEFAULT 0 CHECK (has_concentration IN (0,1)),
    has_foreign_currency_notional INTEGER NOT NULL DEFAULT 0 CHECK (has_foreign_currency_notional IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_matba_speculative
    ON host_matba_rofex_derivatives(commodity, contract_month) WHERE is_speculative_size = 1;

CREATE INDEX IF NOT EXISTS idx_matba_margin
    ON host_matba_rofex_derivatives(account_cuit_prefix, account_cuit_suffix4) WHERE has_margin_call = 1;

CREATE INDEX IF NOT EXISTS idx_matba_concentration
    ON host_matba_rofex_derivatives(commodity, contract_month) WHERE has_concentration = 1;

CREATE INDEX IF NOT EXISTS idx_matba_foreign
    ON host_matba_rofex_derivatives(commodity) WHERE has_foreign_currency_notional = 1;

CREATE INDEX IF NOT EXISTS idx_matba_exposure
    ON host_matba_rofex_derivatives(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_matba_drift
    ON host_matba_rofex_derivatives(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_matba_account
    ON host_matba_rofex_derivatives(account_cuit_prefix, account_cuit_suffix4);

CREATE INDEX IF NOT EXISTS idx_matba_broker
    ON host_matba_rofex_derivatives(broker_matricula, broker_cuit_prefix, broker_cuit_suffix4);
