-- host_arg_ccp inventories Argentine CCP (Central Counter-
-- party / Cámara Compensadora) margin + settlement files
-- cached on clearing-member, ALYC broker, prop-desk, and
-- back-office workstations.
--
-- Argentine clearing houses:
--
--   Argentina Clearing y Compensación (ACyC) — ROFEX CCP for
--                                              futures/options.
--   BYMA CCA (Cámara Compensadora de Activos)  — equity + bond
--                                                clearing.
--   CVSA Garantías                             — collateral
--                                                management.
--   MAEClear                                   — MAE post-trade
--                                                + RV settlement.
--
-- Every derivative algotrader has positions cleared through a
-- CCP. The CCP demands initial margin, issues margin calls
-- when MTM drift breaches thresholds, settles daily T+1, and
-- holds a default fund contribution from each clearing member.
--
-- Workstation cache footprint:
--
--   garantias_iniciales_<dt>.xml      initial margin posted
--   llamada_margen_<dt>.csv           margin call records
--   liquidacion_diaria_<dt>.xml       T+1 daily settlement
--   aforos_<dt>.csv                   collateral haircut table
--   saldo_compensador_<dt>.xml        clearing member balance
--   fondo_garantia_compensacion_<dt>.xml default fund
--   factor_riesgo_<asset>_<dt>.json   risk-factor table
--   stress_test_<dt>.xml              stress-test result
--
-- **The CCP / clearing-house layer.** Distinct from:
--   - iter 109 winargmatbarofex MATba-Rofex positions files
--   - iter 113 winargfix        FIX wire-protocol session
--   - iter 117 winargcvsa       CVSA custody (cash holdings,
--                                not the margin sub-system)
--   - iter 137 winargbyma       BYMA equity terminal
--   - iter 136 winargsiopel     SIOPEL/MAE OTC terminal
--   - iter 139 winargprimary    Primary REST/WS (order entry)
--
-- CCP-specific risk signals matter for:
--   * Margin call active + collateral shortfall = default
--     risk for the clearing member.
--   * Haircut > 50 % = pre-default CCP risk-tightening
--     signal (CNV Reglamento Operativo Mercados Art. 47).
--   * Stress-test breach = clearing-member's contribution
--     to default fund needs reinforcement.
--   * Negative compensador balance = pending default event.
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 731       Régimen de Agentes (clearing members)
--   CNV RG 622       Operativa de mercado
--   CNV RG 813       Cámaras compensadoras
--   ACyC Reglamento Operativo
--   BYMA Reglamento Operativo
--   CPMI-IOSCO PFMI (Principles for FMIs)
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1592    Gather Victim Org Information
--   T1078    Valid Accounts (compromised clearing member)
--   CWE-200, CWE-359, CWE-532
--   Ley 25.326 (cliente CUIT en cuenta margen)
--
-- Headline finding shapes:
--   has_margin_call_active    — file has active margin call.
--   has_collateral_shortfall  — initial margin < required.
--   has_high_haircut          — single asset haircut > 50 %.
--   has_negative_balance      — clearing member balance < 0.
--   has_stress_test_breach    — stress test failed threshold.
--   has_default_fund_call     — extra contribution called.
--   has_cliente_cuit          — cliente CUIT detected.
--   is_credential_exposure_risk — readable file + cliente
--                                CUIT + (margin OR settlement).
--
-- All CUITs reduced to entity prefix + last 4 digits.

CREATE TABLE IF NOT EXISTS host_arg_ccp (
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
            'ccp-margin-collateral','ccp-margin-call',
            'ccp-daily-settlement','ccp-haircut-table',
            'ccp-clearing-member-balance','ccp-default-fund',
            'ccp-haircut-factor','ccp-stress-test',
            'ccp-installer','other','unknown'
        )),
    ccp_entity                  TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (ccp_entity IN (
            'argentina-clearing','byma-cca','caja-valores-garantias',
            'maeclear','other','unknown'
        )),
    asset_class                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (asset_class IN (
            'futures-financial','futures-agro','equity-rv',
            'bonds-rf','caucion-repo','options',
            'other','unknown'
        )),
    clearing_member_matricula   TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    margin_required_ars_cents   INTEGER NOT NULL DEFAULT 0,
    margin_posted_ars_cents     INTEGER NOT NULL DEFAULT 0,
    margin_call_ars_cents       INTEGER NOT NULL DEFAULT 0,
    max_haircut_pct             INTEGER NOT NULL DEFAULT 0
        CHECK (max_haircut_pct BETWEEN 0 AND 100),
    compensador_balance_cents   INTEGER NOT NULL DEFAULT 0,
    default_fund_contribution_cents INTEGER NOT NULL DEFAULT 0,
    stress_test_var_cents       INTEGER NOT NULL DEFAULT 0,
    settlement_date             TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_margin_call_active      INTEGER NOT NULL DEFAULT 0 CHECK (has_margin_call_active IN (0,1)),
    has_collateral_shortfall    INTEGER NOT NULL DEFAULT 0 CHECK (has_collateral_shortfall IN (0,1)),
    has_high_haircut            INTEGER NOT NULL DEFAULT 0 CHECK (has_high_haircut IN (0,1)),
    has_negative_balance        INTEGER NOT NULL DEFAULT 0 CHECK (has_negative_balance IN (0,1)),
    has_stress_test_breach      INTEGER NOT NULL DEFAULT 0 CHECK (has_stress_test_breach IN (0,1)),
    has_default_fund_call       INTEGER NOT NULL DEFAULT 0 CHECK (has_default_fund_call IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_ccp_margin_call
    ON host_arg_ccp(clearing_member_matricula, period_yyyymm) WHERE has_margin_call_active = 1;

CREATE INDEX IF NOT EXISTS idx_ccp_shortfall
    ON host_arg_ccp(clearing_member_matricula) WHERE has_collateral_shortfall = 1;

CREATE INDEX IF NOT EXISTS idx_ccp_high_haircut
    ON host_arg_ccp(ccp_entity, asset_class) WHERE has_high_haircut = 1;

CREATE INDEX IF NOT EXISTS idx_ccp_negative
    ON host_arg_ccp(clearing_member_matricula) WHERE has_negative_balance = 1;

CREATE INDEX IF NOT EXISTS idx_ccp_stress
    ON host_arg_ccp(clearing_member_matricula, period_yyyymm) WHERE has_stress_test_breach = 1;

CREATE INDEX IF NOT EXISTS idx_ccp_default_fund
    ON host_arg_ccp(clearing_member_matricula) WHERE has_default_fund_call = 1;

CREATE INDEX IF NOT EXISTS idx_ccp_cliente
    ON host_arg_ccp(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_ccp_exposure
    ON host_arg_ccp(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_ccp_drift
    ON host_arg_ccp(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_ccp_entity
    ON host_arg_ccp(ccp_entity, artifact_kind);

CREATE INDEX IF NOT EXISTS idx_ccp_settle_date
    ON host_arg_ccp(settlement_date, ccp_entity);
