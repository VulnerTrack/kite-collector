-- host_arg_prismaweb inventories BYMA PrismaWeb clearing &
-- settlement portal artifact files cached on Argentine ALYC
-- clearing-member, FCI-manager, and bank back-office
-- workstations.
--
-- PrismaWeb is BYMA's clearing & settlement portal — the
-- equity / option / CEDEAR / FCI cash flow post-trade layer.
-- It is the equity-side complement to MAEclear (which
-- handles OTC bonds).
--
-- PrismaWeb settles:
--
--   - Equity T+1 + T+2 (BYMA-listed shares)
--   - CEDEAR settlement (foreign-stock receipts)
--   - Argentine equity option exercise/assignment
--   - FCI cash flow (suscripción/rescate primary)
--   - Margin calls (alycs vs. clearing house)
--   - Garantías (collateral postings)
--   - Member position reports
--
-- **The equity clearing layer.** Distinct from:
--
--   - iter 157 winargmaeclear      — MAE OTC bond clearing
--   - iter 137 winargcvsa          — CVSA equity custody
--   - iter 109 winargmatbarofex    — MTR-Rofex futures CCP
--   - iter 156 winargbymadata      — BYMA market-data feed
--   - iter 110 winargfci           — FCI Sociedad Gerente
--
-- PrismaWeb member tiers:
--   alyc-clearing       direct clearing member
--   alyc-non-clearing   indirect (clears via correspondent)
--   fci-manager         FCI cash-flow settlement
--   banking-custodian   bank custodian role
--
-- Workstation cache footprint:
--
--   C:\PrismaWeb\config\settings.xml      portal cfg
--   C:\PrismaWeb\daily_settle\<dt>.xml    T+1 settle
--   C:\PrismaWeb\garantias\<dt>.csv       collateral
--   C:\PrismaWeb\margin_calls\<dt>.csv    margin calls
--   C:\PrismaWeb\opciones\ejercicio_<dt>.xml options exer
--   C:\PrismaWeb\fci_cashflow\<dt>.xml    FCI cash flow
--   C:\PrismaWeb\drop_copy\<dt>.fix       FIX drop-copy
--   C:\PrismaWeb\member_position\<dt>.xml positions
--   %APPDATA%\PrismaWeb\session.tok       portal session
--
-- PrismaWeb-specific risk signals:
--   * Margin call event = member liquidity concern
--   * Options exercise assignment = obligation flow
--   * T+1 settlement fail = CNV RG 622 art. 47 violation
--   * Large garantías = clearing-member risk profile
--   * CEDEAR settlement = foreign-stock cross-border flow
--   * FCI cash flow = FCI primary subscription/redemption
--   * Cliente CUIT in any of the above = Ley 25.326 PII
--
-- Regulatory base:
--   Ley 26.831       Mercado de Capitales
--   CNV RG 622 art.47 Liquidación T+1
--   CNV RG 622 art.50 Garantías y margen
--   CNV RG 731       Régimen de Agentes
--   CNV RG 1023      Ciberresiliencia
--   BCRA Com. A 7916 operaciones cambiarias
--   Ley 25.326       Protección de Datos Personales
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts
--   T1071    Application Layer Protocol (FIX drop-copy)
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--   has_password_in_config         — portal cleartext.
--   has_fix_drop_copy              — FIX drop-copy session.
--   has_margin_call_event          — member margin call.
--   has_options_exercise           — equity options exer.
--   has_t1_fail                    — T+1 settle fail.
--   has_high_collateral            — > 100 M ARS garantías.
--   has_cedear_settlement          — CEDEAR settle row.
--   has_fci_cashflow               — FCI primary cashflow.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable + (password OR
--                                    cliente CUIT).

CREATE TABLE IF NOT EXISTS host_arg_prismaweb (
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
            'prismaweb-config','prismaweb-credentials',
            'prismaweb-daily-settlement','prismaweb-collateral',
            'prismaweb-margin-calls','prismaweb-options-exercise',
            'prismaweb-fci-cashflow','prismaweb-fix-drop-copy',
            'prismaweb-member-position','prismaweb-installer',
            'other','unknown'
        )),
    account_class               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (account_class IN (
            'alyc-clearing','alyc-non-clearing',
            'fci-manager','banking-custodian',
            'auditor','demo','other','unknown'
        )),
    member_id                   TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    fix_session_sender          TEXT    NOT NULL DEFAULT '',
    fix_session_target          TEXT    NOT NULL DEFAULT '',
    session_first_seen          TEXT    NOT NULL DEFAULT '',
    session_last_seen           TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    settlement_count            INTEGER NOT NULL DEFAULT 0,
    settlement_fail_count       INTEGER NOT NULL DEFAULT 0,
    margin_call_count           INTEGER NOT NULL DEFAULT 0,
    options_exercise_count      INTEGER NOT NULL DEFAULT 0,
    cedear_settlement_count     INTEGER NOT NULL DEFAULT 0,
    fci_cashflow_count          INTEGER NOT NULL DEFAULT 0,
    collateral_ars_cents        INTEGER NOT NULL DEFAULT 0,
    total_volume_ars_cents      INTEGER NOT NULL DEFAULT 0,
    distinct_counterparty_count INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_fix_drop_copy           INTEGER NOT NULL DEFAULT 0 CHECK (has_fix_drop_copy IN (0,1)),
    has_margin_call_event       INTEGER NOT NULL DEFAULT 0 CHECK (has_margin_call_event IN (0,1)),
    has_options_exercise        INTEGER NOT NULL DEFAULT 0 CHECK (has_options_exercise IN (0,1)),
    has_t1_fail                 INTEGER NOT NULL DEFAULT 0 CHECK (has_t1_fail IN (0,1)),
    has_high_collateral         INTEGER NOT NULL DEFAULT 0 CHECK (has_high_collateral IN (0,1)),
    has_cedear_settlement       INTEGER NOT NULL DEFAULT 0 CHECK (has_cedear_settlement IN (0,1)),
    has_fci_cashflow            INTEGER NOT NULL DEFAULT 0 CHECK (has_fci_cashflow IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_prismaweb_password
    ON host_arg_prismaweb(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_prismaweb_drop_copy
    ON host_arg_prismaweb(fix_session_sender, fix_session_target) WHERE has_fix_drop_copy = 1;

CREATE INDEX IF NOT EXISTS idx_prismaweb_margin
    ON host_arg_prismaweb(member_id, period_yyyymm) WHERE has_margin_call_event = 1;

CREATE INDEX IF NOT EXISTS idx_prismaweb_exercise
    ON host_arg_prismaweb(member_id, period_yyyymm) WHERE has_options_exercise = 1;

CREATE INDEX IF NOT EXISTS idx_prismaweb_t1fail
    ON host_arg_prismaweb(member_id, period_yyyymm) WHERE has_t1_fail = 1;

CREATE INDEX IF NOT EXISTS idx_prismaweb_collateral
    ON host_arg_prismaweb(member_id, collateral_ars_cents) WHERE has_high_collateral = 1;

CREATE INDEX IF NOT EXISTS idx_prismaweb_cedear
    ON host_arg_prismaweb(member_id, period_yyyymm) WHERE has_cedear_settlement = 1;

CREATE INDEX IF NOT EXISTS idx_prismaweb_fci
    ON host_arg_prismaweb(member_id, period_yyyymm) WHERE has_fci_cashflow = 1;

CREATE INDEX IF NOT EXISTS idx_prismaweb_cliente
    ON host_arg_prismaweb(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_prismaweb_exposure
    ON host_arg_prismaweb(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_prismaweb_drift
    ON host_arg_prismaweb(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_prismaweb_kind
    ON host_arg_prismaweb(artifact_kind, account_class);
