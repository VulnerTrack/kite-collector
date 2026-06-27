-- host_arg_mercap inventories Mercap broker back-office
-- files cached on Argentine ALYC broker-dealer, FCI admin,
-- and back-office-officer workstations.
--
-- Mercap (mercap.com.ar) is the dominant ALYC back-office
-- software in Argentina, used by ~60% of CNV-registered
-- broker-dealers. Mercap modules:
--
--   Gestión Clientes  KYC, cuenta-comitente onboarding
--   Liquidación       compra-venta + caución T+1/T+2 settlement
--   Tesorería         cobros / pagos / movimientos AR$/USD
--   Contabilidad      libro diario + balance + CNV reporting
--   Regulatorio       AIF + Régimen Informativo + IUE
--
-- Workstation cache footprint:
--
--   C:\Mercap\Liquidacion\liquidacion_cv_<dt>.csv
--   C:\Mercap\Conciliacion\conciliacion_cvsa_<dt>.xml
--   C:\Mercap\Tesoreria\saldo_diario_<dt>.csv
--   C:\Mercap\Contabilidad\contabilidad_cnv_<dt>.xml
--   C:\Mercap\Regulatorio\regimen_informativo_<dt>.csv
--   C:\Mercap\Tesoreria\cobros_pagos_<dt>.csv
--   C:\Mercap\Liquidacion\comisiones_<dt>.csv
--   C:\Mercap\KYC\cliente_<cuit>.xml
--   C:\Mercap\Certificados\op_<id>.pdf
--   %APPDATA%\Mercap\config.ini
--
-- **The broker back-office layer.** Distinct from:
--   - iter 107 winargcnvalyc      ALYC disclosure
--   - iter 117 winargcvsa         CVSA custody (depository)
--   - iter 142 winargccp          CCP margin / settlement
--   - iter 138 winarguifros       UIF / AML compliance
--   - iter 144 winargcnvrg1023    cybersec compliance
--
-- Mercap-specific risk signals matter for:
--   * Negative cliente balance = cliente owes broker (risk
--     of write-off, FATCA / IRP reporting trigger).
--   * Unreconciled CVSA = settlement mismatch (CNV RG 622
--     Art. 33 must-investigate within 48h).
--   * Overdue settlement (T+>2) = liquidación falla
--     (CCP default fund trigger).
--   * Commission > 5% of trade notional = anomaly (CNV
--     RG 731 monitoring threshold).
--   * KYC review overdue > 12 months = UIF Resol. 30/30-E
--     non-compliance.
--   * Missing régimen informativo file for the period =
--     AIF non-presentation (CNV sanction).
--
-- Regulatory base:
--   Ley 26.831        Mercado de Capitales
--   CNV RG 622        Operativa de mercado
--   CNV RG 731        Régimen de Agentes
--   CNV RG 813        Cámaras compensadoras
--   UIF Resol. 30-E   ROS / KYC
--   AFIP RG 4838      Operaciones internacionales
--   Ley 25.326        Protección datos personales
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1552    Unsecured Credentials (Mercap config)
--   T1078    Valid Accounts (back-office officer)
--   CWE-200, CWE-359, CWE-532
--   CWE-798  (hardcoded credentials in .ini)
--   Ley 25.326 (cliente PII en KYC)
--
-- Headline finding shapes:
--   has_negative_cliente_balance   — saldo cliente < 0.
--   has_unreconciled_cvsa          — CVSA mismatch flagged.
--   has_overdue_settlement         — settlement > T+2.
--   has_commission_anomaly         — commission > 5% trade.
--   has_kyc_overdue                — KYC review > 12 months.
--   has_unreported_cnv             — period without régimen
--                                    informativo file.
--   has_cliente_cuit               — cliente CUIT detected.
--   is_credential_exposure_risk    — readable file + cliente
--                                    CUIT + (balance OR KYC
--                                    body OR commission).
--
-- Cliente CUITs reduced to entity prefix + last 4 digits.
-- Operator-officer CUITs reduced same. cuenta-comitente
-- truncated to last 4 digits.

CREATE TABLE IF NOT EXISTS host_arg_mercap (
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
            'mercap-liquidacion-cv','mercap-conciliacion-cvsa',
            'mercap-saldo-cliente','mercap-contabilidad-cnv',
            'mercap-regimen-informativo','mercap-cobros-pagos',
            'mercap-comisiones','mercap-kyc-cliente',
            'mercap-certificado','mercap-config',
            'mercap-installer','other','unknown'
        )),
    module                      TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (module IN (
            'gestion-clientes','contabilidad','liquidacion',
            'tesoreria','regulatory-cnv','regulatory-uif',
            'regulatory-afip','back-office','other','unknown'
        )),
    broker_matricula            TEXT    NOT NULL DEFAULT '',
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    cuenta_comitente_suffix4    TEXT    NOT NULL DEFAULT '',
    saldo_cliente_ars_cents     INTEGER NOT NULL DEFAULT 0,
    total_settlement_ars_cents  INTEGER NOT NULL DEFAULT 0,
    max_settlement_days         INTEGER NOT NULL DEFAULT 0,
    commission_pct_max          INTEGER NOT NULL DEFAULT 0
        CHECK (commission_pct_max BETWEEN 0 AND 100),
    kyc_last_review_date        TEXT    NOT NULL DEFAULT '',
    reconciliation_diff_cents   INTEGER NOT NULL DEFAULT 0,
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_negative_cliente_balance INTEGER NOT NULL DEFAULT 0 CHECK (has_negative_cliente_balance IN (0,1)),
    has_unreconciled_cvsa       INTEGER NOT NULL DEFAULT 0 CHECK (has_unreconciled_cvsa IN (0,1)),
    has_overdue_settlement      INTEGER NOT NULL DEFAULT 0 CHECK (has_overdue_settlement IN (0,1)),
    has_commission_anomaly      INTEGER NOT NULL DEFAULT 0 CHECK (has_commission_anomaly IN (0,1)),
    has_kyc_overdue             INTEGER NOT NULL DEFAULT 0 CHECK (has_kyc_overdue IN (0,1)),
    has_unreported_cnv          INTEGER NOT NULL DEFAULT 0 CHECK (has_unreported_cnv IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_mercap_negbal
    ON host_arg_mercap(broker_matricula) WHERE has_negative_cliente_balance = 1;

CREATE INDEX IF NOT EXISTS idx_mercap_cvsa
    ON host_arg_mercap(broker_matricula, period_yyyymm) WHERE has_unreconciled_cvsa = 1;

CREATE INDEX IF NOT EXISTS idx_mercap_settle
    ON host_arg_mercap(broker_matricula, period_yyyymm) WHERE has_overdue_settlement = 1;

CREATE INDEX IF NOT EXISTS idx_mercap_comm
    ON host_arg_mercap(broker_matricula) WHERE has_commission_anomaly = 1;

CREATE INDEX IF NOT EXISTS idx_mercap_kyc
    ON host_arg_mercap(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_kyc_overdue = 1;

CREATE INDEX IF NOT EXISTS idx_mercap_cnv_miss
    ON host_arg_mercap(broker_matricula, period_yyyymm) WHERE has_unreported_cnv = 1;

CREATE INDEX IF NOT EXISTS idx_mercap_cliente
    ON host_arg_mercap(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_mercap_exposure
    ON host_arg_mercap(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_mercap_drift
    ON host_arg_mercap(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_mercap_module
    ON host_arg_mercap(module, artifact_kind);

CREATE INDEX IF NOT EXISTS idx_mercap_broker
    ON host_arg_mercap(broker_matricula, module);
