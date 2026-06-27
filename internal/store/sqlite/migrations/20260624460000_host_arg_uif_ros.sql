-- host_arg_uif_ros inventories UIF (Unidad de Información
-- Financiera) anti-money-laundering compliance files cached
-- on Argentine bank, ALYC broker-dealer, FCI administrator,
-- and compliance-officer workstations.
--
-- UIF is Argentina's FIU (Financial Intelligence Unit) under
-- Ley 25.246. Every sujeto obligado (ALYC, bank, FCI, AFJP,
-- escribano, exchange, etc.) must file:
--
--   ROS  Reporte de Operación Sospechosa     Resol. UIF 30
--   ROI  Reporte de Operación Inusual        Resol. UIF 230
--   RFT  Reporte de Financiamiento Terrorismo Resol. UIF 70
--   DDJJ Declaración Jurada PEP              Resol. UIF 134
--
-- Workstation cache footprint:
--
--   C:\UIF\Reportes\ros_<id>_<period>.xml      ROS export
--   C:\UIF\Reportes\roi_<id>_<period>.xml      ROI export
--   C:\UIF\PEP\pep_list_<period>.csv           PEP listado
--   C:\UIF\Sanctions\ofac_consol_<date>.csv    OFAC SDN list
--   C:\UIF\Sanctions\un_consol_<date>.xml      UN list
--   C:\UIF\KYC\<cuit>_kyc.xml                  KYC dossier
--   C:\UIF\Alertas\alert_<id>.json             monitoring
--   C:\UIF\Sumarios\sumario_<id>.pdf           case summary
--   %APPDATA%\UIF\Compliance\report_<id>.xml   officer report
--
-- **The AML / compliance layer.** Distinct from:
--   - iter 107 winargcnvalyc       ALYC broker disclosure
--   - iter 113 winargfix           FIX wire-protocol session
--   - iter 117 winargcvsa          CVSA central custody
--   - iter 136 winargsiopel        SIOPEL/MAE OTC terminal
--   - iter 137 winargbyma          BYMA equity terminal
--
-- UIF cache carries the highest PII concentration in the
-- regulatory stack — full KYC dossiers, PEP/sanctions hits,
-- structured-transactions detail, transaction-monitoring IPs.
-- A leak is reportable under Ley 25.326 + AAIP.
--
-- Regulatory base:
--   Ley 25.246           régimen PLA/FT
--   Ley 25.326           protección datos personales
--   Resol. UIF 30        reportes operaciones sospechosas
--   Resol. UIF 70        terrorismo
--   Resol. UIF 134       PEP - personas expuestas
--   Resol. UIF 230       ROIs
--   CNV RG 941           sistema PLAFT mercados
--   BCRA Com. A 7724     ciberseguridad SF
--   FATF Recommendation 10/12/16
--
-- MITRE / CWE:
--   T1213   Data from Information Repositories
--   T1592   Gather Victim Org Information
--   T1078   Valid Accounts (compliance officer)
--   CWE-200, CWE-359, CWE-732, CWE-922
--   Ley 25.326 (cliente PII en KYC)
--
-- Headline finding shapes:
--   has_pep_match              — file references a PEP entry.
--   has_sanctions_match        — file references a sanctions
--                                list entry (OFAC/UN/EU).
--   has_high_risk_jurisdiction — file references a FATF
--                                blacklist / grey-list country.
--   has_structuring_pattern    — file contains smurfing /
--                                fractionamiento markers.
--   has_unusual_volume         — file references operations
--                                above ROI threshold.
--   has_cliente_cuit           — cliente CUIT detected.
--   is_credential_exposure_risk — readable file + cliente
--                                CUIT + (KYC body OR ROS body).
--
-- All CUITs reduced to entity-type prefix + last 4 digits.
-- PEP names truncated to SHA-256 hash of normalized form to
-- protect the politically-exposed-persons listing.

CREATE TABLE IF NOT EXISTS host_arg_uif_ros (
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
            'uif-ros-export','uif-roi-export','uif-rft-export',
            'uif-pep-list','uif-sanctions-list',
            'uif-kyc-dossier','uif-monitoring-alert',
            'uif-sumario','uif-compliance-report',
            'uif-ddjj-pep','uif-installer',
            'other','unknown'
        )),
    sujeto_obligado_kind        TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (sujeto_obligado_kind IN (
            'bank','alyc','fci','afjp','exchange','escribano',
            'casa-cambio','seguros','other','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    cumpliento_officer_cuit_pfx TEXT    NOT NULL DEFAULT ''
        CHECK (cumpliento_officer_cuit_pfx IN ('','20','23','24','27')),
    cumpliento_officer_cuit_sf4 TEXT    NOT NULL DEFAULT '',
    pep_name_hash               TEXT    NOT NULL DEFAULT '',
    sanctions_list_source       TEXT    NOT NULL DEFAULT ''
        CHECK (sanctions_list_source IN ('','ofac','un','eu','uk-hmt','arg-uif','other')),
    high_risk_jurisdiction      TEXT    NOT NULL DEFAULT '',
    alert_count                 INTEGER NOT NULL DEFAULT 0,
    transaction_count           INTEGER NOT NULL DEFAULT 0,
    max_amount_ars_cents        INTEGER NOT NULL DEFAULT 0,
    total_amount_ars_cents      INTEGER NOT NULL DEFAULT 0,
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    report_status               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (report_status IN ('','draft','filed','rejected','accepted','unknown')),
    has_pep_match               INTEGER NOT NULL DEFAULT 0 CHECK (has_pep_match IN (0,1)),
    has_sanctions_match         INTEGER NOT NULL DEFAULT 0 CHECK (has_sanctions_match IN (0,1)),
    has_high_risk_jurisdiction  INTEGER NOT NULL DEFAULT 0 CHECK (has_high_risk_jurisdiction IN (0,1)),
    has_structuring_pattern     INTEGER NOT NULL DEFAULT 0 CHECK (has_structuring_pattern IN (0,1)),
    has_unusual_volume          INTEGER NOT NULL DEFAULT 0 CHECK (has_unusual_volume IN (0,1)),
    has_cliente_cuit            INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_cuit IN (0,1)),
    has_kyc_body                INTEGER NOT NULL DEFAULT 0 CHECK (has_kyc_body IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_uif_pep
    ON host_arg_uif_ros(period_yyyymm) WHERE has_pep_match = 1;

CREATE INDEX IF NOT EXISTS idx_uif_sanctions
    ON host_arg_uif_ros(sanctions_list_source) WHERE has_sanctions_match = 1;

CREATE INDEX IF NOT EXISTS idx_uif_high_risk
    ON host_arg_uif_ros(high_risk_jurisdiction) WHERE has_high_risk_jurisdiction = 1;

CREATE INDEX IF NOT EXISTS idx_uif_structuring
    ON host_arg_uif_ros(period_yyyymm) WHERE has_structuring_pattern = 1;

CREATE INDEX IF NOT EXISTS idx_uif_unusual
    ON host_arg_uif_ros(period_yyyymm) WHERE has_unusual_volume = 1;

CREATE INDEX IF NOT EXISTS idx_uif_cliente
    ON host_arg_uif_ros(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_uif_exposure
    ON host_arg_uif_ros(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_uif_drift
    ON host_arg_uif_ros(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_uif_kind
    ON host_arg_uif_ros(artifact_kind, sujeto_obligado_kind);

CREATE INDEX IF NOT EXISTS idx_uif_status
    ON host_arg_uif_ros(report_status, period_yyyymm);
