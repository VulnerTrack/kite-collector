-- host_arg_cnv_rg1023 inventories CNV RG 1023/2024 cyber-
-- security + technology compliance artifacts cached on
-- Argentine ALYC broker-dealer, FCI administrator, and
-- cybersecurity-officer workstations.
--
-- CNV RG 1023/2024 (Aug 2024) mandates that every sujeto-
-- regulado-CNV (ALYC, FCI administrator, FCI custodian,
-- mercado, cámara compensadora) implement a documented
-- cybersecurity program including:
--
--   * Cybersecurity Responsible Officer designation
--   * Incident response playbook
--   * Cyber-incident registry
--   * Quarterly vulnerability assessment
--   * Annual penetration test
--   * Business Continuity Plan (BCP) + Disaster Recovery (DR)
--   * Encryption policy
--   * Access control matrix
--   * Data classification matrix
--   * Third-party risk assessments
--   * MFA documentation
--   * Cybersecurity awareness training records
--   * Annual external cybersecurity audit
--
-- These artifacts are usually cached on compliance-officer
-- workstations as PDF / DOCX / XLSX / Markdown / JSON.
--
-- **The cybersec-compliance layer.** Distinct from:
--   - iter 107 winargcnvalyc — ALYC business disclosure
--   - iter 138 winarguifros  — UIF / AML compliance
--   - iter 142 winargccp     — CCP margin / settlement
--
-- Risk signals:
--   * Critical-severity finding > 30d open = mandatory
--     remediation under RG 1023 Art. 12.
--   * Overdue vulnerability scan (> 90d since last quarter
--     close) = non-compliance.
--   * Overdue annual pentest = non-compliance.
--   * Overdue annual external audit = non-compliance.
--   * MFA documentation gap = T1078 valid-accounts risk.
--   * Third-party unassessed = supply-chain risk.
--   * Cliente PII inside compliance doc = Ley 25.326
--     exposure.
--
-- Regulatory base:
--   CNV RG 1023/2024  Régimen de ciberseguridad y tecnología
--   CNV RG 731/2018   Régimen de Agentes (predecessor)
--   BCRA Com. A 7724  Ciberseguridad SF (parallel rule)
--   Ley 25.326        Protección datos personales
--   ISO/IEC 27001     Information security management
--   NIST CSF 2.0      Cybersecurity framework
--
-- MITRE / CWE:
--   T1213    Data from Information Repositories
--   T1078    Valid Accounts (MFA gap)
--   T1199    Trusted Relationship (third-party)
--   CWE-200, CWE-359, CWE-922
--   Ley 25.326 (cliente PII in compliance doc)
--
-- Headline finding shapes:
--   has_critical_finding       — file references CRITICAL
--                                severity finding.
--   has_open_high_finding      — HIGH severity finding listed
--                                as open / not remediated.
--   has_overdue_review         — last review date > review
--                                window (90d quarterly, 12mo
--                                annual).
--   has_no_mfa_documented      — file expected to cover MFA
--                                but no MFA entries found.
--   has_unassessed_third_party — third-party risk register
--                                shows an entry without
--                                assessment date.
--   has_cliente_pii            — cliente CUIT detected in
--                                compliance doc (PII bleed).
--   has_incident_without_playbook — incident registered but
--                                no playbook reference.
--   is_credential_exposure_risk — readable file + cliente
--                                CUIT + (cybersec body OR
--                                officer PII).
--
-- Cliente CUITs reduced to entity-prefix + last 4 digits.
-- Officer (oficial de ciberseguridad) CUIT same reduction.

CREATE TABLE IF NOT EXISTS host_arg_cnv_rg1023 (
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
            'cybersec-officer-designation',
            'cybersec-incident-playbook',
            'cybersec-incident-registry',
            'cybersec-vuln-scan-report',
            'cybersec-pentest-report',
            'cybersec-bcp-dr-plan',
            'cybersec-encryption-policy',
            'cybersec-access-matrix',
            'cybersec-data-classification',
            'cybersec-thirdparty-risk',
            'cybersec-mfa-documentation',
            'cybersec-awareness-training',
            'cybersec-audit-report',
            'cybersec-installer',
            'other','unknown'
        )),
    compliance_status           TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (compliance_status IN (
            'compliant','non-compliant','pending-review',
            'in-progress','other','unknown'
        )),
    max_severity                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (max_severity IN (
            'critical','high','medium','low','info',
            'not-applicable','unknown'
        )),
    sujeto_regulado_kind        TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (sujeto_regulado_kind IN (
            'alyc','fci-admin','fci-custodian','mercado',
            'camara-compensadora','other','unknown'
        )),
    cliente_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (cliente_cuit_prefix IN ('','20','23','24','27','30','33','34')),
    cliente_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    officer_cuit_prefix         TEXT    NOT NULL DEFAULT ''
        CHECK (officer_cuit_prefix IN ('','20','23','24','27')),
    officer_cuit_suffix4        TEXT    NOT NULL DEFAULT '',
    finding_count               INTEGER NOT NULL DEFAULT 0,
    critical_count              INTEGER NOT NULL DEFAULT 0,
    high_count                  INTEGER NOT NULL DEFAULT 0,
    medium_count                INTEGER NOT NULL DEFAULT 0,
    open_finding_count          INTEGER NOT NULL DEFAULT 0,
    third_party_count           INTEGER NOT NULL DEFAULT 0,
    third_party_unassessed_count INTEGER NOT NULL DEFAULT 0,
    mfa_entry_count             INTEGER NOT NULL DEFAULT 0,
    last_review_date            TEXT    NOT NULL DEFAULT '',
    next_review_date            TEXT    NOT NULL DEFAULT '',
    period_yyyymm               TEXT    NOT NULL DEFAULT '',
    has_critical_finding        INTEGER NOT NULL DEFAULT 0 CHECK (has_critical_finding IN (0,1)),
    has_open_high_finding       INTEGER NOT NULL DEFAULT 0 CHECK (has_open_high_finding IN (0,1)),
    has_overdue_review          INTEGER NOT NULL DEFAULT 0 CHECK (has_overdue_review IN (0,1)),
    has_no_mfa_documented       INTEGER NOT NULL DEFAULT 0 CHECK (has_no_mfa_documented IN (0,1)),
    has_unassessed_third_party  INTEGER NOT NULL DEFAULT 0 CHECK (has_unassessed_third_party IN (0,1)),
    has_cliente_pii             INTEGER NOT NULL DEFAULT 0 CHECK (has_cliente_pii IN (0,1)),
    has_incident_without_playbook INTEGER NOT NULL DEFAULT 0 CHECK (has_incident_without_playbook IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_rg1023_critical
    ON host_arg_cnv_rg1023(file_path) WHERE has_critical_finding = 1;

CREATE INDEX IF NOT EXISTS idx_rg1023_open_high
    ON host_arg_cnv_rg1023(file_path) WHERE has_open_high_finding = 1;

CREATE INDEX IF NOT EXISTS idx_rg1023_overdue
    ON host_arg_cnv_rg1023(artifact_kind) WHERE has_overdue_review = 1;

CREATE INDEX IF NOT EXISTS idx_rg1023_mfa
    ON host_arg_cnv_rg1023(file_path) WHERE has_no_mfa_documented = 1;

CREATE INDEX IF NOT EXISTS idx_rg1023_thirdparty
    ON host_arg_cnv_rg1023(file_path) WHERE has_unassessed_third_party = 1;

CREATE INDEX IF NOT EXISTS idx_rg1023_pii
    ON host_arg_cnv_rg1023(cliente_cuit_prefix, cliente_cuit_suffix4) WHERE has_cliente_pii = 1;

CREATE INDEX IF NOT EXISTS idx_rg1023_incident
    ON host_arg_cnv_rg1023(file_path) WHERE has_incident_without_playbook = 1;

CREATE INDEX IF NOT EXISTS idx_rg1023_exposure
    ON host_arg_cnv_rg1023(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_rg1023_drift
    ON host_arg_cnv_rg1023(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_rg1023_kind
    ON host_arg_cnv_rg1023(artifact_kind, compliance_status);

CREATE INDEX IF NOT EXISTS idx_rg1023_sujeto
    ON host_arg_cnv_rg1023(sujeto_regulado_kind, artifact_kind);
