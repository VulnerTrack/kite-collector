-- host_arg_soc inventories AR financial-firm cybersecurity SOC
-- artifact files cached on SOC-analyst, IR-responder, threat-
-- hunter, vuln-mgmt, and CISO workstations across AR ALYCs, FCIs,
-- insurance companies, audit firms, law firms — every entity
-- covered by prior winarg* iters.
--
-- Regulated under:
--
--   - CNV RG 1023 (Ciberresiliencia 2019) — requires CSIRT
--     designation, incident-response plan, annual pentest,
--     cybersecurity risk-classification.
--   - BCRA Com. A 8005 (Ciberseguridad Financiera 2024) —
--     SIEM, vuln management, threat intelligence, IR plan.
--   - UIF Res. 21/2018 (cyber-risk PLA/FT addendum).
--
-- Distinct from prior iters because the shape is **defensive-
-- operations back-office** (SOC analyst perspective):
--
--   - vs iter 197 winargmodel       — quant strategy (offensive
--                                     IP).
--   - vs iter 196 winargtax         — tax advisory.
--   - vs iter 191 winargperito      — audit firm (financial).
--   - vs iter 185 winargcohen       — ALYC trading desk.
--
-- A SOC artifact leak is doubly-dangerous because:
--
--   * SIEM queries reveal what activity is monitored (= bypass
--     instructions for an attacker who reads them).
--   * IR post-mortems reveal past incident TTPs (= TTP reuse).
--   * Threat-hunt CSV reveals attacker pivot points.
--   * Vulnerability scan = a map of unpatched systems.
--   * Pentest report = the attack-chain a red team already
--     proved (= no need to rediscover).
--   * IOC blocklist = list of detected indicators (= what
--     attackers should change to bypass).
--   * Detection rule (YARA / Sigma) = signature definition
--     (= obfuscation guidance for malware authors).
--
-- SOC distinctive features:
--
--   - SIEM platforms: Splunk SPL (.spl, .conf), Elastic Stack
--     (.kql), Microsoft Sentinel (.kql, .yaml KQL+ARM), QRadar
--     IBM (.aql), Sumo Logic, Devo.
--   - SOAR runbooks: Palo Alto XSOAR, Splunk SOAR (Phantom),
--     Tines, Torq.
--   - Threat intelligence: MISP STIX 2.1 (.json), OpenCTI,
--     Anomali ThreatStream, Recorded Future.
--   - Vuln scanners: Nessus (.nessus), Qualys (.xml),
--     OpenVAS (.xml/.csv), Tenable IO API JSON.
--   - Detection-as-code: YARA (.yar/.yara), Sigma (.yml),
--     Elastic detection rules (.toml), Splunk SPL.
--   - MITRE ATT&CK mapping: layer JSON (https://attack.mitre.org/
--     resources/navigator), per-incident TTP attribution.
--   - SOC 2 Type II reports: third-party trust reports for
--     cloud vendors (AWS, GCP, Datadog, etc.) — auditor
--     attestation that vendor controls work.
--   - CSIRT designation (CNV RG 1023 art.10) — the org-named
--     incident-response team roster.
--   - Annual pentest report (CNV RG 1023 art.12) — required
--     for all CNV-regulated entities.
--
-- Workstation cache footprint (typical):
--
--   %APPDATA%\SOC\<year>\
--     siem_query_<topic>.spl                            Splunk
--     siem_query_<topic>.kql                            Elastic / Sentinel
--     siem_query_<topic>.eql                            Elastic EQL
--     ir_runbook_<incident_type>.md                     runbook
--     threat_hunt_<query>.csv                           hunt output
--     ir_post_mortem_<incident_id>.pdf                  post-mortem
--     mitre_attack_mapping_<incident>.json              ATT&CK layer
--     threat_intel_<feed>.json                          STIX 2.1
--     vulnerability_scan_<scope>.csv                    Nessus / Qualys
--     pentest_report_<year>.pdf                         annual pentest
--     soc_2_<vendor>.pdf                                SOC 2 report
--     csirt_designation.pdf                             CSIRT roster
--     cnv_rg1023_attestation.xml                        self-attest
--     bcra_a8005_filing.xml                             BCRA cyber
--     ioc_blocklist_<dt>.txt                            IOC list
--     detection_rule_<name>.yar                         YARA rule
--     detection_rule_<name>.sigma                       Sigma rule
--
-- Regulatory base:
--
--   CNV RG 1023      Ciberresiliencia (2019)
--   CNV RG 1023 art.10  CSIRT designation
--   CNV RG 1023 art.12  Annual pentest
--   BCRA Com. A 8005  Ciberseguridad financiera (2024)
--   UIF Res. 21/2018  Cyber-risk PLA/FT addendum
--   Ley 25.326       Datos Personales
--   Ley 26.388       Cybercrime Law
--   Ley 27.401       Corporate Criminal Liability
--
-- MITRE / CWE / Industry Standards:
--
--   T1213    Data from Information Repositories (SOC vault)
--   T1552    Unsecured Credentials
--   T1078    Valid Accounts (SIEM admin creds)
--   T1005    Data from Local System (vuln scan output)
--   T1027    Obfuscated Files (encoded threat-intel)
--   ISO 27001        ISMS
--   NIST CSF 2.0     Cyber framework
--   MITRE ATT&CK     TTP taxonomy
--   STIX 2.1         Threat intel exchange format
--   TLP             Traffic Light Protocol
--   CWE-200, CWE-359, CWE-532, CWE-798
--
-- Headline finding shapes:
--
--   has_password_in_config           — cleartext.
--   has_siem_query                   — SIEM detection query.
--   has_ir_runbook                   — incident-response runbook.
--   has_threat_hunt_result           — hunt CSV.
--   has_ir_post_mortem               — post-incident report.
--   has_mitre_attack_mapping         — ATT&CK layer JSON.
--   has_threat_intel_feed            — STIX / OpenCTI feed.
--   has_vulnerability_scan           — Nessus / Qualys.
--   has_pentest_report               — annual mandatory pentest.
--   has_soc2_report                  — SOC 2 Type II.
--   has_csirt_designation            — CSIRT roster.
--   has_cnv_rg1023_attestation       — self-attestation.
--   has_bcra_a8005_filing            — BCRA cyber filing.
--   has_ioc_blocklist                — IOC list.
--   has_yara_rule                    — YARA detection.
--   has_sigma_rule                   — Sigma detection.
--   has_tlp_amber_or_red             — restricted-traffic-light.
--   has_unpatched_critical_cve       — critical CVE in scan.
--   has_active_incident              — incident not closed.
--   is_credential_exposure_risk      — readable + (password OR
--                                      SIEM query OR runbook OR
--                                      post-mortem OR vuln scan).
--   is_detection_bypass_disclosure_risk — readable + (SIEM query
--                                      OR detection rule OR IOC
--                                      blocklist OR MITRE mapping).
--   is_incident_history_exposure_risk — readable + (post-mortem
--                                      OR active incident OR
--                                      threat-hunt result).
--   is_compliance_attestation_leak   — readable + (CNV RG 1023
--                                      attestation OR BCRA A 8005
--                                      filing OR CSIRT designation).

CREATE TABLE IF NOT EXISTS host_arg_soc (
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
            'soc-siem-query','soc-ir-runbook',
            'soc-threat-hunt-result','soc-ir-post-mortem',
            'soc-mitre-attack-mapping','soc-threat-intel-feed',
            'soc-vulnerability-scan','soc-pentest-report',
            'soc-soc2-report','soc-csirt-designation',
            'soc-cnv-rg1023-attestation','soc-bcra-a8005-filing',
            'soc-ioc-blocklist','soc-yara-rule',
            'soc-sigma-rule',
            'soc-config','soc-credentials',
            'soc-installer','other','unknown'
        )),
    siem_platform               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (siem_platform IN (
            'splunk','elastic','sentinel','qradar',
            'sumo-logic','devo','custom','none','unknown'
        )),
    soc_role                    TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (soc_role IN (
            'soc-analyst-l1','soc-analyst-l2','soc-analyst-l3',
            'incident-responder','threat-hunter',
            'vuln-mgmt-engineer','soc-manager','ciso',
            'csirt-coordinator','red-team',
            'compliance-officer','api','other','unknown'
        )),
    tlp_classification          TEXT    NOT NULL DEFAULT ''
        CHECK (tlp_classification IN (
            '','tlp-clear','tlp-green','tlp-amber',
            'tlp-amber-strict','tlp-red',
            'custom','none','unknown'
        )),
    incident_severity           TEXT    NOT NULL DEFAULT ''
        CHECK (incident_severity IN (
            '','informational','low','medium','high','critical',
            'custom','none','unknown'
        )),
    reporting_period            TEXT    NOT NULL DEFAULT ''
        CHECK (length(reporting_period) <= 6),
    csirt_org_cuit_prefix       TEXT    NOT NULL DEFAULT ''
        CHECK (csirt_org_cuit_prefix IN ('','30','33','34')),
    csirt_org_cuit_suffix4      TEXT    NOT NULL DEFAULT '',
    incident_id                 TEXT    NOT NULL DEFAULT '',
    cve_count                   INTEGER NOT NULL DEFAULT 0,
    critical_cve_count          INTEGER NOT NULL DEFAULT 0,
    detection_rule_count        INTEGER NOT NULL DEFAULT 0,
    ioc_count                   INTEGER NOT NULL DEFAULT 0,
    has_password_in_config      INTEGER NOT NULL DEFAULT 0 CHECK (has_password_in_config IN (0,1)),
    has_siem_query              INTEGER NOT NULL DEFAULT 0 CHECK (has_siem_query IN (0,1)),
    has_ir_runbook              INTEGER NOT NULL DEFAULT 0 CHECK (has_ir_runbook IN (0,1)),
    has_threat_hunt_result      INTEGER NOT NULL DEFAULT 0 CHECK (has_threat_hunt_result IN (0,1)),
    has_ir_post_mortem          INTEGER NOT NULL DEFAULT 0 CHECK (has_ir_post_mortem IN (0,1)),
    has_mitre_attack_mapping    INTEGER NOT NULL DEFAULT 0 CHECK (has_mitre_attack_mapping IN (0,1)),
    has_threat_intel_feed       INTEGER NOT NULL DEFAULT 0 CHECK (has_threat_intel_feed IN (0,1)),
    has_vulnerability_scan      INTEGER NOT NULL DEFAULT 0 CHECK (has_vulnerability_scan IN (0,1)),
    has_pentest_report          INTEGER NOT NULL DEFAULT 0 CHECK (has_pentest_report IN (0,1)),
    has_soc2_report             INTEGER NOT NULL DEFAULT 0 CHECK (has_soc2_report IN (0,1)),
    has_csirt_designation       INTEGER NOT NULL DEFAULT 0 CHECK (has_csirt_designation IN (0,1)),
    has_cnv_rg1023_attestation  INTEGER NOT NULL DEFAULT 0 CHECK (has_cnv_rg1023_attestation IN (0,1)),
    has_bcra_a8005_filing       INTEGER NOT NULL DEFAULT 0 CHECK (has_bcra_a8005_filing IN (0,1)),
    has_ioc_blocklist           INTEGER NOT NULL DEFAULT 0 CHECK (has_ioc_blocklist IN (0,1)),
    has_yara_rule               INTEGER NOT NULL DEFAULT 0 CHECK (has_yara_rule IN (0,1)),
    has_sigma_rule              INTEGER NOT NULL DEFAULT 0 CHECK (has_sigma_rule IN (0,1)),
    has_tlp_amber_or_red        INTEGER NOT NULL DEFAULT 0 CHECK (has_tlp_amber_or_red IN (0,1)),
    has_unpatched_critical_cve  INTEGER NOT NULL DEFAULT 0 CHECK (has_unpatched_critical_cve IN (0,1)),
    has_active_incident         INTEGER NOT NULL DEFAULT 0 CHECK (has_active_incident IN (0,1)),
    has_csirt_org_cuit          INTEGER NOT NULL DEFAULT 0 CHECK (has_csirt_org_cuit IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_detection_bypass_disclosure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_detection_bypass_disclosure_risk IN (0,1)),
    is_incident_history_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_incident_history_exposure_risk IN (0,1)),
    is_compliance_attestation_leak INTEGER NOT NULL DEFAULT 0 CHECK (is_compliance_attestation_leak IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_soc_password
    ON host_arg_soc(file_path) WHERE has_password_in_config = 1;

CREATE INDEX IF NOT EXISTS idx_soc_siem
    ON host_arg_soc(siem_platform, reporting_period) WHERE has_siem_query = 1;

CREATE INDEX IF NOT EXISTS idx_soc_runbook
    ON host_arg_soc(file_path, reporting_period) WHERE has_ir_runbook = 1;

CREATE INDEX IF NOT EXISTS idx_soc_hunt
    ON host_arg_soc(reporting_period, ioc_count) WHERE has_threat_hunt_result = 1;

CREATE INDEX IF NOT EXISTS idx_soc_postmortem
    ON host_arg_soc(incident_id, incident_severity) WHERE has_ir_post_mortem = 1;

CREATE INDEX IF NOT EXISTS idx_soc_mitre
    ON host_arg_soc(incident_id) WHERE has_mitre_attack_mapping = 1;

CREATE INDEX IF NOT EXISTS idx_soc_threat_intel
    ON host_arg_soc(reporting_period, ioc_count) WHERE has_threat_intel_feed = 1;

CREATE INDEX IF NOT EXISTS idx_soc_vuln
    ON host_arg_soc(reporting_period, critical_cve_count) WHERE has_vulnerability_scan = 1;

CREATE INDEX IF NOT EXISTS idx_soc_pentest
    ON host_arg_soc(reporting_period) WHERE has_pentest_report = 1;

CREATE INDEX IF NOT EXISTS idx_soc_soc2
    ON host_arg_soc(file_path) WHERE has_soc2_report = 1;

CREATE INDEX IF NOT EXISTS idx_soc_csirt
    ON host_arg_soc(csirt_org_cuit_prefix, csirt_org_cuit_suffix4) WHERE has_csirt_designation = 1;

CREATE INDEX IF NOT EXISTS idx_soc_cnv
    ON host_arg_soc(reporting_period) WHERE has_cnv_rg1023_attestation = 1;

CREATE INDEX IF NOT EXISTS idx_soc_bcra
    ON host_arg_soc(reporting_period) WHERE has_bcra_a8005_filing = 1;

CREATE INDEX IF NOT EXISTS idx_soc_ioc
    ON host_arg_soc(reporting_period, ioc_count) WHERE has_ioc_blocklist = 1;

CREATE INDEX IF NOT EXISTS idx_soc_yara
    ON host_arg_soc(file_path) WHERE has_yara_rule = 1;

CREATE INDEX IF NOT EXISTS idx_soc_sigma
    ON host_arg_soc(file_path) WHERE has_sigma_rule = 1;

CREATE INDEX IF NOT EXISTS idx_soc_tlp
    ON host_arg_soc(tlp_classification, reporting_period) WHERE has_tlp_amber_or_red = 1;

CREATE INDEX IF NOT EXISTS idx_soc_critical_cve
    ON host_arg_soc(reporting_period, critical_cve_count) WHERE has_unpatched_critical_cve = 1;

CREATE INDEX IF NOT EXISTS idx_soc_active
    ON host_arg_soc(incident_id, incident_severity) WHERE has_active_incident = 1;

CREATE INDEX IF NOT EXISTS idx_soc_org
    ON host_arg_soc(csirt_org_cuit_prefix, csirt_org_cuit_suffix4) WHERE has_csirt_org_cuit = 1;

CREATE INDEX IF NOT EXISTS idx_soc_exposure
    ON host_arg_soc(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_soc_bypass
    ON host_arg_soc(file_path) WHERE is_detection_bypass_disclosure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_soc_incident
    ON host_arg_soc(file_path) WHERE is_incident_history_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_soc_attestation
    ON host_arg_soc(file_path) WHERE is_compliance_attestation_leak = 1;

CREATE INDEX IF NOT EXISTS idx_soc_drift
    ON host_arg_soc(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_soc_kind
    ON host_arg_soc(artifact_kind, siem_platform);
