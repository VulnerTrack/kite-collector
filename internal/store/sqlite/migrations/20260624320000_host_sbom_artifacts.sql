-- host_sbom_artifacts inventories SBOM (Software Bill of
-- Materials) files cached on workstations across Windows,
-- Linux, and macOS.
--
-- SBOM is the compliance-mandated standard for software-
-- licence + supply-chain inventory:
--
--   US Executive Order 14028 — federal supplier SBOM
--   NIST SP 800-218 SSDF      Secure Software Development
--   EU Cyber Resilience Act    digital-product SBOM
--   ISO/IEC 5962 (SPDX)        SBOM document standard
--   ISO/IEC 19770-2 SWID       Software identification tags
--   CycloneDX                  OWASP SBOM format
--
-- Files cached on workstations:
--
--   <project>.spdx                 SPDX tag-value
--   <project>.spdx.json            SPDX JSON
--   <project>.spdx.yaml            SPDX YAML
--   <project>.cdx.json             CycloneDX JSON
--   <project>.bom.xml              CycloneDX XML
--   <project>.bom.json             CycloneDX JSON alt
--   <project>.cyclonedx.json       CycloneDX JSON alt
--   <product>.swidtag              ISO/IEC 19770-2 SWID
--
-- **The supply-chain / licence-provenance layer.**
-- Distinct from:
--   - iter 121 winsoftwarelicences — per-licence-file
--   - iter 122 winsamexports       — SAM-tool exports
--   - iter 123 winregistryuninstall — host-native inventory
--
-- Per SBOM the audit captures:
--   - format (SPDX 2.2/2.3/3.0, CycloneDX 1.4/1.5/1.6, SWID)
--   - component count (packages declared)
--   - PII-handling component subset (catalogue shared with
--     iter 121/122/123)
--   - OSS-licence distribution
--   - vulnerable-component count (rows referencing CVE-)
--
-- Regulatory base:
--   US EO 14028 (2021) — SBOM mandate for federal suppliers
--   NIST SP 800-218     Secure Software Development
--                       Framework — SBOM as control
--   EU CRA (2024/2847)  Cyber Resilience Act — digital
--                       product SBOM
--   ISO/IEC 5962        SPDX
--   ISO/IEC 19770-2     SWID tags
--   ISO/IEC 27001:2022 A.5.32 IP rights
--
-- MITRE / CWE:
--   T1518   Software Discovery
--   T1195   Supply Chain Compromise (SBOM helps detect)
--   CWE-200, CWE-359, CWE-732
--   CWE-1357 Reliance on Insufficiently Trustworthy
--           Component (SBOM tracks)
--
-- Headline finding shapes:
--   has_pii_components          — > 0 components match PII /
--                                  financial / PHI catalogue.
--   has_vulnerable_components   — > 0 components reference
--                                  CVE-XXXX-YYYYY in body.
--   has_oss_components          — > 0 OSS-licensed components.
--   is_credential_exposure_risk — readable file + components
--                                  + PII / vulnerable.

CREATE TABLE IF NOT EXISTS host_sbom_artifacts (
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
            'spdx-json','spdx-tag-value','spdx-yaml',
            'cyclonedx-json','cyclonedx-xml',
            'swid-tag','other','unknown'
        )),
    sbom_format                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (sbom_format IN (
            'spdx-2.2','spdx-2.3','spdx-3.0',
            'cyclonedx-1.4','cyclonedx-1.5','cyclonedx-1.6',
            'swid-iso-19770-2','other','unknown'
        )),
    document_name               TEXT    NOT NULL DEFAULT '',
    document_namespace          TEXT    NOT NULL DEFAULT '',
    creator_org                 TEXT    NOT NULL DEFAULT '',
    creation_date_yyyymmdd      TEXT    NOT NULL DEFAULT '',
    component_count             INTEGER NOT NULL DEFAULT 0,
    pii_component_count         INTEGER NOT NULL DEFAULT 0,
    vulnerable_component_count  INTEGER NOT NULL DEFAULT 0,
    oss_component_count         INTEGER NOT NULL DEFAULT 0,
    license_distinct_count      INTEGER NOT NULL DEFAULT 0,
    has_pii_components          INTEGER NOT NULL DEFAULT 0 CHECK (has_pii_components IN (0,1)),
    has_vulnerable_components   INTEGER NOT NULL DEFAULT 0 CHECK (has_vulnerable_components IN (0,1)),
    has_oss_components          INTEGER NOT NULL DEFAULT 0 CHECK (has_oss_components IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_sbom_pii
    ON host_sbom_artifacts(document_name) WHERE has_pii_components = 1;

CREATE INDEX IF NOT EXISTS idx_sbom_vuln
    ON host_sbom_artifacts(document_name) WHERE has_vulnerable_components = 1;

CREATE INDEX IF NOT EXISTS idx_sbom_oss
    ON host_sbom_artifacts(document_name) WHERE has_oss_components = 1;

CREATE INDEX IF NOT EXISTS idx_sbom_exposure
    ON host_sbom_artifacts(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_sbom_drift
    ON host_sbom_artifacts(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_sbom_format
    ON host_sbom_artifacts(sbom_format, creation_date_yyyymmdd);

CREATE INDEX IF NOT EXISTS idx_sbom_creator
    ON host_sbom_artifacts(creator_org, creation_date_yyyymmdd);
