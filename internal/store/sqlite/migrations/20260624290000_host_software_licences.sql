-- host_software_licences inventories software-licence
-- artifacts cached on workstations across Windows, Linux,
-- and macOS.
--
-- Per ISO/IEC 27001:2022 A.5.32, organisations must maintain
-- a detailed inventory of every software licence installed on
-- enterprise assets. The inventory documents:
--
--   * product title
--   * publisher / manufacturer
--   * initial install date
--   * purpose
--   * vendor URL (when applicable)
--   * whether the software handles DP/DS — datos personales /
--     datos sensibles (Ley 25.326 / GDPR / HIPAA scope)
--
-- This collector enumerates the *licence-artifact files*
-- themselves (.lic, .license, .key, license.json, LICENSE,
-- EULA, registration.dat) and derives the inventory from
-- them — file-based discovery, not registry scraping.
--
-- License keys are NEVER persisted verbatim. Only:
--   * SHA-256 hash of the key (license_key_hash)
--   * SHA-256 hash of the file body (file_hash)
--
-- DP/DS classification is heuristic. A curated catalogue
-- (CRM, ERP, accounting, browsers, email, payroll, EHR,
-- payment processors, etc.) flags products that are known
-- to process personal / financial / medical data.
--
-- Regulatory base:
--   ISO/IEC 27001:2022 A.5.32 — Intellectual property rights
--   ISO/IEC 27001:2022 A.8.1  — User endpoint devices
--   ISO/IEC 19770-1            — Software Asset Management
--   ITIL 4 SAM (Software Asset Management)
--   Ley 11.723 (AR) — Propiedad Intelectual
--   Ley 25.326 (AR) — Protección de Datos Personales
--   GDPR Art. 30   — Records of processing activities
--   HIPAA 164.308   — Administrative safeguards
--   PCI DSS 12.5    — Asset inventory
--
-- MITRE / CWE:
--   T1518.001   Software Discovery: Security Software
--   T1592       Gather Victim Org Information
--   CWE-200, CWE-359, CWE-732
--   CWE-798     Use of Hard-coded Credentials (license keys)
--
-- Headline finding shapes:
--   is_expired                 — license expiry < clock.
--   has_license_key            — file body contains a key.
--   is_oss_license             — recognised OSS licence.
--   is_pii_handling            — product matches PII-handling
--                                catalogue.
--   is_credential_exposure_risk — readable file + license key
--                                + (PII OR financial OR PHI).
--
-- Product title + publisher captured as-is (these are public
-- product names, not PII).

CREATE TABLE IF NOT EXISTS host_software_licences (
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
            'lic-keyfile','license-json','license-xml',
            'license-text','eula-text','registration-dat',
            'plist-license','dpkg-copyright','other','unknown'
        )),
    product_title               TEXT    NOT NULL DEFAULT '',
    publisher                   TEXT    NOT NULL DEFAULT '',
    product_url                 TEXT    NOT NULL DEFAULT '',
    install_date_yyyymmdd       TEXT    NOT NULL DEFAULT '',
    expiry_date_yyyymmdd        TEXT    NOT NULL DEFAULT '',
    license_type                TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (license_type IN (
            'perpetual','subscription','oss-mit','oss-apache',
            'oss-bsd','oss-gpl','oss-lgpl','oss-mpl',
            'oss-other','freeware','trial','evaluation',
            'oem','enterprise','other','unknown'
        )),
    dp_ds_class                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (dp_ds_class IN (
            'handles-pii','handles-financial','handles-phi',
            'handles-pci','system-utility','dev-tool',
            'media-tool','oss-no-pii','other','unknown'
        )),
    license_key_hash            TEXT    NOT NULL DEFAULT '',
    license_purpose             TEXT    NOT NULL DEFAULT '',
    is_expired                  INTEGER NOT NULL DEFAULT 0 CHECK (is_expired IN (0,1)),
    has_license_key             INTEGER NOT NULL DEFAULT 0 CHECK (has_license_key IN (0,1)),
    is_oss_license              INTEGER NOT NULL DEFAULT 0 CHECK (is_oss_license IN (0,1)),
    is_pii_handling             INTEGER NOT NULL DEFAULT 0 CHECK (is_pii_handling IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_lic_expired
    ON host_software_licences(product_title) WHERE is_expired = 1;

CREATE INDEX IF NOT EXISTS idx_lic_keyed
    ON host_software_licences(publisher, product_title) WHERE has_license_key = 1;

CREATE INDEX IF NOT EXISTS idx_lic_oss
    ON host_software_licences(license_type) WHERE is_oss_license = 1;

CREATE INDEX IF NOT EXISTS idx_lic_pii
    ON host_software_licences(publisher, product_title) WHERE is_pii_handling = 1;

CREATE INDEX IF NOT EXISTS idx_lic_exposure
    ON host_software_licences(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_lic_drift
    ON host_software_licences(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_lic_product
    ON host_software_licences(publisher, product_title);

CREATE INDEX IF NOT EXISTS idx_lic_dp_ds
    ON host_software_licences(dp_ds_class, license_type);
