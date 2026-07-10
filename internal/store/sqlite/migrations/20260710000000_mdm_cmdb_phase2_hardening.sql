-- 20260710000000_mdm_cmdb_phase2_hardening.sql (RFC-0135 Phase 2)
--
-- Adds the three genuinely-new MDM/CMDB asset columns. The other six columns
-- this RFC wires into the Go layer (mdm_enrollment_id, cmdb_sys_id, site,
-- tenant, asset_tag, operational_status) already exist as of
-- 20260410000000_mdm_cmdb_columns.sql — that migration created them but they
-- were never referenced by assetColumns/scanAsset/UpsertAsset, so this
-- migration only adds what is genuinely new. All columns are nullable and
-- additive; existing queries are unaffected.

ALTER TABLE assets ADD COLUMN ownership_type TEXT;     -- corporate_dedicated | corporate_shared | employee_owned | unknown
ALTER TABLE assets ADD COLUMN enrolled_user_upn TEXT;  -- MDM-reported primary user (UPN/email); nullable, PII (Section 6.3)
ALTER TABLE assets ADD COLUMN compliance_state TEXT;   -- compliant | non_compliant | unknown | not_evaluated

CREATE INDEX IF NOT EXISTS idx_assets_compliance_state ON assets(compliance_state);
CREATE INDEX IF NOT EXISTS idx_assets_ownership_type ON assets(ownership_type);

-- Local connector security-profile cache. Backs the security-profile REST
-- surface without a round trip to ClickHouse and is synced to
-- ontology_entities (ConnectorSecurityProfile) on the standard bridge cadence.
-- The six booleans plus tls_mode are the code-derived hardening posture of each
-- connector; hardening_score is their equally-weighted fraction (0.0-1.0).
CREATE TABLE IF NOT EXISTS connector_security_profiles (
    source_name              TEXT NOT NULL,
    endpoint_validated       INTEGER NOT NULL DEFAULT 0,
    path_segments_sanitized  INTEGER NOT NULL DEFAULT 0,
    pagination_guarded       INTEGER NOT NULL DEFAULT 0,
    tls_mode                 TEXT NOT NULL DEFAULT 'system_ca'
                             CHECK (tls_mode IN ('system_ca', 'custom_ca', 'insecure')),
    credentials_zeroed       INTEGER NOT NULL DEFAULT 0,
    enabled_flag_respected   INTEGER NOT NULL DEFAULT 0,
    circuit_breaker_attached INTEGER NOT NULL DEFAULT 0,
    hardening_score          REAL NOT NULL DEFAULT 0.0,
    assessed_at              TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (source_name, assessed_at)
);

CREATE INDEX IF NOT EXISTS idx_security_profiles_source ON connector_security_profiles(source_name);
