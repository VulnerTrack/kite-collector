-- 20260712000000_connector_hardening_entra_dns.sql (RFC-0137)
--
-- Extends RFC-0135's connector_security_profiles cache with the
-- credential_privilege_tier attribute (Section 4.1.1) and adds the
-- connector_guard_event table backing the ConnectorGuardEvent ontology class
-- for the five sources this RFC hardens (entra + the four Cloud DNS providers).
--
-- Additive-only. The @tolerate header opts the ADD COLUMN into duplicate-column
-- tolerance so this composes safely whether or not a future revision of
-- RFC-0135's own migration also adds the column (Section 10.3, RFC-0060
-- idempotency); every CREATE is IF NOT EXISTS-guarded. No existing table's
-- prior columns are modified.
--
-- @tolerate: duplicate column name

ALTER TABLE connector_security_profiles
    ADD COLUMN credential_privilege_tier TEXT NOT NULL DEFAULT 'unknown';

-- Local connector guard-event log. Each row is one firing of an
-- internal/safenet guard (SSRF scope block, pagination cap, cursor/path
-- sanitization rejection) for a specific connector invocation. Append-only;
-- synced to ontology_entities (ConnectorGuardEvent) on the standard bridge
-- cadence. blocked_value is always truncated/redacted and never a credential.
CREATE TABLE IF NOT EXISTS connector_guard_event (
    id               TEXT PRIMARY KEY NOT NULL,   -- cge:{source_name}:{guard_event_type}:{unix_ms}
    source_name      TEXT NOT NULL,
    guard_event_type TEXT NOT NULL,               -- ssrf_scope_block | ip_count_cap | pagination_iteration_cap | pagination_byte_cap | cursor_sanitization_rejected
    blocked_value    TEXT,                         -- truncated or redacted, never a credential
    action_taken     TEXT NOT NULL,               -- blocked | truncated | rejected | capped
    occurred_at      TEXT NOT NULL,               -- RFC3339, UTC
    severity         TEXT NOT NULL DEFAULT 'medium'
);

CREATE INDEX IF NOT EXISTS idx_cge_source_time
    ON connector_guard_event(source_name, occurred_at);
