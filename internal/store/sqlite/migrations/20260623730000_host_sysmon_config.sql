-- 20260623730000_host_sysmon_config.sql: durable storage for per-host
-- Sysmon configuration singleton introduced by CDMS iter 66.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_sysmon_config — singleton per asset capturing the
--                        on-disk Sysmon configuration XML.
--                        We parse the file at one of the
--                        canonical paths (ProgramData, C:\Sysmon,
--                        Program Files) — whichever is readable
--                        first. The audit pipeline pairs this row
--                        with the service inventory: if Sysmon is
--                        installed and running but `source=no-config`,
--                        that's its own finding (running with built-in
--                        defaults = zero coverage).
--
-- Audit value (MITRE T1562.001 — Disable or Modify Tools,
-- T1564.005 — Hidden File System/Process, defender side):
--   - `has_no_process_create_rules=1` — the ProcessCreate
--     RuleGroup is missing, so EventID 1 (the most useful
--     telemetry) is never recorded. Common after a botched
--     "let me trim the config" pass.
--   - `has_no_network_connect_rules=1` — EventID 3 is off, so
--     outbound C2 callbacks are invisible.
--   - `has_no_dns_query_rules=1` — EventID 22 is off, so DNS
--     beacons are invisible.
--   - `has_suspicious_exclusion=1` — at least one exclusion
--     entry matches a world-writable path (C:\Users\Public\,
--     %TEMP%, C:\Windows\Temp\, etc). Classic T1564.005 attempt
--     to blind the EDR for a specific dropper path.
--   - `is_schema_outdated=1` — schemaversion < 4.50; pre-4.50
--     lacks FileBlockExecutable / ProcessTampering coverage.
--   - Drift events — file_hash change on the config = the EDR
--     coverage surface was modified; alert verbatim.

CREATE TABLE IF NOT EXISTS host_sysmon_config (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    source                          TEXT NOT NULL
                                    CHECK (source IN (
                                        'config-xml', 'no-config',
                                        'no-probe', 'unknown'
                                    )),
    config_path                     TEXT,
    file_hash                       TEXT,
    schema_version                  TEXT,                   -- "4.83"
    hash_algorithms                 TEXT,                   -- "SHA256,IMPHASH"
    dns_lookup_enabled              INTEGER NOT NULL DEFAULT 0
                                    CHECK (dns_lookup_enabled IN (0, 1)),
    check_revocation_enabled        INTEGER NOT NULL DEFAULT 0
                                    CHECK (check_revocation_enabled IN (0, 1)),
    archive_directory               TEXT,
    rule_groups_json                TEXT NOT NULL DEFAULT '[]',  -- ["ProcessCreate","NetworkConnect","DnsQuery",...]
    exclusion_image_paths_json      TEXT NOT NULL DEFAULT '[]',
    suspicious_exclusion_paths_json TEXT NOT NULL DEFAULT '[]',
    rule_group_count                INTEGER NOT NULL DEFAULT 0,
    exclusion_count                 INTEGER NOT NULL DEFAULT 0,
    is_schema_outdated              INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_schema_outdated IN (0, 1)),
    has_strong_hash_algorithms      INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_strong_hash_algorithms IN (0, 1)),
    has_no_process_create_rules     INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_no_process_create_rules IN (0, 1)),
    has_no_network_connect_rules    INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_no_network_connect_rules IN (0, 1)),
    has_no_dns_query_rules          INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_no_dns_query_rules IN (0, 1)),
    has_suspicious_exclusion        INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_suspicious_exclusion IN (0, 1)),
    is_hardened                     INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_hardened IN (0, 1)),
    last_seen_at                    TEXT NOT NULL,
    collected_at                    TEXT NOT NULL,
    synced_at                       INTEGER,
    created_at                      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_sysmon_config_unique
    ON host_sysmon_config(asset_id);

CREATE INDEX IF NOT EXISTS idx_host_sysmon_config_unsynced
    ON host_sysmon_config(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me hosts without process-create coverage".
CREATE INDEX IF NOT EXISTS idx_host_sysmon_config_no_pc
    ON host_sysmon_config(asset_id)
    WHERE has_no_process_create_rules = 1;

-- Fast path: "show me suspicious exclusions" (T1564.005).
CREATE INDEX IF NOT EXISTS idx_host_sysmon_config_susp_excl
    ON host_sysmon_config(asset_id)
    WHERE has_suspicious_exclusion = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_sysmon_config_file_hash
    ON host_sysmon_config(asset_id, file_hash);
