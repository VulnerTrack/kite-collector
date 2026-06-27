-- 20260502000000_network_scan_safety.sql: durable audit trail for the
-- network scanner safety guards introduced by RFC-0124.
--
-- Three additive tables. No existing rows or columns are touched:
--
--   network_scan_events  — one row per Discover() call, with the safety
--                          outcome and the IP/port enumeration counters.
--                          Already-synced rows are watermarked via
--                          synced_at so the Python ontology bridge can
--                          page through unsynced records cheaply.
--
--   network_open_ports   — one row per (scan_id, ip, port) observation
--                          of a successful TCP connect.
--
--   safety_guard_events  — one row per fired safenet guard (SSRF block,
--                          IP-count cap, port range, concurrency cap,
--                          pagination cap, cursor sanitization). May be
--                          attached to a scan via scan_id or stand alone
--                          (e.g. a guard fired inside a paginated HTTP
--                          connector with no scan context).
--
-- All three tables sit alongside scan_runs(id) for FK validation. Sync
-- watermarks are NULL on insert and stamped to unixepoch() once the
-- DBOS workflow has confirmed the row is in ClickHouse.

CREATE TABLE IF NOT EXISTS network_scan_events (
    scan_id            TEXT PRIMARY KEY NOT NULL,
    agent_id           TEXT NOT NULL,
    scope_hash         TEXT NOT NULL,
    started_at         TEXT NOT NULL,
    completed_at       TEXT,
    ips_enumerated     INTEGER NOT NULL DEFAULT 0,
    ips_scanned        INTEGER NOT NULL DEFAULT 0,
    ips_responsive     INTEGER NOT NULL DEFAULT 0,
    ports_probed_json  TEXT NOT NULL DEFAULT '[]',
    outcome            TEXT NOT NULL CHECK(outcome IN (
                            'completed', 'partial', 'capped_ips',
                            'validation_error', 'timeout', 'cancelled'
                       )),
    safety_guard_count INTEGER NOT NULL DEFAULT 0,
    synced_at          INTEGER,
    created_at         INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_network_scan_events_started
    ON network_scan_events(started_at);
CREATE INDEX IF NOT EXISTS idx_network_scan_events_unsynced
    ON network_scan_events(synced_at)
    WHERE synced_at IS NULL;

CREATE TABLE IF NOT EXISTS network_open_ports (
    id          TEXT PRIMARY KEY NOT NULL,
    scan_id     TEXT NOT NULL REFERENCES network_scan_events(scan_id),
    ip_address  TEXT NOT NULL,
    port        INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    probe_at    TEXT NOT NULL,
    synced_at   INTEGER,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_network_open_ports_scan
    ON network_open_ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_network_open_ports_unsynced
    ON network_open_ports(synced_at)
    WHERE synced_at IS NULL;

CREATE TABLE IF NOT EXISTS safety_guard_events (
    id                TEXT PRIMARY KEY NOT NULL,
    guard_type        TEXT NOT NULL CHECK(guard_type IN (
                          'ssrf_scope_block',
                          'ip_count_cap',
                          'port_range_violation',
                          'concurrency_cap',
                          'pagination_iteration_cap',
                          'pagination_byte_cap',
                          'cursor_sanitization_rejected'
                     )),
    action_taken      TEXT NOT NULL CHECK(action_taken IN (
                          'rejected', 'capped', 'logged'
                     )),
    triggered_at      TEXT NOT NULL,
    input_summary     TEXT NOT NULL DEFAULT '',
    source_component  TEXT NOT NULL,
    details_json      TEXT NOT NULL DEFAULT '{}',
    scan_id           TEXT,
    synced_at         INTEGER,
    created_at        INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_safety_guard_triggered
    ON safety_guard_events(triggered_at);
CREATE INDEX IF NOT EXISTS idx_safety_guard_unsynced
    ON safety_guard_events(synced_at)
    WHERE synced_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_safety_guard_scan
    ON safety_guard_events(scan_id)
    WHERE scan_id IS NOT NULL;
