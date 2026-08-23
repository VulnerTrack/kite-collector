-- 20260822050000_machine_memory_samples.sql: durable per-machine RAM time
-- series. One additive table; nothing existing is touched.
--
-- This is the LOCAL, always-on counterpart to the optional OTLP host-metrics
-- stream (RFC-0157). It is populated cross-platform from gopsutil
-- (Linux/macOS/Windows/BSD) at the host-metrics cadence, so a machine's memory
-- history stays queryable in kite.db even with no telemetry backend
-- configured. Being a store table, it also renders in the dashboard's generic
-- /tables view with no extra wiring.
--
-- Retention is by deletion: the sampler prunes rows older than a configurable
-- window (default 90 days) on each cycle, bounding growth. The
-- (machine_id, sampled_at) index serves both the time-series read and the
-- retention prune scan.
CREATE TABLE IF NOT EXISTS machine_memory_samples (
    id            TEXT PRIMARY KEY NOT NULL,
    machine_id    TEXT NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    sampled_at    TEXT NOT NULL,               -- RFC3339 UTC
    total_bytes   INTEGER NOT NULL,
    used_bytes    INTEGER NOT NULL,
    used_percent  REAL NOT NULL,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_machine_memory_samples_machine_time
    ON machine_memory_samples(machine_id, sampled_at);
