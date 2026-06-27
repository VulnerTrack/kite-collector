-- 20260623130000_host_processes.sql: durable storage for OS process
-- inventory introduced by CDMS iter 2.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_processes — one row per (asset_id, pid) observed. PIDs recycle, so
--                    each scan upserts; historical pid timelines live in
--                    ClickHouse via the synced_at watermark. started_at
--                    distinguishes "still the same process" from "fresh
--                    process at the same pid" for the bridge to reason about.
--
-- `status` and `is_kernel_thread` give the audit pipeline cheap signals:
--   - status='zombie' + ppid=1 → an orphaned process whose parent died
--   - is_kernel_thread=1 → skip CVE/CPE matching (no userspace binary)

CREATE TABLE IF NOT EXISTS host_processes (
    id               TEXT PRIMARY KEY NOT NULL,
    asset_id         TEXT NOT NULL,
    pid              INTEGER NOT NULL,
    ppid             INTEGER NOT NULL DEFAULT 0,
    name             TEXT NOT NULL,
    exe              TEXT,
    cmdline          TEXT,
    username         TEXT,
    status           TEXT NOT NULL DEFAULT 'unknown'
                     CHECK (status IN (
                         'running', 'sleeping', 'idle', 'stopped',
                         'zombie', 'wait', 'lock', 'unknown'
                     )),
    is_kernel_thread INTEGER NOT NULL DEFAULT 0
                     CHECK (is_kernel_thread IN (0, 1)),
    rss_bytes        INTEGER,
    vms_bytes        INTEGER,
    num_threads      INTEGER,
    cwd              TEXT,
    started_at       TEXT,
    last_seen_at     TEXT NOT NULL,
    collected_at     TEXT NOT NULL,
    synced_at        INTEGER,
    created_at       INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_processes_unique
    ON host_processes(asset_id, pid);

CREATE INDEX IF NOT EXISTS idx_host_processes_unsynced
    ON host_processes(synced_at)
    WHERE synced_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_host_processes_status
    ON host_processes(asset_id, status);

-- For drift detection across scans: "what processes started since last scan".
CREATE INDEX IF NOT EXISTS idx_host_processes_started_at
    ON host_processes(asset_id, started_at);
