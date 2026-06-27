-- 20260623200000_host_scheduled_jobs.sql: durable storage for per-host
-- scheduled-job inventory introduced by CDMS iter 9.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_scheduled_jobs — one row per (asset_id, source, source_path,
--                         name). source_path lets two crontabs with the
--                         same job name (e.g. "backup" in both
--                         /etc/cron.d/backup and ~user/crontab) coexist
--                         without colliding.
--
-- Audit value:
--   - MITRE ATT&CK T1053 (Scheduled Task/Job) — every row IS a potential
--     persistence mechanism; the audit pipeline cross-references each
--     command against known LOLBins (loldrivers / GTFOBins).
--   - CWE-250 (Execution with Unnecessary Privileges) — run_as='root'
--     for a job that doesn't need root.
--   - CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
--     — job command path outside /usr/bin, /usr/local/bin, /sbin
--     (typical attacker drop locations: /tmp, /var/tmp, /dev/shm).
--   - Drift detection — adding a brand-new entry between scans is itself
--     a high-signal event when no change-management workflow ran.

CREATE TABLE IF NOT EXISTS host_scheduled_jobs (
    id            TEXT PRIMARY KEY NOT NULL,
    asset_id      TEXT NOT NULL,
    source        TEXT NOT NULL
                  CHECK (source IN (
                      'cron', 'systemd-timer', 'launchd',
                      'windows-task-scheduler', 'at', 'unknown'
                  )),
    name          TEXT NOT NULL,
    source_path   TEXT NOT NULL,        -- absolute path of the file that declares the job
    schedule      TEXT,                  -- raw schedule string (cron expr / OnCalendar / etc.)
    schedule_kind TEXT NOT NULL DEFAULT 'unknown'
                  CHECK (schedule_kind IN (
                      'cron-5-field', 'cron-7-field',
                      'systemd-oncalendar', 'systemd-monotonic',
                      'time-trigger', 'event-trigger', 'unknown'
                  )),
    command       TEXT,
    run_as        TEXT,
    enabled       INTEGER NOT NULL DEFAULT 1
                  CHECK (enabled IN (0, 1)),
    last_run_at   TEXT,
    next_run_at   TEXT,
    last_exit     INTEGER,
    cmd_hash      TEXT NOT NULL,          -- sha256 of the canonical command string
    last_seen_at  TEXT NOT NULL,
    collected_at  TEXT NOT NULL,
    synced_at     INTEGER,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_scheduled_jobs_unique
    ON host_scheduled_jobs(asset_id, source, source_path, name);

CREATE INDEX IF NOT EXISTS idx_host_scheduled_jobs_unsynced
    ON host_scheduled_jobs(synced_at)
    WHERE synced_at IS NULL;

-- For the CWE-250 finding: "show me root-running jobs".
CREATE INDEX IF NOT EXISTS idx_host_scheduled_jobs_root
    ON host_scheduled_jobs(asset_id, source)
    WHERE run_as IN ('root', '0', 'SYSTEM', 'LocalSystem');

-- For drift detection: "what jobs landed since last scan?"
CREATE INDEX IF NOT EXISTS idx_host_scheduled_jobs_cmd_hash
    ON host_scheduled_jobs(asset_id, cmd_hash);
