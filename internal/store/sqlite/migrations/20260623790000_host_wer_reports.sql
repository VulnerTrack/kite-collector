-- 20260623790000_host_wer_reports.sql: durable storage for per-host
-- Windows Error Reporting (WER) report inventory introduced by
-- CDMS iter 72.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_wer_reports — one row per WER report directory discovered
--                      under C:\ProgramData\Microsoft\Windows\WER\
--                      ReportArchive\ (uploaded) and \ReportQueue\
--                      (pending). Each directory pairs a `Report.wer`
--                      text descriptor with zero or more `.dmp` /
--                      `.hdmp` minidump files. The audit pipeline
--                      flips a high-priority alert on any `lsass.exe`
--                      dump — that's the canonical T1003.001 LSASS
--                      memory extraction artifact.
--
-- Audit value (MITRE T1003.001 — OS Credential Dumping: LSASS Memory,
-- T1119 — Automated Collection, defender side):
--   - `is_lsass_dump=1` is the headline. Mimikatz-style attackers
--     trigger an lsass crash specifically to harvest the resulting
--     dump. WER catches every one and parks it on disk before
--     uploading.
--   - `is_security_process_dump=1` broadens the same finding to
--     winlogon / wininit / csrss / smss / services — every sensitive
--     SYSTEM process whose memory contains credentials, tickets, or
--     secrets.
--   - `has_minidump=1` + size > threshold flags reports holding a
--     full minidump (cred-rich) rather than a tiny event-only entry.
--   - Drift events — new reports appearing between scans IS the
--     signal; the audit pipeline diffs scan-over-scan to catch
--     newly-dropped dumps.

CREATE TABLE IF NOT EXISTS host_wer_reports (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    report_dir                  TEXT NOT NULL,            -- absolute directory path
    report_descriptor_path      TEXT,                     -- Report.wer absolute path
    report_descriptor_hash      TEXT,                     -- sha256(Report.wer body)
    report_kind                 TEXT NOT NULL
                                CHECK (report_kind IN (
                                    'archive', 'queue', 'unknown'
                                )),
    event_name                  TEXT,                     -- "APPCRASH" / "BEX" / etc
    event_time                  INTEGER,                  -- unix epoch derived from FILETIME
    consent                     TEXT,                     -- "1" (auto) / "0" / etc
    app_name                    TEXT,                     -- "lsass.exe"
    app_path                    TEXT,                     -- "C:\Windows\System32\lsass.exe"
    app_version                 TEXT,
    fault_module_name           TEXT,
    fault_module_version        TEXT,
    minidump_count              INTEGER NOT NULL DEFAULT 0,
    minidump_total_bytes        INTEGER NOT NULL DEFAULT 0,
    has_minidump                INTEGER NOT NULL DEFAULT 0
                                CHECK (has_minidump IN (0, 1)),
    is_lsass_dump               INTEGER NOT NULL DEFAULT 0
                                CHECK (is_lsass_dump IN (0, 1)),
    is_security_process_dump    INTEGER NOT NULL DEFAULT 0
                                CHECK (is_security_process_dump IN (0, 1)),
    is_browser_dump             INTEGER NOT NULL DEFAULT 0
                                CHECK (is_browser_dump IN (0, 1)),
    is_large_minidump           INTEGER NOT NULL DEFAULT 0
                                CHECK (is_large_minidump IN (0, 1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0
                                CHECK (is_credential_exposure_risk IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_wer_reports_unique
    ON host_wer_reports(asset_id, report_dir);

CREATE INDEX IF NOT EXISTS idx_host_wer_reports_unsynced
    ON host_wer_reports(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me LSASS dumps" (T1003.001 — top priority).
CREATE INDEX IF NOT EXISTS idx_host_wer_reports_lsass
    ON host_wer_reports(asset_id, report_dir)
    WHERE is_lsass_dump = 1;

-- Fast path: any credential-exposure-risk dump (broader headline).
CREATE INDEX IF NOT EXISTS idx_host_wer_reports_cred_risk
    ON host_wer_reports(asset_id, app_name, report_dir)
    WHERE is_credential_exposure_risk = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_wer_reports_descriptor_hash
    ON host_wer_reports(asset_id, report_dir, report_descriptor_hash);
