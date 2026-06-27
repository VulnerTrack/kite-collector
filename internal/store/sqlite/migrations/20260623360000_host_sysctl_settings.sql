-- 20260623360000_host_sysctl_settings.sql: durable storage for per-host
-- Linux sysctl inventory introduced by CDMS iter 25.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_sysctl_settings — one row per (asset_id, source, key). The
--                          collector reads every sysctl config file
--                          (/etc/sysctl.conf, /etc/sysctl.d/*,
--                          /usr/lib/sysctl.d/*, /run/sysctl.d/*) and
--                          optionally the live /proc/sys/* values so
--                          drift between configured and live can be
--                          surfaced. macOS sysctl(8) and Windows
--                          registry security tunables are future
--                          iterations.
--
-- Audit value:
--   - MITRE T1562 (Impair Defenses) — tampering with kernel.dmesg_restrict
--     or kernel.kptr_restrict hides kernel pointer leaks an attacker
--     needs to plant an exploit; flipping kernel.yama.ptrace_scope opens
--     credential-harvest via ptrace.
--   - CWE-693 (Protection Mechanism Failure) — `is_baseline_violation=1`
--     flags settings that deviate from the CIS / kernel-hardening
--     baseline. Examples: fs.protected_symlinks=0 (CVE-2010-0832 class),
--     net.ipv4.conf.all.accept_redirects=1 (route-poisoning enabler).
--   - CWE-1248 (Semantically Improper Output Validation) — bad
--     kernel.core_pattern values can pipe core dumps to attacker-
--     controlled paths (CVE-2021-3492 / DirtyPipe vector).
--   - Drift events — `is_drift_from_disk=1` flags live /proc/sys values
--     that don't match what /etc/sysctl.d/* says they should be. Either
--     the file changed and sysctl --system wasn't re-run, OR somebody
--     wrote directly to /proc/sys at runtime (transient tamper).

CREATE TABLE IF NOT EXISTS host_sysctl_settings (
    id                      TEXT PRIMARY KEY NOT NULL,
    asset_id                TEXT NOT NULL,
    source                  TEXT NOT NULL
                            CHECK (source IN (
                                'etc-sysctl-conf',
                                'etc-sysctl-d',
                                'usr-lib-sysctl-d',
                                'run-sysctl-d',
                                'proc-sys',
                                'unknown'
                            )),
    key                     TEXT NOT NULL,
    current_value           TEXT NOT NULL,
    expected_value          TEXT,             -- CIS baseline target; NULL when no baseline pin
    is_security_critical    INTEGER NOT NULL DEFAULT 0
                            CHECK (is_security_critical IN (0, 1)),
    is_baseline_violation   INTEGER NOT NULL DEFAULT 0
                            CHECK (is_baseline_violation IN (0, 1)),
    is_drift_from_disk      INTEGER NOT NULL DEFAULT 0
                            CHECK (is_drift_from_disk IN (0, 1)),
    file_path               TEXT,
    file_hash               TEXT,
    line_no                 INTEGER NOT NULL DEFAULT 0,
    raw_line                TEXT,
    last_seen_at            TEXT NOT NULL,
    collected_at            TEXT NOT NULL,
    synced_at               INTEGER,
    created_at              INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_sysctl_settings_unique
    ON host_sysctl_settings(asset_id, source, key);

CREATE INDEX IF NOT EXISTS idx_host_sysctl_settings_unsynced
    ON host_sysctl_settings(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me security-critical settings that violate the baseline".
CREATE INDEX IF NOT EXISTS idx_host_sysctl_settings_violations
    ON host_sysctl_settings(asset_id, key)
    WHERE is_baseline_violation = 1;

-- Fast path: "show me hosts where the live /proc value diverges from disk".
CREATE INDEX IF NOT EXISTS idx_host_sysctl_settings_drift
    ON host_sysctl_settings(asset_id, key)
    WHERE is_drift_from_disk = 1;

-- Drift detection on per-file content.
CREATE INDEX IF NOT EXISTS idx_host_sysctl_settings_file_hash
    ON host_sysctl_settings(asset_id, file_path, file_hash);
