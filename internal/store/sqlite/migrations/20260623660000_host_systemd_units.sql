-- 20260623660000_host_systemd_units.sql: durable storage for per-host
-- systemd unit-hardening inventory introduced by CDMS iter 59.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_systemd_units — one row per .service unit found under any
--                        of the canonical systemd unit-search dirs.
--                        Drop-in fragments (*.service.d/*.conf) are
--                        out of scope; the audit pipeline joins on
--                        unit_name to layer them in later.
--
-- Audit value (MITRE T1543.002 — Systemd Service, T1611 — Escape to
-- Host, T1068 — Exploitation for Privilege Escalation):
--   - CWE-269 (Improper Privilege Management) — `runs_as_root=1`
--     identifies units running with the default identity (no User=
--     directive) or `User=root`. Combined with missing hardening
--     directives = full host compromise on any service-level CVE.
--   - CWE-732 (Incorrect Permission Assignment) — `is_writable_system=1`
--     captures missing `ProtectSystem=` / `=false`; the service can
--     rewrite /usr and /boot, the textbook persistence implant path.
--   - `has_no_seccomp_filter=1` — missing `SystemCallFilter=` lets the
--     service issue arbitrary syscalls; CVE families like CVE-2017-7184
--     turn unfiltered syscalls into root.
--   - `has_unrestricted_capabilities=1` — missing `CapabilityBoundingSet=`
--     leaves CAP_SYS_ADMIN etc available; one buggy ioctl handler ≈ root.
--   - `is_no_new_privileges_off=1` — without `NoNewPrivileges=yes`, a
--     setuid binary invoked from the service regains its privileges.
--   - `is_hardened_baseline=1` rolls up the four core directives the
--     audit pipeline expects on every third-party unit.
--   - Drift events — file_hash change on a unit = the persistence
--     surface was modified; worth alerting alongside the
--     `host_launch_services` table on macOS.

CREATE TABLE IF NOT EXISTS host_systemd_units (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    file_path                       TEXT NOT NULL,
    file_hash                       TEXT NOT NULL,
    unit_name                       TEXT NOT NULL,         -- "foo.service"
    unit_kind                       TEXT NOT NULL
                                    CHECK (unit_kind IN (
                                        'service', 'socket', 'timer',
                                        'mount', 'path', 'target', 'unknown'
                                    )),
    source_dir                      TEXT NOT NULL
                                    CHECK (source_dir IN (
                                        'etc', 'lib', 'usrlib', 'run', 'unknown'
                                    )),
    description                     TEXT,
    service_type                    TEXT,                  -- "simple" / "oneshot" / "forking" / etc
    exec_start                      TEXT,
    user_name                       TEXT,
    group_name                      TEXT,
    working_directory               TEXT,
    capability_bounding_set         TEXT,
    ambient_capabilities            TEXT,
    system_call_filter              TEXT,
    restrict_address_families       TEXT,
    no_new_privileges               TEXT,                  -- raw "yes" / "no" / "" so we can distinguish unset
    private_tmp                     TEXT,
    private_devices                 TEXT,
    private_network                 TEXT,
    protect_system                  TEXT,                  -- "strict" / "full" / "true" / "false" / ""
    protect_home                    TEXT,
    protect_kernel_tunables         TEXT,
    protect_kernel_modules          TEXT,
    protect_control_groups          TEXT,
    restrict_namespaces             TEXT,
    lock_personality                TEXT,
    memory_deny_write_execute       TEXT,
    runs_as_root                    INTEGER NOT NULL DEFAULT 0
                                    CHECK (runs_as_root IN (0, 1)),
    is_no_new_privileges_off        INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_no_new_privileges_off IN (0, 1)),
    is_private_tmp_off              INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_private_tmp_off IN (0, 1)),
    is_writable_system              INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_writable_system IN (0, 1)),
    is_writable_home                INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_writable_home IN (0, 1)),
    has_no_seccomp_filter           INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_no_seccomp_filter IN (0, 1)),
    has_unrestricted_capabilities   INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_unrestricted_capabilities IN (0, 1)),
    has_dangerous_ambient_caps      INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_dangerous_ambient_caps IN (0, 1)),
    is_hardened_baseline            INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_hardened_baseline IN (0, 1)),
    last_seen_at                    TEXT NOT NULL,
    collected_at                    TEXT NOT NULL,
    synced_at                       INTEGER,
    created_at                      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_systemd_units_unique
    ON host_systemd_units(asset_id, file_path);

CREATE INDEX IF NOT EXISTS idx_host_systemd_units_unsynced
    ON host_systemd_units(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me root-running services with no hardening at all"
-- (the CWE-269 + CWE-732 union — every defense-in-depth check missed).
CREATE INDEX IF NOT EXISTS idx_host_systemd_units_root_unhardened
    ON host_systemd_units(asset_id, unit_name)
    WHERE runs_as_root = 1 AND is_hardened_baseline = 0
      AND unit_kind = 'service';

-- Fast path: "show me services that can write /usr and /boot".
CREATE INDEX IF NOT EXISTS idx_host_systemd_units_writable_system
    ON host_systemd_units(asset_id, unit_name)
    WHERE is_writable_system = 1 AND unit_kind = 'service';

-- Fast path: "show me unfiltered syscalls" (no seccomp).
CREATE INDEX IF NOT EXISTS idx_host_systemd_units_no_seccomp
    ON host_systemd_units(asset_id, unit_name)
    WHERE has_no_seccomp_filter = 1 AND unit_kind = 'service';

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_systemd_units_file_hash
    ON host_systemd_units(asset_id, file_path, file_hash);
