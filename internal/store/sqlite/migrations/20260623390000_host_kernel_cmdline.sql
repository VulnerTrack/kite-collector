-- 20260623390000_host_kernel_cmdline.sql: durable storage for per-host
-- kernel command-line inventory introduced by CDMS iter 28.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_kernel_cmdline — one row per (asset_id, source, key, value).
--                         The collector reads /proc/cmdline (the live
--                         boot args the kernel saw) and the configured
--                         /etc/default/grub GRUB_CMDLINE_LINUX* lines
--                         so drift between configured and live can be
--                         surfaced.
--
-- Audit value:
--   - MITRE T1547 (Boot or Logon Autostart Execution) — `init=/bin/bash`
--     or any other init= override replaces /sbin/init with an attacker-
--     controlled binary on next boot. Always a critical finding.
--   - MITRE T1542 (Pre-OS Boot) — Secure Boot bypass / kernel-signature
--     verification disabled (`module.sig_enforce=0`) prepares the host
--     for an unsigned-module rootkit.
--   - MITRE T1562.001 (Disable or Modify Tools) — `selinux=0`,
--     `apparmor=0`, `audit=0` neuter the relevant defenders at boot
--     regardless of /etc/selinux/config or /etc/audit/audit.rules state.
--   - CWE-693 (Protection Mechanism Failure) — CPU vulnerability
--     mitigations disabled (`mitigations=off`, `nopti`, `nospectre_v2`,
--     `noibrs`, etc.) re-exposes the host to the side-channel exploit
--     family those mitigations fixed.
--   - Drift events — `is_drift_from_disk=1` flags rows where the live
--     /proc/cmdline value differs from what /etc/default/grub configured.
--     Either the bootloader was edited and update-grub wasn't re-run,
--     OR an attacker booted with manually-edited boot args.

CREATE TABLE IF NOT EXISTS host_kernel_cmdline (
    id                      TEXT PRIMARY KEY NOT NULL,
    asset_id                TEXT NOT NULL,
    source                  TEXT NOT NULL
                            CHECK (source IN (
                                'proc-cmdline',
                                'grub-default',
                                'unknown'
                            )),
    key                     TEXT NOT NULL,
    value                   TEXT NOT NULL DEFAULT '',
    has_value               INTEGER NOT NULL DEFAULT 0
                            CHECK (has_value IN (0, 1)),
    is_security_critical    INTEGER NOT NULL DEFAULT 0
                            CHECK (is_security_critical IN (0, 1)),
    is_baseline_violation   INTEGER NOT NULL DEFAULT 0
                            CHECK (is_baseline_violation IN (0, 1)),
    is_drift_from_disk      INTEGER NOT NULL DEFAULT 0
                            CHECK (is_drift_from_disk IN (0, 1)),
    finding_category        TEXT
                            CHECK (finding_category IS NULL OR finding_category IN (
                                'kaslr-disabled',
                                'cpu-mitigation-disabled',
                                'mac-disabled',
                                'audit-disabled',
                                'module-signing-off',
                                'init-override',
                                'lsm-disabled',
                                'unknown'
                            )),
    file_path               TEXT,
    file_hash               TEXT,
    line_no                 INTEGER NOT NULL DEFAULT 0,
    raw_line                TEXT,
    last_seen_at            TEXT NOT NULL,
    collected_at            TEXT NOT NULL,
    synced_at               INTEGER,
    created_at              INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_kernel_cmdline_unique
    ON host_kernel_cmdline(asset_id, source, key, value);

CREATE INDEX IF NOT EXISTS idx_host_kernel_cmdline_unsynced
    ON host_kernel_cmdline(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me boot args that violate the security baseline".
CREATE INDEX IF NOT EXISTS idx_host_kernel_cmdline_violations
    ON host_kernel_cmdline(asset_id, finding_category)
    WHERE is_baseline_violation = 1;

-- Fast path: "show me hosts whose live cmdline differs from configured".
CREATE INDEX IF NOT EXISTS idx_host_kernel_cmdline_drift
    ON host_kernel_cmdline(asset_id, key)
    WHERE is_drift_from_disk = 1;

-- Drift detection on /etc/default/grub.
CREATE INDEX IF NOT EXISTS idx_host_kernel_cmdline_file_hash
    ON host_kernel_cmdline(asset_id, file_path, file_hash);
