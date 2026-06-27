-- 20260623310000_host_kernel_modules.sql: durable storage for per-host
-- kernel module / kernel extension inventory introduced by CDMS iter 20.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_kernel_modules — one row per (asset_id, name). Linux fills it
--                         from /proc/modules + /sys/module/<name>;
--                         macOS from `kextstat`; Windows from SCM
--                         kernel-mode driver enumeration; FreeBSD from
--                         `kldstat`. Drift between scans surfaces via
--                         the file_hash column.
--
-- Audit value (MITRE T1547.006 — Boot or Logon Autostart Execution:
-- Kernel Modules and Extensions / T1014 — Rootkit):
--   - `is_unsigned=1` flags an out-of-tree or developer-signed module
--     in a kernel that enforces module-signing. Catastrophic on
--     production hosts (Secure Boot bypass primitive).
--   - `is_out_of_tree=1` flags modules loaded from outside
--     /lib/modules/$(uname -r)/. Standard tactic for kernel-level
--     persistence — the file lives anywhere the attacker can write.
--   - `taints` non-empty flags modules that marked the kernel tainted
--     (P=proprietary, O=out-of-tree, E=unsigned, F=forced-load).
--   - `refcount=0` AND `is_out_of_tree=1` flags modules loaded but
--     unused — classic stashed rootkit shape.
--   - File `file_hash` drift between scans on a module binary = the
--     code that owns ring-0 changed. Always worth alerting on.

CREATE TABLE IF NOT EXISTS host_kernel_modules (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    name                TEXT NOT NULL,
    source              TEXT NOT NULL
                        CHECK (source IN (
                            'linux-proc-modules', 'linux-sysfs',
                            'macos-kextstat', 'windows-scm',
                            'freebsd-kldstat', 'openbsd-modstat',
                            'unknown'
                        )),
    state               TEXT NOT NULL
                        CHECK (state IN (
                            'live', 'loading', 'unloading', 'unknown'
                        )),
    size_bytes          INTEGER NOT NULL DEFAULT 0,
    refcount            INTEGER NOT NULL DEFAULT 0,
    used_by_json        TEXT NOT NULL DEFAULT '[]',
    load_address        TEXT,                       -- "0xffffffffc0..." (hex), NULL if not exposed
    taints              TEXT,                       -- "POE" — concatenated taint letters
    file_path           TEXT,                       -- absolute path to .ko / .kext / .sys
    file_hash           TEXT,                       -- sha256 of file at file_path
    version             TEXT,                       -- module version from .modinfo / Info.plist
    signer              TEXT,                       -- signing identity (CN= ...)
    is_unsigned         INTEGER NOT NULL DEFAULT 0
                        CHECK (is_unsigned IN (0, 1)),
    is_out_of_tree      INTEGER NOT NULL DEFAULT 0
                        CHECK (is_out_of_tree IN (0, 1)),
    is_tainting         INTEGER NOT NULL DEFAULT 0
                        CHECK (is_tainting IN (0, 1)),
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_kernel_modules_unique
    ON host_kernel_modules(asset_id, name);

CREATE INDEX IF NOT EXISTS idx_host_kernel_modules_unsynced
    ON host_kernel_modules(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me unsigned modules in ring-0".
CREATE INDEX IF NOT EXISTS idx_host_kernel_modules_unsigned
    ON host_kernel_modules(asset_id, name)
    WHERE is_unsigned = 1;

-- Fast path: "show me out-of-tree modules" (rootkit candidate set).
CREATE INDEX IF NOT EXISTS idx_host_kernel_modules_oot
    ON host_kernel_modules(asset_id, name)
    WHERE is_out_of_tree = 1;

-- Fast path: "show me tainting modules".
CREATE INDEX IF NOT EXISTS idx_host_kernel_modules_tainting
    ON host_kernel_modules(asset_id, name)
    WHERE is_tainting = 1;

-- Drift detection on per-module binary.
CREATE INDEX IF NOT EXISTS idx_host_kernel_modules_file_hash
    ON host_kernel_modules(asset_id, name, file_hash);
