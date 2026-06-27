-- 20260623430000_host_polkit_rules.sql: durable storage for per-host
-- PolicyKit (polkit) inventory introduced by CDMS iter 32.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_polkit_rules — one row per (asset_id, file_path, action_id, line_no).
--                       The collector parses both action-policy XML
--                       files under /usr/share/polkit-1/actions/ and
--                       JS rules under /etc/polkit-1/rules.d/ +
--                       /usr/share/polkit-1/rules.d/. macOS uses
--                       Authorization Services (future iteration);
--                       Windows uses UAC.
--
-- Audit value:
--   - MITRE T1548 (Abuse Elevation Control Mechanism) — polkit is the
--     modern privilege-broker on Linux desktops. A rule that returns
--     `polkit.Result.YES` for systemd-manage-units, mount, or any
--     pkexec action without authentication lets an unprivileged user
--     pivot to root. The 2021 CVE-2021-4034 (`pwnkit`) was an
--     argument-handling bug; rule-level misconfig is the policy-side
--     equivalent.
--   - CWE-269 (Improper Privilege Management) — `is_passwordless=1`
--     flags actions whose `allow_active`/`allow_inactive` slots are
--     set to `yes` rather than `auth_admin*` / `auth_self*`.
--   - CWE-732 (Incorrect Permission Assignment) — `is_critical=1`
--     marks actions in the curated set (systemd manage-units, pkexec,
--     disk mounts, NetworkManager modifications). Passwordless on
--     these is the headline finding.
--   - Drift events — file_hash change on any polkit rule file = the
--     authorisation policy was modified.

CREATE TABLE IF NOT EXISTS host_polkit_rules (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    source              TEXT NOT NULL
                        CHECK (source IN (
                            'action-policy',     -- /usr/share/polkit-1/actions/*.policy XML
                            'local-rules',       -- /etc/polkit-1/rules.d/*
                            'vendor-rules',      -- /usr/share/polkit-1/rules.d/*
                            'authority-store',   -- legacy /etc/polkit-1/localauthority/
                            'unknown'
                        )),
    action_id           TEXT NOT NULL DEFAULT '',
    action_description  TEXT,
    allow_any           TEXT,                       -- yes/no/auth_self/auth_admin/auth_self_keep/auth_admin_keep
    allow_inactive      TEXT,
    allow_active        TEXT,
    rule_snippet        TEXT,                       -- one-line summary for .rules files
    is_critical         INTEGER NOT NULL DEFAULT 0
                        CHECK (is_critical IN (0, 1)),
    is_passwordless     INTEGER NOT NULL DEFAULT 0
                        CHECK (is_passwordless IN (0, 1)),
    grants_yes          INTEGER NOT NULL DEFAULT 0
                        CHECK (grants_yes IN (0, 1)),
    file_path           TEXT,
    file_hash           TEXT,
    line_no             INTEGER NOT NULL DEFAULT 0,
    raw_line            TEXT,
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_polkit_rules_unique
    ON host_polkit_rules(asset_id, file_path, action_id, line_no);

CREATE INDEX IF NOT EXISTS idx_host_polkit_rules_unsynced
    ON host_polkit_rules(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me critical actions granted without auth".
CREATE INDEX IF NOT EXISTS idx_host_polkit_rules_critical_pw
    ON host_polkit_rules(asset_id, action_id)
    WHERE is_critical = 1 AND is_passwordless = 1;

-- Fast path: "show me JS rules that return YES" (any context).
CREATE INDEX IF NOT EXISTS idx_host_polkit_rules_grants_yes
    ON host_polkit_rules(asset_id, action_id)
    WHERE grants_yes = 1;

-- Drift detection on per-file content.
CREATE INDEX IF NOT EXISTS idx_host_polkit_rules_file_hash
    ON host_polkit_rules(asset_id, file_path, file_hash);
