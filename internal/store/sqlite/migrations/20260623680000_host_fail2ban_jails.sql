-- 20260623680000_host_fail2ban_jails.sql: durable storage for per-host
-- fail2ban jail inventory introduced by CDMS iter 61.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_fail2ban_jails — one row per [section] discovered across
--                         the canonical fail2ban configuration chain:
--                         /etc/fail2ban/jail.conf (vendor defaults),
--                         /etc/fail2ban/jail.local (admin overrides),
--                         /etc/fail2ban/jail.d/*.conf (drop-ins),
--                         plus Homebrew counterparts. The [DEFAULT]
--                         section gets its own row; per-jail rows
--                         inherit fields from DEFAULT and only
--                         re-export when overridden.
--
-- Audit value (MITRE T1110 — Brute Force, defender side, plus
-- T1562.001 — Disable or Modify Tools):
--   - CWE-307 (Improper Restriction of Excessive Authentication
--     Attempts) — `is_critical_jail_disabled=1` on the sshd / postfix
--     / nginx-auth jails leaves the canonical brute-force surfaces
--     completely unprotected. Common pattern: fail2ban is installed,
--     someone toggled the jail off "just to debug", forgot.
--   - `has_loose_threshold=1` flags effective max-attempts higher
--     than the audit pipeline's policy (default >5 retries inside
--     the findtime window).
--   - `has_short_bantime=1` — bans <10m can be brute-force-evaded
--     by an attacker willing to wait between rounds.
--   - `is_ignoreip_world_exposed=1` — `ignoreip` includes 0.0.0.0/0
--     or any /0 prefix. Anyone on the internet is whitelisted; the
--     jail is purely cosmetic.
--   - Drift events — file_hash change on any jail.* file = the
--     ban surface was modified; alert verbatim.

CREATE TABLE IF NOT EXISTS host_fail2ban_jails (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    file_path                       TEXT NOT NULL,
    file_hash                       TEXT NOT NULL,
    section_name                    TEXT NOT NULL,        -- "DEFAULT", "sshd", "apache-auth"
    section_kind                    TEXT NOT NULL
                                    CHECK (section_kind IN (
                                        'default', 'jail', 'unknown'
                                    )),
    enabled                         TEXT,                 -- raw "true" / "false" / "" so we can distinguish unset
    port                            TEXT,                 -- "ssh" / "22" / "80,443"
    filter_name                     TEXT,
    log_path                        TEXT,
    backend                         TEXT,                 -- "auto" / "systemd" / "polling"
    max_retry                       INTEGER,
    find_time_seconds               INTEGER,
    ban_time_seconds                INTEGER,
    ignore_ip                       TEXT,
    action                          TEXT,
    action_count                    INTEGER NOT NULL DEFAULT 0,
    is_enabled                      INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_enabled IN (0, 1)),
    is_critical_jail                INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_critical_jail IN (0, 1)),
    is_critical_jail_disabled       INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_critical_jail_disabled IN (0, 1)),
    has_loose_threshold             INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_loose_threshold IN (0, 1)),
    has_short_bantime               INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_short_bantime IN (0, 1)),
    is_permanent_ban                INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_permanent_ban IN (0, 1)),
    is_ignoreip_world_exposed       INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_ignoreip_world_exposed IN (0, 1)),
    last_seen_at                    TEXT NOT NULL,
    collected_at                    TEXT NOT NULL,
    synced_at                       INTEGER,
    created_at                      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_fail2ban_jails_unique
    ON host_fail2ban_jails(asset_id, file_path, section_name);

CREATE INDEX IF NOT EXISTS idx_host_fail2ban_jails_unsynced
    ON host_fail2ban_jails(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me critical jails (sshd/postfix/nginx) turned off"
-- (CWE-307 + T1110 + T1562.001 — the headline finding).
CREATE INDEX IF NOT EXISTS idx_host_fail2ban_jails_critical_off
    ON host_fail2ban_jails(asset_id, file_path, section_name)
    WHERE is_critical_jail_disabled = 1;

-- Fast path: "show me ignoreip whitelisting the internet".
CREATE INDEX IF NOT EXISTS idx_host_fail2ban_jails_world_ignored
    ON host_fail2ban_jails(asset_id, file_path, section_name)
    WHERE is_ignoreip_world_exposed = 1;

-- Fast path: loose retry thresholds.
CREATE INDEX IF NOT EXISTS idx_host_fail2ban_jails_loose
    ON host_fail2ban_jails(asset_id, file_path, section_name)
    WHERE has_loose_threshold = 1 AND is_enabled = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_fail2ban_jails_file_hash
    ON host_fail2ban_jails(asset_id, file_path, file_hash);
