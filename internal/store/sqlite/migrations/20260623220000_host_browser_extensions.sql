-- 20260623220000_host_browser_extensions.sql: durable storage for
-- per-host browser extension inventory introduced by CDMS iter 11.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_browser_extensions — one row per (asset_id, browser, profile,
--                             extension_id). Multiple Chrome profiles on
--                             the same host carry their own extension
--                             sets, so the profile path is part of the
--                             natural key.
--
-- Audit value (MITRE ATT&CK T1176 — Browser Extensions):
--   - High-permission extensions (e.g. "<all_urls>" host_permissions)
--     can read/modify every web page including SaaS login flows. The
--     `host_permissions_json` column drives the "what can this extension
--     see?" audit query.
--   - `install_source='sideloaded'` extensions bypass the store-vetting
--     process and are far more likely to be malicious — CWE-829
--     (Inclusion of Functionality from Untrusted Control Sphere).
--   - `manifest_version=2` extensions are deprecated as of Chrome 127+;
--     code that hasn't migrated to MV3 is also code that's not been
--     touched and may carry vulns.
--   - `update_url` other than the official store (e.g.
--     'https://clients2.google.com/service/update2/crx') indicates
--     enterprise-managed or sideloaded installs.

CREATE TABLE IF NOT EXISTS host_browser_extensions (
    id                   TEXT PRIMARY KEY NOT NULL,
    asset_id             TEXT NOT NULL,
    browser              TEXT NOT NULL
                         CHECK (browser IN (
                             'chrome', 'chromium', 'edge', 'brave',
                             'opera', 'vivaldi', 'arc',
                             'firefox', 'firefox-esr', 'librewolf',
                             'safari', 'unknown'
                         )),
    profile              TEXT NOT NULL,         -- profile name or directory basename
    extension_id         TEXT NOT NULL,         -- 32-char Chrome ID, UUID for Firefox, etc.
    name                 TEXT,
    version              TEXT,
    description          TEXT,
    enabled              INTEGER NOT NULL DEFAULT 1
                         CHECK (enabled IN (0, 1)),
    manifest_version     INTEGER NOT NULL DEFAULT 0
                         CHECK (manifest_version IN (0, 1, 2, 3)),
    install_source       TEXT NOT NULL DEFAULT 'unknown'
                         CHECK (install_source IN (
                             'store', 'sideloaded', 'enterprise-policy',
                             'developer', 'system', 'unknown'
                         )),
    update_url           TEXT,
    permissions_json     TEXT NOT NULL DEFAULT '[]',  -- JSON array, API permissions
    host_permissions_json TEXT NOT NULL DEFAULT '[]', -- JSON array, URL match patterns
    profile_path         TEXT NOT NULL,         -- absolute path to the profile dir
    manifest_path        TEXT,                  -- absolute path to manifest.json / install.rdf
    last_seen_at         TEXT NOT NULL,
    collected_at         TEXT NOT NULL,
    synced_at            INTEGER,
    created_at           INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_browser_extensions_unique
    ON host_browser_extensions(asset_id, browser, profile, extension_id);

CREATE INDEX IF NOT EXISTS idx_host_browser_extensions_unsynced
    ON host_browser_extensions(synced_at)
    WHERE synced_at IS NULL;

-- For T1176 + CWE-829: "show me sideloaded extensions".
CREATE INDEX IF NOT EXISTS idx_host_browser_extensions_sideloaded
    ON host_browser_extensions(asset_id, browser)
    WHERE install_source = 'sideloaded';

-- For the broad-permission audit: index on (asset_id, browser) so the
-- JSON LIKE scan on host_permissions_json is bounded per host.
CREATE INDEX IF NOT EXISTS idx_host_browser_extensions_by_browser
    ON host_browser_extensions(asset_id, browser);
