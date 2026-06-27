-- 20260623750000_host_browser_policies.sql: durable storage for
-- per-host browser managed-policy inventory introduced by CDMS
-- iter 68.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_browser_policies — one row per (browser, policy_name)
--                            pair discovered in the canonical
--                            enterprise-policy locations:
--                              Chrome  (Windows): C:\Program Files\Google\Chrome\policies\managed\*.json
--                              Chrome  (Linux):   /etc/opt/chrome/policies/managed/*.json
--                              Edge    (Windows): C:\Program Files (x86)\Microsoft\Edge\Application\policies\managed\*.json
--                              Edge    (Linux):   /etc/opt/edge/policies/managed/*.json
--                              Firefox (Windows): C:\Program Files\Mozilla Firefox\distribution\policies.json
--                              Firefox (Linux):   /etc/firefox/policies/policies.json
--                            Browser managed policies are MDM/AD
--                            pushed JSON; the audit pipeline cross-
--                            references against vendor compliance
--                            baselines (CIS, MS Security Baseline).
--
-- Audit value (MITRE T1562.001 — Disable or Modify Tools, defender
-- side, plus T1176 — Browser Extensions for the force-install rows):
--   - CWE-693 (Protection Mechanism Failure) — `is_safe_browsing_off=1`
--     captures `SafeBrowsingProtectionLevel=0` and equivalents;
--     legitimate phishing-protection telemetry is turned off.
--   - CWE-256 (Plaintext Storage of Password) — `is_password_manager_off=1`
--     flags `PasswordManagerEnabled=false`; pushes users to reuse
--     passwords elsewhere or write them down.
--   - `is_download_restrictions_off=1` — `DownloadRestrictions=0`
--     allows binary downloads with no safety scan, T1105 staging.
--   - `is_extension_force_installed=1` — `ExtensionInstallForcelist`
--     entries — every extension shipped this way runs in every
--     tab; one bad entry = browser-wide RCE (T1176 + T1195).
--   - `is_url_blocklist_empty=1` — `URLBlocklist` policy absent
--     OR empty; the audit pipeline expects at least a minimal
--     phishing/malware blocklist in a managed deployment.
--   - Drift events — file_hash change on any policy file = the
--     MDM-enforced posture was modified; alert verbatim.

CREATE TABLE IF NOT EXISTS host_browser_policies (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    browser_kind                    TEXT NOT NULL
                                    CHECK (browser_kind IN (
                                        'chrome', 'edge', 'firefox', 'unknown'
                                    )),
    file_path                       TEXT NOT NULL,
    file_hash                       TEXT NOT NULL,
    policy_name                     TEXT NOT NULL,
    policy_value_kind               TEXT NOT NULL
                                    CHECK (policy_value_kind IN (
                                        'bool', 'number', 'string',
                                        'array', 'object', 'null'
                                    )),
    policy_value                    TEXT NOT NULL,       -- stringified JSON
    is_safe_browsing_off            INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_safe_browsing_off IN (0, 1)),
    is_password_manager_off         INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_password_manager_off IN (0, 1)),
    is_download_restrictions_off    INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_download_restrictions_off IN (0, 1)),
    is_extension_force_installed    INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_extension_force_installed IN (0, 1)),
    is_url_blocklist_empty          INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_url_blocklist_empty IN (0, 1)),
    is_concerning                   INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_concerning IN (0, 1)),
    last_seen_at                    TEXT NOT NULL,
    collected_at                    TEXT NOT NULL,
    synced_at                       INTEGER,
    created_at                      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_browser_policies_unique
    ON host_browser_policies(asset_id, browser_kind, file_path, policy_name);

CREATE INDEX IF NOT EXISTS idx_host_browser_policies_unsynced
    ON host_browser_policies(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me concerning policies across browsers".
CREATE INDEX IF NOT EXISTS idx_host_browser_policies_concerning
    ON host_browser_policies(asset_id, browser_kind, policy_name)
    WHERE is_concerning = 1;

-- Fast path: "show me force-installed extensions" (T1176 + T1195).
CREATE INDEX IF NOT EXISTS idx_host_browser_policies_force_ext
    ON host_browser_policies(asset_id, browser_kind)
    WHERE is_extension_force_installed = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_browser_policies_file_hash
    ON host_browser_policies(asset_id, file_path, file_hash);
