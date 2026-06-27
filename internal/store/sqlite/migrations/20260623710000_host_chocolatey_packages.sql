-- 20260623710000_host_chocolatey_packages.sql: durable storage for
-- per-host Chocolatey package inventory introduced by CDMS iter 64.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_chocolatey_packages — one row per installed Chocolatey
--                              package, discovered by walking the
--                              on-disk metadata at
--                              C:\ProgramData\chocolatey\lib\<pkg>\
--                              <pkg>.nuspec. The audit pipeline
--                              joins this against the vendor CVE
--                              feed by (package_id, version) to
--                              compute exposure.
--
-- Audit value (MITRE T1195 — Supply Chain Compromise, defender
-- side, plus T1059 — Command and Scripting Interpreter):
--   - CWE-1104 (Use of Unmaintained Third Party Components) — every
--     row contributes to the asset/version inventory the audit
--     pipeline cross-references with CVE feeds.
--   - `has_no_license_metadata=1` flags packages shipped without a
--     license declaration; this is rare for the public chocolatey
--     gallery but common for private/internal feeds, and is a
--     compliance audit headline.
--   - `is_from_non_default_source=1` flags packages whose install
--     source isn't `https://community.chocolatey.org/api/v2/` —
--     custom feeds widen the supply-chain surface (T1195.002).
--   - Drift events — file_hash change on a nuspec = the package
--     was reinstalled / upgraded. Always log the diff to the audit
--     stream so reconstructing a host's install history is possible.

CREATE TABLE IF NOT EXISTS host_chocolatey_packages (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    file_path                   TEXT NOT NULL,         -- ".../lib/git/git.nuspec"
    file_hash                   TEXT NOT NULL,
    package_id                  TEXT NOT NULL,         -- "git"
    package_version             TEXT NOT NULL,         -- "2.45.0"
    title                       TEXT,
    authors                     TEXT,
    owners                      TEXT,
    project_url                 TEXT,
    license_url                 TEXT,
    license_expression          TEXT,                  -- SPDX expression if present
    description                 TEXT,
    summary                     TEXT,
    tags                        TEXT,
    release_notes               TEXT,
    source_url                  TEXT,                  -- read from per-package metadata if available
    dependencies_json           TEXT NOT NULL DEFAULT '[]',
    dependency_count            INTEGER NOT NULL DEFAULT 0,
    has_no_license_metadata     INTEGER NOT NULL DEFAULT 0
                                CHECK (has_no_license_metadata IN (0, 1)),
    is_from_non_default_source  INTEGER NOT NULL DEFAULT 0
                                CHECK (is_from_non_default_source IN (0, 1)),
    is_prerelease               INTEGER NOT NULL DEFAULT 0
                                CHECK (is_prerelease IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_chocolatey_packages_unique
    ON host_chocolatey_packages(asset_id, package_id, package_version);

CREATE INDEX IF NOT EXISTS idx_host_chocolatey_packages_unsynced
    ON host_chocolatey_packages(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me packages without a license" (compliance audit).
CREATE INDEX IF NOT EXISTS idx_host_chocolatey_packages_no_license
    ON host_chocolatey_packages(asset_id, package_id)
    WHERE has_no_license_metadata = 1;

-- Fast path: "show me packages from custom feeds" (T1195 widen).
CREATE INDEX IF NOT EXISTS idx_host_chocolatey_packages_non_default
    ON host_chocolatey_packages(asset_id, package_id, source_url)
    WHERE is_from_non_default_source = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_chocolatey_packages_file_hash
    ON host_chocolatey_packages(asset_id, file_path, file_hash);
