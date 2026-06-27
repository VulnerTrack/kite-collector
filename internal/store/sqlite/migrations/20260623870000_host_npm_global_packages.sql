-- 20260623870000_host_npm_global_packages.sql: durable storage for
-- per-host npm global package inventory introduced by CDMS iter 80.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_npm_global_packages — one row per globally-installed npm
--                              package, discovered by walking the
--                              canonical `node_modules` directories
--                              under each OS's global prefix. Each
--                              row carries the manifest hash so the
--                              audit pipeline catches package
--                              upgrades or replacement between scans
--                              (npm supply-chain compromises like
--                              ua-parser-js, event-stream, the
--                              chalk/colors takeovers all surfaced
--                              as new versions of an already-
--                              installed package).
--
-- Audit value (MITRE T1195.002 — Supply Chain Compromise: Compromise
-- Software Supply Chain, plus T1059.007 — JavaScript for install
-- scripts):
--   - `has_install_scripts=1` — package declares any of
--     `preinstall`/`install`/`postinstall` in its `scripts`. These
--     run npm-side at install time with the user's privileges
--     (or root if `sudo npm install -g`). CWE-1188 surface.
--   - `has_bin_entries=1` — package declares `bin` mappings;
--     installs CLI commands the user can invoke straight from
--     the shell.
--   - `has_no_license=1` — package ships without a license field.
--     Rare on the public registry; common for hand-rolled or
--     private packages.
--   - `is_scoped_package=1` — `@scope/name` prefix. Scoped
--     packages can be private (organisation-restricted) or public
--     — useful grouping for the audit report.

CREATE TABLE IF NOT EXISTS host_npm_global_packages (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    file_path                   TEXT NOT NULL,        -- package.json
    file_hash                   TEXT NOT NULL,
    package_dir                 TEXT NOT NULL,
    install_prefix              TEXT NOT NULL,        -- top-level node_modules root
    name                        TEXT NOT NULL,        -- "chalk" / "@scope/foo"
    version                     TEXT,                 -- "5.3.0"
    description                 TEXT,
    license                     TEXT,
    author                      TEXT,
    homepage                    TEXT,
    repository_url              TEXT,
    main_entry                  TEXT,                 -- "./dist/index.js"
    engine_node                 TEXT,                 -- ">=18"
    dependency_count            INTEGER NOT NULL DEFAULT 0,
    dependencies_json           TEXT NOT NULL DEFAULT '[]',
    bin_entries_json            TEXT NOT NULL DEFAULT '[]',
    install_script_names_json   TEXT NOT NULL DEFAULT '[]',
    is_scoped_package           INTEGER NOT NULL DEFAULT 0
                                CHECK (is_scoped_package IN (0, 1)),
    has_install_scripts         INTEGER NOT NULL DEFAULT 0
                                CHECK (has_install_scripts IN (0, 1)),
    has_bin_entries             INTEGER NOT NULL DEFAULT 0
                                CHECK (has_bin_entries IN (0, 1)),
    has_no_license              INTEGER NOT NULL DEFAULT 0
                                CHECK (has_no_license IN (0, 1)),
    has_no_homepage             INTEGER NOT NULL DEFAULT 0
                                CHECK (has_no_homepage IN (0, 1)),
    has_no_repository           INTEGER NOT NULL DEFAULT 0
                                CHECK (has_no_repository IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_npm_global_packages_unique
    ON host_npm_global_packages(asset_id, file_path);

CREATE INDEX IF NOT EXISTS idx_host_npm_global_packages_unsynced
    ON host_npm_global_packages(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: packages with install scripts (CWE-1188 surface).
CREATE INDEX IF NOT EXISTS idx_host_npm_global_packages_install
    ON host_npm_global_packages(asset_id, name, version)
    WHERE has_install_scripts = 1;

-- Fast path: missing-license packages (compliance audit).
CREATE INDEX IF NOT EXISTS idx_host_npm_global_packages_no_license
    ON host_npm_global_packages(asset_id, name)
    WHERE has_no_license = 1;

-- Drift detection (hash change on package.json = upgrade or
-- replacement).
CREATE INDEX IF NOT EXISTS idx_host_npm_global_packages_drift
    ON host_npm_global_packages(asset_id, file_path, file_hash);
