-- 20260623860000_host_vscode_extensions.sql: durable storage for
-- per-host VSCode / VS Insiders / Cursor extension inventory
-- introduced by CDMS iter 79.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_vscode_extensions — one row per installed editor
--                            extension. Discovered by walking the
--                            per-user `.vscode/extensions/` and
--                            sibling directories. Each row carries
--                            the manifest hash so drift between
--                            scans is captured.
--
-- Audit value (MITRE T1195 — Supply Chain Compromise, plus T1059 —
-- Command and Scripting Interpreter via debug/terminal contributes,
-- defender side):
--   - `is_third_party_publisher=1` — publisher is NOT on the
--     curated Microsoft / official-vendor allowlist. Audit
--     pipeline cross-references against the marketplace and
--     vendor allowlists.
--   - `has_wildcard_activation=1` — extension activates on `*`
--     (every editor launch) or `onStartupFinished` (every
--     window load). Common but expands the runtime attack
--     surface.
--   - `contributes_terminal=1` / `contributes_debug=1` — extension
--     ships a custom terminal/PTY profile or debug adapter. Both
--     are direct code-execution surfaces.
--   - `is_workspace_trust_disabled=1` — extension explicitly
--     opts out of VSCode's Workspace Trust gate, meaning it
--     runs untrusted workspace code unconditionally.
--   - Drift events — manifest hash change between scans = the
--     extension was upgraded or replaced. Always alert-worthy.

CREATE TABLE IF NOT EXISTS host_vscode_extensions (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    file_path                       TEXT NOT NULL,        -- package.json
    file_hash                       TEXT NOT NULL,
    extension_dir                   TEXT NOT NULL,        -- parent dir
    user_profile                    TEXT,                 -- user name owning the .vscode
    editor_kind                     TEXT NOT NULL
                                    CHECK (editor_kind IN (
                                        'vscode', 'vscode-insiders',
                                        'cursor', 'unknown'
                                    )),
    publisher                       TEXT NOT NULL,        -- "ms-python"
    extension_name                  TEXT NOT NULL,        -- "python"
    extension_version               TEXT,                 -- "2024.0.1"
    display_name                    TEXT,
    description                     TEXT,
    main_entry                      TEXT,                 -- "./out/extension.js"
    engine_vscode                   TEXT,                 -- "^1.80.0"
    activation_events_json          TEXT NOT NULL DEFAULT '[]',
    contributes_json                TEXT NOT NULL DEFAULT '[]', -- top-level keys
    is_third_party_publisher        INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_third_party_publisher IN (0, 1)),
    has_wildcard_activation         INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_wildcard_activation IN (0, 1)),
    contributes_terminal            INTEGER NOT NULL DEFAULT 0
                                    CHECK (contributes_terminal IN (0, 1)),
    contributes_debug               INTEGER NOT NULL DEFAULT 0
                                    CHECK (contributes_debug IN (0, 1)),
    contributes_tasks               INTEGER NOT NULL DEFAULT 0
                                    CHECK (contributes_tasks IN (0, 1)),
    is_workspace_trust_disabled     INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_workspace_trust_disabled IN (0, 1)),
    is_supply_chain_candidate       INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_supply_chain_candidate IN (0, 1)),
    last_seen_at                    TEXT NOT NULL,
    collected_at                    TEXT NOT NULL,
    synced_at                       INTEGER,
    created_at                      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_vscode_extensions_unique
    ON host_vscode_extensions(asset_id, file_path);

CREATE INDEX IF NOT EXISTS idx_host_vscode_extensions_unsynced
    ON host_vscode_extensions(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: third-party publisher (T1195 supply chain).
CREATE INDEX IF NOT EXISTS idx_host_vscode_extensions_third_party
    ON host_vscode_extensions(asset_id, publisher, extension_name)
    WHERE is_third_party_publisher = 1;

-- Fast path: supply-chain-candidate rollup (third-party + RCE-adjacent
-- contributes).
CREATE INDEX IF NOT EXISTS idx_host_vscode_extensions_supply
    ON host_vscode_extensions(asset_id, publisher, extension_name)
    WHERE is_supply_chain_candidate = 1;

-- Fast path: extensions that opt out of Workspace Trust.
CREATE INDEX IF NOT EXISTS idx_host_vscode_extensions_no_trust
    ON host_vscode_extensions(asset_id, publisher, extension_name)
    WHERE is_workspace_trust_disabled = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_vscode_extensions_drift
    ON host_vscode_extensions(asset_id, file_path, file_hash);
