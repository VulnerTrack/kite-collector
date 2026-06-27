-- 20260623230000_host_editor_extensions.sql: durable storage for per-host
-- editor / IDE extension inventory introduced by CDMS iter 12.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_editor_extensions — one row per (asset_id, editor, profile,
--                            publisher, name). Publisher + name is the
--                            VS Code marketplace identity; for editors
--                            that don't have publishers (Vim plugins,
--                            Sublime packages) publisher is the empty
--                            string.
--
-- Audit value (T1176-adjacent — userspace-application persistence):
--   - Editor extensions run with full editor IPC capability and can
--     read EVERY open file. A malicious extension on a developer
--     laptop is one of the highest-value initial-access primitives.
--   - `install_source='sideloaded'` (VSIX install bypassing the
--     marketplace) → CWE-829.
--   - `activates_on_startup=1` extensions execute code at editor launch
--     — the highest blast-radius activation pattern.
--   - Cross-reference against ATT&CK-known malicious publishers
--     ("ms-vscode" lookalikes, etc.) lives in the audit pipeline.

CREATE TABLE IF NOT EXISTS host_editor_extensions (
    id                    TEXT PRIMARY KEY NOT NULL,
    asset_id              TEXT NOT NULL,
    editor                TEXT NOT NULL
                          CHECK (editor IN (
                              'vscode', 'vscodium', 'cursor',
                              'code-server', 'windsurf',
                              'intellij', 'pycharm', 'goland',
                              'webstorm', 'phpstorm', 'rubymine',
                              'rider', 'datagrip', 'clion', 'rustrover',
                              'android-studio',
                              'sublime', 'vim', 'neovim', 'emacs',
                              'unknown'
                          )),
    profile               TEXT NOT NULL,         -- "default" or named profile
    publisher             TEXT NOT NULL,
    name                  TEXT NOT NULL,
    extension_id          TEXT NOT NULL,         -- "publisher.name" for VS Code; UUID for JetBrains
    version               TEXT,
    display_name          TEXT,
    description           TEXT,
    author                TEXT,
    main_script           TEXT,                  -- entry-point path declared in package.json/plugin.xml
    engine_version        TEXT,                  -- required editor API version
    install_source        TEXT NOT NULL DEFAULT 'unknown'
                          CHECK (install_source IN (
                              'marketplace', 'sideloaded',
                              'ssh-remote', 'dev', 'system', 'unknown'
                          )),
    activates_on_startup  INTEGER NOT NULL DEFAULT 0
                          CHECK (activates_on_startup IN (0, 1)),
    activation_events_json TEXT NOT NULL DEFAULT '[]',  -- e.g. ["onStartupFinished","onLanguage:python"]
    categories_json       TEXT NOT NULL DEFAULT '[]',   -- e.g. ["Programming Languages","Linters"]
    keywords_json         TEXT NOT NULL DEFAULT '[]',
    extension_path        TEXT NOT NULL,
    manifest_path         TEXT,
    last_seen_at          TEXT NOT NULL,
    collected_at          TEXT NOT NULL,
    synced_at             INTEGER,
    created_at            INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_editor_extensions_unique
    ON host_editor_extensions(asset_id, editor, profile, publisher, name);

CREATE INDEX IF NOT EXISTS idx_host_editor_extensions_unsynced
    ON host_editor_extensions(synced_at)
    WHERE synced_at IS NULL;

-- For the CWE-829 finding: "show me sideloaded extensions".
CREATE INDEX IF NOT EXISTS idx_host_editor_extensions_sideloaded
    ON host_editor_extensions(asset_id, editor)
    WHERE install_source = 'sideloaded';

-- For startup-activation audits.
CREATE INDEX IF NOT EXISTS idx_host_editor_extensions_startup
    ON host_editor_extensions(asset_id, editor)
    WHERE activates_on_startup = 1;

-- For supply-chain lookalike-publisher detection (joined against known-bad list).
CREATE INDEX IF NOT EXISTS idx_host_editor_extensions_publisher
    ON host_editor_extensions(publisher);
