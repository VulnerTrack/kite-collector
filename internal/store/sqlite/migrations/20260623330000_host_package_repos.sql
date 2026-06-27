-- 20260623330000_host_package_repos.sql: durable storage for per-host
-- package repository inventory introduced by CDMS iter 22.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_package_repos — one row per (asset_id, ecosystem, url). Linux
--                        fills it from /etc/apt/sources.list +
--                        /etc/apt/sources.list.d/*, /etc/yum.repos.d/*,
--                        /etc/zypp/repos.d/*, /etc/apk/repositories,
--                        per-user pip/npm/cargo/gem config. macOS will
--                        cover brew taps; Windows will cover winget +
--                        chocolatey config.
--
-- Audit value (MITRE T1195 — Supply Chain Compromise):
--   - `is_https=0` flags HTTP-only mirrors. Any router on the path
--     can MitM the install. Catastrophic when paired with
--     `gpg_check=0` — no signature verification + no transport
--     integrity = the package the host installs is whatever the MitM
--     attacker sent.
--   - `gpg_check=0` flags `gpgcheck=0` in yum/dnf or `[trusted=yes]`
--     in apt. CWE-345 (Insufficient Verification of Data Authenticity).
--   - `is_third_party=1` flags repos that are NOT the canonical OS
--     mirror (e.g. PPAs on Ubuntu, COPRs on Fedora, AUR helpers).
--     Worth tracking even when signed — a compromised PPA is the
--     most common Linux supply-chain delivery vehicle.
--   - Drift events — file_hash change on any repo definition file =
--     the host's update path was modified.

CREATE TABLE IF NOT EXISTS host_package_repos (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    ecosystem           TEXT NOT NULL
                        CHECK (ecosystem IN (
                            'apt', 'yum', 'dnf', 'zypper', 'apk',
                            'pacman', 'brew', 'pip', 'npm', 'cargo',
                            'gem', 'go-module', 'snap', 'flatpak',
                            'winget', 'chocolatey', 'unknown'
                        )),
    name                TEXT NOT NULL,             -- repo ID / tap name / "default"
    url                 TEXT NOT NULL,
    distribution        TEXT,                       -- "jammy", "el9", NULL when N/A
    components_json     TEXT NOT NULL DEFAULT '[]', -- ["main", "universe"]
    architectures_json  TEXT NOT NULL DEFAULT '[]', -- ["amd64", "arm64"]
    signed_by           TEXT,                       -- path to keyring or key fingerprint
    is_https            INTEGER NOT NULL DEFAULT 0
                        CHECK (is_https IN (0, 1)),
    gpg_check           INTEGER NOT NULL DEFAULT 0
                        CHECK (gpg_check IN (0, 1)),
    is_enabled          INTEGER NOT NULL DEFAULT 1
                        CHECK (is_enabled IN (0, 1)),
    is_third_party      INTEGER NOT NULL DEFAULT 0
                        CHECK (is_third_party IN (0, 1)),
    is_source           INTEGER NOT NULL DEFAULT 0
                        CHECK (is_source IN (0, 1)),
    user_scope          TEXT,                       -- username when sourced from ~/.npmrc etc.
    file_path           TEXT,
    file_hash           TEXT,
    line_no             INTEGER NOT NULL DEFAULT 0,
    raw_line            TEXT,
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_package_repos_unique
    ON host_package_repos(asset_id, ecosystem, url, user_scope);

CREATE INDEX IF NOT EXISTS idx_host_package_repos_unsynced
    ON host_package_repos(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me repos serving over plain HTTP".
CREATE INDEX IF NOT EXISTS idx_host_package_repos_http
    ON host_package_repos(asset_id, ecosystem, url)
    WHERE is_https = 0;

-- Fast path: "show me repos without signature checking".
CREATE INDEX IF NOT EXISTS idx_host_package_repos_unsigned
    ON host_package_repos(asset_id, ecosystem, url)
    WHERE gpg_check = 0;

-- Fast path: "show me third-party repos".
CREATE INDEX IF NOT EXISTS idx_host_package_repos_thirdparty
    ON host_package_repos(asset_id, ecosystem, url)
    WHERE is_third_party = 1;

-- Drift detection on per-file content.
CREATE INDEX IF NOT EXISTS idx_host_package_repos_file_hash
    ON host_package_repos(asset_id, file_path, file_hash);
