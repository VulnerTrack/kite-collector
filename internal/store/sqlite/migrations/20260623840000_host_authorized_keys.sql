-- 20260623840000_host_authorized_keys.sql: durable storage for per-
-- host OpenSSH authorized_keys inventory introduced by CDMS iter 77.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_authorized_keys — one row per key entry parsed out of an
--                          authorized_keys file across all the
--                          canonical locations:
--                            Windows admin: C:\ProgramData\ssh\
--                                           administrators_authorized_keys
--                            Windows user:  C:\Users\<u>\.ssh\authorized_keys
--                            Linux/macOS:   /root/.ssh/authorized_keys
--                            Linux/macOS:   /home/<u>/.ssh/authorized_keys
--                            macOS:         /Users/<u>/.ssh/authorized_keys
--
-- Audit value (MITRE T1098.004 — Account Manipulation: SSH
-- Authorized Keys, defender side):
--   - `is_administrators_key=1` — key sits in Windows
--     administrators_authorized_keys. OpenSSH on Windows treats
--     this file as the single source of truth for ANY admin-
--     group login; one key here = root-equivalent persistence.
--   - `is_root_key=1` — key sits in /root/.ssh/authorized_keys.
--     Equivalent persistence on Linux/macOS.
--   - `is_weak_key_type=1` — key type is ssh-dss (DSA, broken),
--     ecdsa-sha2-nistp192 (small curve), or the parsed RSA
--     length is under 2048 bits.
--   - `is_no_comment=1` — key has no trailing comment field.
--     Legitimate ssh-keygen always appends user@host; anonymous
--     keys are a persistence signal.
--   - `has_dangerous_options=1` — key carries options that
--     bypass the usual restrictions (no-pty/no-X11 are fine; a
--     missing `command=` with a permissive options set on a
--     persisted key is the audit concern).
--   - Drift events — file_hash change on any authorized_keys
--     file = the SSH trust surface was modified; alert verbatim.

CREATE TABLE IF NOT EXISTS host_authorized_keys (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    file_path                   TEXT NOT NULL,
    file_hash                   TEXT NOT NULL,
    line_no                     INTEGER NOT NULL,
    user_profile                TEXT,                   -- "" when admin-scope file
    key_scope                   TEXT NOT NULL
                                CHECK (key_scope IN (
                                    'admin', 'root', 'user', 'unknown'
                                )),
    key_type                    TEXT NOT NULL
                                CHECK (key_type IN (
                                    'rsa', 'ed25519', 'ecdsa',
                                    'dsa', 'rsa-sha2', 'sk-ed25519',
                                    'sk-ecdsa', 'unknown'
                                )),
    key_type_raw                TEXT NOT NULL,          -- raw "ssh-rsa" / "ssh-ed25519" / …
    key_fingerprint             TEXT,                   -- sha256 hex of decoded blob (12 hex prefix)
    key_bits                    INTEGER NOT NULL DEFAULT 0,  -- RSA modulus length when parseable
    comment                     TEXT,
    options                     TEXT,
    has_options                 INTEGER NOT NULL DEFAULT 0
                                CHECK (has_options IN (0, 1)),
    is_administrators_key       INTEGER NOT NULL DEFAULT 0
                                CHECK (is_administrators_key IN (0, 1)),
    is_root_key                 INTEGER NOT NULL DEFAULT 0
                                CHECK (is_root_key IN (0, 1)),
    is_weak_key_type            INTEGER NOT NULL DEFAULT 0
                                CHECK (is_weak_key_type IN (0, 1)),
    is_no_comment               INTEGER NOT NULL DEFAULT 0
                                CHECK (is_no_comment IN (0, 1)),
    has_dangerous_options       INTEGER NOT NULL DEFAULT 0
                                CHECK (has_dangerous_options IN (0, 1)),
    is_high_privilege_target    INTEGER NOT NULL DEFAULT 0
                                CHECK (is_high_privilege_target IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_authorized_keys_unique
    ON host_authorized_keys(asset_id, file_path, line_no);

CREATE INDEX IF NOT EXISTS idx_host_authorized_keys_unsynced
    ON host_authorized_keys(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: T1098.004 — high-privilege persistence targets.
CREATE INDEX IF NOT EXISTS idx_host_authorized_keys_priv
    ON host_authorized_keys(asset_id, file_path, key_fingerprint)
    WHERE is_high_privilege_target = 1;

-- Fast path: anonymous keys on a privileged file.
CREATE INDEX IF NOT EXISTS idx_host_authorized_keys_no_comment
    ON host_authorized_keys(asset_id, file_path)
    WHERE is_no_comment = 1 AND is_high_privilege_target = 1;

-- Fast path: weak key algorithm.
CREATE INDEX IF NOT EXISTS idx_host_authorized_keys_weak
    ON host_authorized_keys(asset_id, file_path, key_fingerprint)
    WHERE is_weak_key_type = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_authorized_keys_drift
    ON host_authorized_keys(asset_id, file_path, file_hash);
