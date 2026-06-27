-- 20260623250000_host_ssh_keys.sql: durable storage for per-host SSH
-- key + known-host inventory introduced by CDMS iter 14.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_ssh_keys — one row per (asset_id, role, fingerprint_sha256,
--                   source_path). Fingerprint is the natural identity
--                   for a key (multiple authorized_keys lines may grant
--                   the same key access to multiple accounts); source
--                   path keeps per-file granularity for forensics.
--
-- Audit value:
--   - MITRE T1098.004 (Account Manipulation: SSH Authorized Keys) —
--     every `role='authorized'` row is a persistent access grant. Drift
--     between scans = new key landed; rotation event triggered.
--   - MITRE T1552.004 (Unsecured Credentials: Private Keys) —
--     `role='identity-private' AND has_passphrase=0` is a passwordless
--     private key sitting on disk, the canonical credential-theft win.
--   - CWE-327 (Broken/Risky Crypto) — `key_type='ssh-rsa'` with
--     `key_bits < 2048` or `key_type='ssh-dss'` (DSA, removed from
--     OpenSSH 7.0+). Modern: ed25519, ecdsa-p256+, rsa>=3072.
--   - Lateral-movement graph — `role='known-host'` rows trace where this
--     user *has* SSHed. Combined with `role='authorized'` on the target
--     hosts, this builds the credential-reachability graph.
--   - T1098 drift — new authorized_keys entries since last scan are
--     high-signal events even without other indicators.

CREATE TABLE IF NOT EXISTS host_ssh_keys (
    id                 TEXT PRIMARY KEY NOT NULL,
    asset_id           TEXT NOT NULL,
    role               TEXT NOT NULL
                       CHECK (role IN (
                           'authorized',          -- ~/.ssh/authorized_keys
                           'identity-public',     -- ~/.ssh/id_*.pub
                           'identity-private',    -- ~/.ssh/id_* (no .pub)
                           'known-host',          -- ~/.ssh/known_hosts
                           'host-key',            -- /etc/ssh/ssh_host_*_key.pub
                           'unknown'
                       )),
    owner_user         TEXT,                       -- "alice" / "root" — owner of the .ssh dir
    key_type           TEXT,                       -- "ssh-ed25519" | "ssh-rsa" | "ecdsa-sha2-nistp256" | "ssh-dss" | "sk-..."
    key_bits           INTEGER,                    -- key size in bits (for RSA/DSA); 0 for fixed-size (ed25519, ecdsa-256/384/521)
    fingerprint_sha256 TEXT NOT NULL,              -- SHA-256 of the public key blob (the "SHA256:…" form OpenSSH prints)
    fingerprint_md5    TEXT,                       -- legacy hex MD5 for cross-tool joins
    comment            TEXT,                       -- trailing field on public-key lines
    options            TEXT,                       -- restrict= / command= / from= prefix on authorized_keys lines
    hostname           TEXT,                       -- known_hosts: hostname[,ip] field (or "HASHED" when in |1| form)
    has_passphrase     INTEGER NOT NULL DEFAULT 0  -- private-key only: bit-level inspection of the PEM body
                       CHECK (has_passphrase IN (0, 1)),
    is_weak            INTEGER NOT NULL DEFAULT 0
                       CHECK (is_weak IN (0, 1)),
    source_path        TEXT NOT NULL,
    line_no            INTEGER,                    -- authorized_keys / known_hosts: 1-based line number
    last_seen_at       TEXT NOT NULL,
    collected_at       TEXT NOT NULL,
    synced_at          INTEGER,
    created_at         INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_ssh_keys_unique
    ON host_ssh_keys(asset_id, role, fingerprint_sha256, source_path, COALESCE(line_no, 0));

CREATE INDEX IF NOT EXISTS idx_host_ssh_keys_unsynced
    ON host_ssh_keys(synced_at)
    WHERE synced_at IS NULL;

-- For T1098.004: "show me persistent SSH access grants on this host".
CREATE INDEX IF NOT EXISTS idx_host_ssh_keys_authorized
    ON host_ssh_keys(asset_id, owner_user)
    WHERE role = 'authorized';

-- For T1552.004: "show me passwordless private keys on this host".
CREATE INDEX IF NOT EXISTS idx_host_ssh_keys_unprotected_private
    ON host_ssh_keys(asset_id, owner_user)
    WHERE role = 'identity-private' AND has_passphrase = 0;

-- For weak-crypto sweep (CWE-327): index just the offenders.
CREATE INDEX IF NOT EXISTS idx_host_ssh_keys_weak
    ON host_ssh_keys(asset_id, key_type)
    WHERE is_weak = 1;

-- For lateral-movement-graph joins on fingerprint across hosts.
CREATE INDEX IF NOT EXISTS idx_host_ssh_keys_fingerprint
    ON host_ssh_keys(fingerprint_sha256);
