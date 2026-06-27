-- 20260623640000_host_wireguard_tunnels.sql: durable storage for per-host
-- WireGuard tunnel inventory introduced by CDMS iter 57.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_wireguard_tunnels — one row per [Interface]/[Peer] section
--                            discovered under /etc/wireguard/*.conf
--                            (and Homebrew counterparts). section_kind
--                            distinguishes the local-tunnel `[Interface]`
--                            row from each `[Peer]` row so the audit
--                            pipeline can target findings precisely.
--
-- Audit value (MITRE T1572 — Protocol Tunneling, T1059 — Command and
-- Scripting Interpreter, T1539 — Steal Web Session Cookie):
--   - CWE-312 (Cleartext Storage of Sensitive Information) —
--     `has_private_key_exposed=1` flags an [Interface] row whose
--     PrivateKey is stored in a world- or group-readable .conf.
--     WireGuard's installer leaves files at 0600 by intent.
--   - CWE-732 — `is_file_world_readable=1` / `is_file_group_readable=1`
--     surface the same finding by file mode.
--   - T1572 — `is_full_traffic_route=1` is a [Peer] with AllowedIPs
--     covering 0.0.0.0/0 or ::/0 — that peer can route all of this
--     host's traffic (or vice versa); when this is a server-side
--     config, it's a wildcard catch-all you didn't mean to grant.
--   - CWE-78 / T1059 (OS Command Injection) — `has_shell_hook=1` on
--     [Interface] sections flags PostUp/PostDown/PreUp/PreDown lines
--     that invoke a shell command. Tunnel bring-up = arbitrary code
--     on the host root account.
--   - CWE-308 (Use of Single-factor Authentication) — `is_missing_preshared_key=1`
--     on a [Peer] section drops the third (PSK) factor; legitimate
--     for personal tunnels, regression for site-to-site.
--   - Drift events — file_hash change on any .conf = the tunnel
--     surface was modified; alert verbatim.

CREATE TABLE IF NOT EXISTS host_wireguard_tunnels (
    id                           TEXT PRIMARY KEY NOT NULL,
    asset_id                     TEXT NOT NULL,
    file_path                    TEXT NOT NULL,
    file_hash                    TEXT NOT NULL,
    section_kind                 TEXT NOT NULL
                                 CHECK (section_kind IN (
                                     'interface', 'peer', 'unknown'
                                 )),
    section_index                INTEGER NOT NULL DEFAULT 0,    -- 0 for [Interface], 1..N for [Peer] order in file
    tunnel_name                  TEXT NOT NULL,                 -- file basename without .conf
    address                      TEXT,                          -- [Interface]: "10.0.0.1/24"
    listen_port                  INTEGER,                       -- [Interface]
    dns                          TEXT,                          -- [Interface]
    mtu                          INTEGER,                       -- [Interface]
    table_routing                TEXT,                          -- [Interface] Table = "auto" / "off" / numeric
    public_key_fingerprint       TEXT,                          -- sha256(first 12 hex of public key) for join across rows
    peer_public_key_fingerprint  TEXT,                          -- [Peer] only
    endpoint                     TEXT,                          -- [Peer] "host:port"
    allowed_ips                  TEXT,                          -- raw comma-separated
    persistent_keepalive_seconds INTEGER,                       -- [Peer]
    shell_hooks_json             TEXT NOT NULL DEFAULT '[]',    -- [Interface] PostUp etc body strings
    file_mode                    INTEGER,                       -- octal int (0600 = 384)
    file_owner_uid               INTEGER,
    has_private_key              INTEGER NOT NULL DEFAULT 0
                                 CHECK (has_private_key IN (0, 1)),
    has_preshared_key            INTEGER NOT NULL DEFAULT 0
                                 CHECK (has_preshared_key IN (0, 1)),
    is_missing_preshared_key     INTEGER NOT NULL DEFAULT 0
                                 CHECK (is_missing_preshared_key IN (0, 1)),
    is_full_traffic_route        INTEGER NOT NULL DEFAULT 0
                                 CHECK (is_full_traffic_route IN (0, 1)),
    has_shell_hook               INTEGER NOT NULL DEFAULT 0
                                 CHECK (has_shell_hook IN (0, 1)),
    has_persistent_keepalive     INTEGER NOT NULL DEFAULT 0
                                 CHECK (has_persistent_keepalive IN (0, 1)),
    is_file_world_readable       INTEGER NOT NULL DEFAULT 0
                                 CHECK (is_file_world_readable IN (0, 1)),
    is_file_group_readable       INTEGER NOT NULL DEFAULT 0
                                 CHECK (is_file_group_readable IN (0, 1)),
    has_private_key_exposed      INTEGER NOT NULL DEFAULT 0
                                 CHECK (has_private_key_exposed IN (0, 1)),
    last_seen_at                 TEXT NOT NULL,
    collected_at                 TEXT NOT NULL,
    synced_at                    INTEGER,
    created_at                   INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_wireguard_tunnels_unique
    ON host_wireguard_tunnels(asset_id, file_path, section_index);

CREATE INDEX IF NOT EXISTS idx_host_wireguard_tunnels_unsynced
    ON host_wireguard_tunnels(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me private keys leaking through the filesystem"
-- (CWE-312 + CWE-732).
CREATE INDEX IF NOT EXISTS idx_host_wireguard_tunnels_key_exposed
    ON host_wireguard_tunnels(asset_id, file_path, tunnel_name)
    WHERE has_private_key_exposed = 1;

-- Fast path: "show me peers that route all traffic" (T1572).
CREATE INDEX IF NOT EXISTS idx_host_wireguard_tunnels_full_route
    ON host_wireguard_tunnels(asset_id, file_path, peer_public_key_fingerprint)
    WHERE is_full_traffic_route = 1 AND section_kind = 'peer';

-- Fast path: "show me tunnels with shell hooks" (T1059).
CREATE INDEX IF NOT EXISTS idx_host_wireguard_tunnels_shell_hook
    ON host_wireguard_tunnels(asset_id, file_path, tunnel_name)
    WHERE has_shell_hook = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_wireguard_tunnels_file_hash
    ON host_wireguard_tunnels(asset_id, file_path, file_hash);
