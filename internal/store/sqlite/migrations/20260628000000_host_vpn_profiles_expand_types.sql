-- 20260628000000_host_vpn_profiles_expand_types.sql: widen the
-- vpn_type CHECK constraint on host_vpn_profiles to cover the
-- commercial / enterprise VPN clients introduced by CDMS iter 14:
--
--   globalprotect    -- Palo Alto Networks GlobalProtect
--   checkpoint       -- Check Point Remote Secure Access
--   directaccess     -- Microsoft DirectAccess (Windows-only)
--   nordlayer        -- NordLayer (formerly NordVPN Teams)
--   protonvpn        -- Proton VPN / Proton VPN for Business
--   mullvad          -- Mullvad VPN
--
-- SQLite cannot ALTER a CHECK constraint in-place, so we use the
-- documented rebuild dance (https://www.sqlite.org/lang_altertable.html
-- §7 "Making Other Kinds Of Table Schema Changes"):
--
--   1. CREATE TABLE with the new schema under a temp name
--   2. INSERT … SELECT * to copy rows (existing enum values are a
--      strict subset of the new ones, so the copy never violates)
--   3. DROP the original
--   4. ALTER … RENAME to claim the canonical name
--   5. Recreate all indexes (they're dropped with the table)
--
-- The migration runner already wraps each file in a transaction,
-- so we don't (and can't) add our own BEGIN/COMMIT here — SQLite
-- rejects nested transactions with "cannot start a transaction
-- within a transaction".

CREATE TABLE IF NOT EXISTS host_vpn_profiles_new (
    id                    TEXT PRIMARY KEY NOT NULL,
    asset_id              TEXT NOT NULL,
    vpn_type              TEXT NOT NULL
                          CHECK (vpn_type IN (
                              'wireguard', 'openvpn',
                              'ipsec', 'strongswan', 'libreswan',
                              'tailscale', 'zerotier', 'nebula', 'netbird',
                              'windows-builtin', 'macos-builtin',
                              'cisco-anyconnect', 'fortinet', 'pulse',
                              'globalprotect', 'checkpoint', 'directaccess',
                              'nordlayer', 'protonvpn', 'mullvad',
                              'unknown'
                          )),
    name                  TEXT NOT NULL,
    config_path           TEXT NOT NULL,
    enabled               INTEGER NOT NULL DEFAULT 0
                          CHECK (enabled IN (0, 1)),
    auto_connect          INTEGER NOT NULL DEFAULT 0
                          CHECK (auto_connect IN (0, 1)),
    endpoint              TEXT,
    protocol              TEXT,
    port                  INTEGER,
    routed_subnets_json   TEXT NOT NULL DEFAULT '[]',
    dns_servers_json      TEXT NOT NULL DEFAULT '[]',
    mtu                   INTEGER,
    is_full_tunnel        INTEGER NOT NULL DEFAULT 0
                          CHECK (is_full_tunnel IN (0, 1)),
    private_key_present   INTEGER NOT NULL DEFAULT 0
                          CHECK (private_key_present IN (0, 1)),
    preshared_key_present INTEGER NOT NULL DEFAULT 0
                          CHECK (preshared_key_present IN (0, 1)),
    last_handshake_at     TEXT,
    last_seen_at          TEXT NOT NULL,
    collected_at          TEXT NOT NULL,
    synced_at             INTEGER,
    created_at            INTEGER NOT NULL DEFAULT (unixepoch())
);

-- INSERT OR IGNORE is paranoia — every existing vpn_type value
-- (cisco-anyconnect, fortinet, pulse, wireguard, …) is already
-- accepted by the widened CHECK, so the copy is total.
INSERT OR IGNORE INTO host_vpn_profiles_new
SELECT * FROM host_vpn_profiles;

DROP TABLE host_vpn_profiles;
ALTER TABLE host_vpn_profiles_new RENAME TO host_vpn_profiles;

-- Restore the index set from the original migration.
CREATE UNIQUE INDEX IF NOT EXISTS idx_host_vpn_profiles_unique
    ON host_vpn_profiles(asset_id, vpn_type, config_path);

CREATE INDEX IF NOT EXISTS idx_host_vpn_profiles_unsynced
    ON host_vpn_profiles(synced_at)
    WHERE synced_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_host_vpn_profiles_full_tunnel
    ON host_vpn_profiles(asset_id, vpn_type)
    WHERE is_full_tunnel = 1;

CREATE INDEX IF NOT EXISTS idx_host_vpn_profiles_unattended_creds
    ON host_vpn_profiles(asset_id, vpn_type)
    WHERE auto_connect = 1 AND private_key_present = 1;

CREATE INDEX IF NOT EXISTS idx_host_vpn_profiles_handshake
    ON host_vpn_profiles(asset_id, last_handshake_at);
