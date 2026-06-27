-- 20260623150000_host_listeners.sql: durable storage for listening TCP/UDP
-- socket inventory introduced by CDMS iter 4.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_listeners — one row per (asset_id, protocol, bind_address, port)
--                    observed in LISTEN state. process_name + pid are
--                    denormalised from host_processes for query speed
--                    (the audit pipeline asks "what's exposed?" far more
--                    often than "which process is doing it?").
--
-- `exposure` is the derived classification that drives most audit rules:
--   internet → bound to 0.0.0.0 / :: (reachable from any IP that can
--              route to the host)
--   lan      → bound to a private CIDR (10/8, 172.16/12, 192.168/16,
--              link-local) — reachable within the broadcast domain only
--   loopback → 127.0.0.0/8 or ::1 — local-only
--
-- This pre-computation lets the CWE-319/284/200 queries run as single
-- equality lookups instead of CIDR matches at query time.

CREATE TABLE IF NOT EXISTS host_listeners (
    id            TEXT PRIMARY KEY NOT NULL,
    asset_id      TEXT NOT NULL,
    protocol      TEXT NOT NULL
                  CHECK (protocol IN ('tcp', 'tcp6', 'udp', 'udp6')),
    bind_address  TEXT NOT NULL,
    port          INTEGER NOT NULL
                  CHECK (port BETWEEN 0 AND 65535),
    exposure      TEXT NOT NULL DEFAULT 'unknown'
                  CHECK (exposure IN (
                      'internet', 'lan', 'loopback', 'unknown'
                  )),
    pid           INTEGER,
    process_name  TEXT,
    exe           TEXT,
    username      TEXT,
    last_seen_at  TEXT NOT NULL,
    collected_at  TEXT NOT NULL,
    synced_at     INTEGER,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_listeners_unique
    ON host_listeners(asset_id, protocol, bind_address, port);

CREATE INDEX IF NOT EXISTS idx_host_listeners_unsynced
    ON host_listeners(synced_at)
    WHERE synced_at IS NULL;

-- For the CWE-200 finding: "show me anything internet-exposed".
CREATE INDEX IF NOT EXISTS idx_host_listeners_internet_exposure
    ON host_listeners(asset_id, exposure, port)
    WHERE exposure = 'internet';

-- FK-like join hint: many audit rules join listeners -> processes by pid.
CREATE INDEX IF NOT EXISTS idx_host_listeners_pid
    ON host_listeners(asset_id, pid)
    WHERE pid IS NOT NULL;
