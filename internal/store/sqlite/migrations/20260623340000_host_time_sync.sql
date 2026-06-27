-- 20260623340000_host_time_sync.sql: durable storage for per-host
-- time-synchronization source inventory introduced by CDMS iter 23.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_time_sync — one row per (asset_id, source, server). Linux fills
--                    it from /etc/chrony/chrony.conf (+ drop-ins),
--                    /etc/ntp.conf, /etc/systemd/timesyncd.conf, OpenNTPD
--                    /etc/ntpd.conf. macOS will cover sntp via
--                    /etc/ntp.conf; Windows will cover w32time.
--
-- Audit value:
--   - MITRE T1124 (System Time Discovery / Time Manipulation) — the
--     prerequisite for clock-skew attacks. An attacker who controls
--     the host's NTP source can shift its clock far enough to make
--     expired Kerberos tickets validate, replay TOTP codes, or
--     invalidate signed payloads' expiry checks.
--   - MITRE T1098 (Account Manipulation, Kerberos branch) — Golden
--     Ticket / Silver Ticket forgery requires the attacker's clock to
--     match the KDC's. Hijacking the host's NTP peer is one path.
--   - CWE-345 (Insufficient Verification of Data Authenticity) —
--     `is_authenticated=0` flags peers without NTS / autokey / shared
--     key. Plain NTP is trivially MitM-able by any router on the path.
--   - `is_public_server=1` flags peers in well-known pool/public
--     networks. Acceptable for personal devices, suspicious for
--     domain-joined endpoints that should sync to the corp NTP server.
--   - Drift events — file_hash change on any time-sync config file =
--     the host's notion of UTC was modified.

CREATE TABLE IF NOT EXISTS host_time_sync (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    source              TEXT NOT NULL
                        CHECK (source IN (
                            'chrony',
                            'ntpd',
                            'systemd-timesyncd',
                            'openntpd',
                            'w32time',
                            'sntp',
                            'unknown'
                        )),
    directive           TEXT NOT NULL
                        CHECK (directive IN (
                            'server', 'peer', 'pool', 'fallback',
                            'sntp-fallback', 'unknown'
                        )),
    server              TEXT NOT NULL,
    port                INTEGER NOT NULL DEFAULT 123,
    protocol            TEXT NOT NULL
                        CHECK (protocol IN (
                            'ntp', 'nts', 'sntp', 'autokey', 'unknown'
                        )),
    iburst              INTEGER NOT NULL DEFAULT 0
                        CHECK (iburst IN (0, 1)),
    prefer_flag         INTEGER NOT NULL DEFAULT 0
                        CHECK (prefer_flag IN (0, 1)),
    is_authenticated    INTEGER NOT NULL DEFAULT 0
                        CHECK (is_authenticated IN (0, 1)),
    is_public_server    INTEGER NOT NULL DEFAULT 0
                        CHECK (is_public_server IN (0, 1)),
    is_pool_member      INTEGER NOT NULL DEFAULT 0
                        CHECK (is_pool_member IN (0, 1)),
    key_id              INTEGER,
    minpoll             INTEGER,
    maxpoll             INTEGER,
    file_path           TEXT,
    file_hash           TEXT,
    line_no             INTEGER NOT NULL DEFAULT 0,
    raw_line            TEXT,
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_time_sync_unique
    ON host_time_sync(asset_id, source, server, port, directive);

CREATE INDEX IF NOT EXISTS idx_host_time_sync_unsynced
    ON host_time_sync(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me public NTP peers on managed endpoints".
CREATE INDEX IF NOT EXISTS idx_host_time_sync_public
    ON host_time_sync(asset_id, server)
    WHERE is_public_server = 1;

-- Fast path: "show me unauthenticated NTP peers".
CREATE INDEX IF NOT EXISTS idx_host_time_sync_unauth
    ON host_time_sync(asset_id, server)
    WHERE is_authenticated = 0;

-- Drift detection on per-file content.
CREATE INDEX IF NOT EXISTS idx_host_time_sync_file_hash
    ON host_time_sync(asset_id, file_path, file_hash);
