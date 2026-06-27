-- 20260623300000_host_intranet_webs.sql: durable storage for the
-- intranet-web inventory introduced by CDMS iter 19.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_intranet_webs — one row per (asset_id, ip, port) for every
--                        internal-facing HTTP/HTTPS endpoint the agent
--                        could reach. The collector probes the LAN host
--                        list emitted by the mdns/ssdp/netbios/lldp/
--                        wsdiscovery sources plus any IPs harvested
--                        from /etc/hosts and the user's proxy PAC.
--
-- Audit value:
--   - CWE-319 (Cleartext Transmission): `is_cleartext=1` flags every
--     plain-http intranet UI that should have been TLS-terminated.
--   - CWE-295 (Improper Cert Validation): `tls_self_signed=1` or
--     `tls_expired=1` flag intranet certs that browsers will warn on —
--     these UIs train users to click through cert warnings, defeating
--     phishing protection.
--   - CWE-200 (Information Exposure): `is_directory_listing=1` flags
--     servers that returned an Apache/nginx autoindex page.
--   - MITRE T1133 (External Remote Services, internal variant) +
--     T1190 (Exploit Public-Facing Application, internal pivot): every
--     row is a candidate attack surface for an already-internal actor.
--   - Drift events: page_hash + cert_fingerprint change between scans
--     surface UI changes (banner updates → patch cycle visibility) and
--     cert rotations.

CREATE TABLE IF NOT EXISTS host_intranet_webs (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    scheme              TEXT NOT NULL
                        CHECK (scheme IN ('http', 'https')),
    host                TEXT NOT NULL,             -- resolved hostname when known, else IP
    ip                  TEXT NOT NULL,
    port                INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    discovery_source    TEXT NOT NULL
                        CHECK (discovery_source IN (
                            'mdns', 'ssdp', 'wsdiscovery',
                            'netbios', 'lldp',
                            'hosts-file', 'proxy-pac',
                            'manual', 'subnet-sweep', 'unknown'
                        )),
    status_code         INTEGER,                    -- HTTP status; NULL if probe failed
    server_header       TEXT,                       -- e.g. "Apache/2.4.59"
    title               TEXT,                       -- first <title> from response body
    content_type        TEXT,                       -- Content-Type header
    powered_by          TEXT,                       -- X-Powered-By
    auth_scheme         TEXT,                       -- 401 WWW-Authenticate scheme
    tls_subject         TEXT,                       -- CN= ... ,O= ...
    tls_issuer          TEXT,
    tls_not_after       TEXT,                       -- RFC3339; NULL when http
    tls_fingerprint_sha256 TEXT,                    -- hex
    is_cleartext        INTEGER NOT NULL DEFAULT 0
                        CHECK (is_cleartext IN (0, 1)),
    tls_self_signed     INTEGER NOT NULL DEFAULT 0
                        CHECK (tls_self_signed IN (0, 1)),
    tls_expired         INTEGER NOT NULL DEFAULT 0
                        CHECK (tls_expired IN (0, 1)),
    is_directory_listing INTEGER NOT NULL DEFAULT 0
                        CHECK (is_directory_listing IN (0, 1)),
    is_default_page     INTEGER NOT NULL DEFAULT 0
                        CHECK (is_default_page IN (0, 1)),
    page_hash           TEXT,                       -- sha256 of (status + headers + title)
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_intranet_webs_unique
    ON host_intranet_webs(asset_id, ip, port);

CREATE INDEX IF NOT EXISTS idx_host_intranet_webs_unsynced
    ON host_intranet_webs(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me cleartext intranet UIs" (CWE-319).
CREATE INDEX IF NOT EXISTS idx_host_intranet_webs_cleartext
    ON host_intranet_webs(asset_id, host)
    WHERE is_cleartext = 1;

-- Fast path: "show me self-signed certs" (CWE-295).
CREATE INDEX IF NOT EXISTS idx_host_intranet_webs_selfsigned
    ON host_intranet_webs(asset_id, host)
    WHERE tls_self_signed = 1;

-- Fast path: "show me expired certs" (CWE-295).
CREATE INDEX IF NOT EXISTS idx_host_intranet_webs_expired
    ON host_intranet_webs(asset_id, host)
    WHERE tls_expired = 1;

-- Fast path: "show me directory-listing exposures" (CWE-200).
CREATE INDEX IF NOT EXISTS idx_host_intranet_webs_dirlist
    ON host_intranet_webs(asset_id, host)
    WHERE is_directory_listing = 1;

-- Drift detection on page banner content.
CREATE INDEX IF NOT EXISTS idx_host_intranet_webs_page_hash
    ON host_intranet_webs(asset_id, ip, port, page_hash);
