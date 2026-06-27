-- 20260623210000_host_certificates.sql: durable storage for per-host
-- X.509 certificate inventory introduced by CDMS iter 10.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_certificates — one row per (asset_id, store, fingerprint_sha256).
--                       fingerprint is the natural key because the same
--                       certificate may exist under multiple subject
--                       symlinks (Debian's /etc/ssl/certs/ uses both the
--                       Common Name and the OpenSSL subject hash) and we
--                       want one row per logical cert.
--
-- Audit value:
--   - CWE-295 (Improper Certificate Validation) — `self_signed=1` certs
--     in `store='system-root'` other than known anchor CAs are findings.
--   - CWE-477 (Obsolete Function) — `signature_algo='sha1WithRSA'` is
--     deprecated; `key_algorithm='RSA-1024'` or below is a finding.
--   - Expiry tracking — `not_after < now + interval '30 days'` drives
--     proactive rotation alerts.
--   - Rogue CA — `is_ca=1` certs whose fingerprint isn't in the Mozilla
--     CA bundle indicate possible MitM injection.

CREATE TABLE IF NOT EXISTS host_certificates (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    store               TEXT NOT NULL
                        CHECK (store IN (
                            'system-root', 'system-intermediate',
                            'user-root', 'user-intermediate',
                            'code-signing', 'mdm', 'webhost', 'other'
                        )),
    subject             TEXT NOT NULL,
    issuer              TEXT NOT NULL,
    serial_hex          TEXT,
    fingerprint_sha256  TEXT NOT NULL,
    fingerprint_sha1    TEXT,                  -- legacy, for cross-tooling joins
    signature_algo      TEXT,                  -- "sha256WithRSAEncryption", "ecdsa-with-SHA256", etc.
    key_algorithm       TEXT,                  -- "RSA-2048", "ECDSA-P256", "Ed25519"
    key_usage           TEXT NOT NULL DEFAULT '[]',  -- JSON array of usage strings
    ext_key_usage       TEXT NOT NULL DEFAULT '[]',  -- JSON array of EKU OIDs/names
    san_dns             TEXT NOT NULL DEFAULT '[]',  -- JSON array of DNS SANs
    san_ip              TEXT NOT NULL DEFAULT '[]',  -- JSON array of IP SANs
    not_before          TEXT NOT NULL,           -- RFC3339
    not_after           TEXT NOT NULL,           -- RFC3339
    is_ca               INTEGER NOT NULL DEFAULT 0
                        CHECK (is_ca IN (0, 1)),
    is_self_signed      INTEGER NOT NULL DEFAULT 0
                        CHECK (is_self_signed IN (0, 1)),
    source_path         TEXT,
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_certificates_unique
    ON host_certificates(asset_id, store, fingerprint_sha256);

CREATE INDEX IF NOT EXISTS idx_host_certificates_unsynced
    ON host_certificates(synced_at)
    WHERE synced_at IS NULL;

-- For the CWE-295 finding: "show me self-signed certs in the system root".
CREATE INDEX IF NOT EXISTS idx_host_certificates_self_signed_root
    ON host_certificates(asset_id, store, is_self_signed)
    WHERE store = 'system-root' AND is_self_signed = 1;

-- For expiry tracking: indexed on not_after so the rotation-window query
-- is a range scan rather than a full table scan.
CREATE INDEX IF NOT EXISTS idx_host_certificates_not_after
    ON host_certificates(asset_id, not_after);

-- For supply-chain joins on intermediate CA fingerprints.
CREATE INDEX IF NOT EXISTS idx_host_certificates_fingerprint
    ON host_certificates(fingerprint_sha256);
