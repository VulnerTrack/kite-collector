-- 20260623410000_host_sshd_config.sql: durable storage for per-host
-- OpenSSH server config inventory introduced by CDMS iter 30.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_sshd_config — one row per (asset_id, file_path, line_no).
--                      The collector parses /etc/ssh/sshd_config plus
--                      every drop-in under /etc/ssh/sshd_config.d/.
--                      macOS uses the same paths; Windows OpenSSH
--                      installs under %ProgramData%\ssh\ (future
--                      iteration).
--
-- Audit value:
--   - MITRE T1021.004 (Remote Services: SSH) — sshd is the canonical
--     remote-shell entry point. Weak server config = lateral pivot.
--   - MITRE T1098 (Account Manipulation, Kerberos branch) —
--     PermitRootLogin=yes lets an attacker who phished any password
--     escalate without intermediate hops.
--   - CWE-307 (Improper Restriction of Excessive Authentication
--     Attempts) — MaxAuthTries > 4 weakens brute-force protection.
--   - CWE-327 (Use of Broken Crypto) — Ciphers / MACs / KexAlgorithms
--     containing aes*-cbc, arcfour, 3des, hmac-md5, hmac-sha1 (no
--     -etm), diffie-hellman-group1-sha1 = `is_baseline_violation=1`
--     with the corresponding finding_category.
--   - CIS Linux Benchmark section 5.2 — every directive here maps
--     1:1 to a CIS control. Drift between scans = audit-evading
--     server modification.

CREATE TABLE IF NOT EXISTS host_sshd_config (
    id                       TEXT PRIMARY KEY NOT NULL,
    asset_id                 TEXT NOT NULL,
    scope                    TEXT NOT NULL
                             CHECK (scope IN ('global', 'match')),
    match_criteria           TEXT,            -- "User alice" / "Host *.corp.local" / NULL when global
    key                      TEXT NOT NULL,
    value                    TEXT NOT NULL DEFAULT '',
    is_security_critical     INTEGER NOT NULL DEFAULT 0
                             CHECK (is_security_critical IN (0, 1)),
    is_baseline_violation    INTEGER NOT NULL DEFAULT 0
                             CHECK (is_baseline_violation IN (0, 1)),
    finding_category         TEXT
                             CHECK (finding_category IS NULL OR finding_category IN (
                                 'root-login-permitted',
                                 'password-auth-permitted',
                                 'empty-password-permitted',
                                 'x11-forwarding-enabled',
                                 'agent-forwarding-enabled',
                                 'tcp-forwarding-enabled',
                                 'host-based-auth-enabled',
                                 'rhosts-not-ignored',
                                 'excessive-auth-attempts',
                                 'long-login-grace',
                                 'weak-cipher',
                                 'weak-mac',
                                 'weak-kex',
                                 'protocol-v1',
                                 'permit-user-environment',
                                 'no-banner',
                                 'unknown'
                             )),
    file_path                TEXT,
    file_hash                TEXT,
    line_no                  INTEGER NOT NULL DEFAULT 0,
    raw_line                 TEXT,
    last_seen_at             TEXT NOT NULL,
    collected_at             TEXT NOT NULL,
    synced_at                INTEGER,
    created_at               INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_sshd_config_unique
    ON host_sshd_config(asset_id, file_path, line_no);

CREATE INDEX IF NOT EXISTS idx_host_sshd_config_unsynced
    ON host_sshd_config(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me CIS 5.2 baseline violations".
CREATE INDEX IF NOT EXISTS idx_host_sshd_config_violations
    ON host_sshd_config(asset_id, finding_category)
    WHERE is_baseline_violation = 1;

-- Fast path: "show me hosts that permit root login or password auth".
CREATE INDEX IF NOT EXISTS idx_host_sshd_config_root_or_pass
    ON host_sshd_config(asset_id, key)
    WHERE finding_category IN ('root-login-permitted', 'password-auth-permitted',
                                'empty-password-permitted');

-- Drift detection on per-file content.
CREATE INDEX IF NOT EXISTS idx_host_sshd_config_file_hash
    ON host_sshd_config(asset_id, file_path, file_hash);
