-- 20260623350000_host_audit_rules.sql: durable storage for per-host
-- Linux auditd rule inventory introduced by CDMS iter 24.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_audit_rules — one row per non-comment line in /etc/audit/
--                      audit.rules + every drop-in under
--                      /etc/audit/rules.d/. Each rule is recorded
--                      verbatim (raw_line) plus parsed into the
--                      indexed columns the audit pipeline queries.
--
-- Audit value:
--   - MITRE T1562.006 (Impair Defenses: Indicator Blocking) — every
--     `auditctl -e 0` toggle or `auditctl -D` flush, every drop-in
--     that adds a `never` rule excluding the audit subsystem itself
--     is a defender-tamper event. `is_self_destructive=1` flags
--     rules that exclude audit syscalls (the canonical evasion).
--   - MITRE T1070.002 (Indicator Removal: Clear Linux/Mac System Logs)
--     — file-watch rules covering /var/log/* + /etc/audit/* tell us
--     whether log-clear attempts will be observed at all.
--   - `is_immutable=1` (auditctl -e 2) is the security-positive flag:
--     rules are locked until reboot. Drift to 0 = active tamper.
--   - `is_sensitive_path_watch=1` flags `-w` rules covering the
--     canonical sensitive-paths set (/etc/passwd, /etc/shadow,
--     /etc/sudoers, /etc/ssh/*, /etc/pam.d/*, /var/log/wtmp etc.).
--     Their absence in the audit baseline is itself a finding.
--   - File `file_hash` drift between scans on /etc/audit/rules.d/*
--     = auditd rule set was modified. Always worth alerting on.

CREATE TABLE IF NOT EXISTS host_audit_rules (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    rule_kind           TEXT NOT NULL
                        CHECK (rule_kind IN (
                            'file-watch',         -- -w path -p perm -k key
                            'syscall',            -- -a action,list -S syscall -k key
                            'control',            -- -e / -f / -b / -D / -r
                            'unknown'
                        )),
    list                TEXT
                        CHECK (list IS NULL OR list IN (
                            'exit', 'exclude', 'user', 'task', 'unknown'
                        )),
    action              TEXT
                        CHECK (action IS NULL OR action IN (
                            'always', 'never', 'unknown'
                        )),
    path                TEXT,
    perm                TEXT,                       -- combination of r/w/x/a
    syscalls_json       TEXT NOT NULL DEFAULT '[]', -- syscall numbers/names
    filters_json        TEXT NOT NULL DEFAULT '[]', -- ["arch=b64","auid>=1000","auid!=unset"]
    key                 TEXT,                       -- -k <key>
    arch                TEXT,                       -- "b64" / "b32"
    control_flag        TEXT,                       -- "e", "f", "b", "D", "r" for control rules
    control_value       TEXT,                       -- numeric/string value attached to the flag
    is_immutable        INTEGER NOT NULL DEFAULT 0
                        CHECK (is_immutable IN (0, 1)),
    is_self_destructive INTEGER NOT NULL DEFAULT 0
                        CHECK (is_self_destructive IN (0, 1)),
    is_sensitive_path_watch INTEGER NOT NULL DEFAULT 0
                        CHECK (is_sensitive_path_watch IN (0, 1)),
    file_path           TEXT,
    file_hash           TEXT,
    line_no             INTEGER NOT NULL DEFAULT 0,
    raw_line            TEXT,
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_audit_rules_unique
    ON host_audit_rules(asset_id, file_path, line_no);

CREATE INDEX IF NOT EXISTS idx_host_audit_rules_unsynced
    ON host_audit_rules(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me self-destructive rules (audit-subsystem exclusions)".
CREATE INDEX IF NOT EXISTS idx_host_audit_rules_self_destructive
    ON host_audit_rules(asset_id, key)
    WHERE is_self_destructive = 1;

-- Fast path: "show me sensitive-path watches present per asset".
CREATE INDEX IF NOT EXISTS idx_host_audit_rules_sensitive_watch
    ON host_audit_rules(asset_id, path)
    WHERE is_sensitive_path_watch = 1;

-- Fast path: "show me hosts NOT in immutable mode".
CREATE INDEX IF NOT EXISTS idx_host_audit_rules_immutable
    ON host_audit_rules(asset_id)
    WHERE is_immutable = 1;

-- Drift detection on per-file content.
CREATE INDEX IF NOT EXISTS idx_host_audit_rules_file_hash
    ON host_audit_rules(asset_id, file_path, file_hash);
