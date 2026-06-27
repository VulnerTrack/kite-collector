-- 20260423000001_identity_onboarding.sql: RFC-0112 dashboard onboarding
-- Adds the singleton enrolled_identity record and a bounded probe_result
-- history for the dashboard's token-enrollment + connection-check flow.

CREATE TABLE IF NOT EXISTS enrolled_identity (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    api_key_fingerprint     TEXT NOT NULL,
    api_key_wrapped         BLOB NOT NULL,
    first_enrolled_at       INTEGER NOT NULL,
    last_enrolled_at        INTEGER NOT NULL,
    last_check_passed_at    INTEGER,
    last_check_failed_at    INTEGER
) STRICT;

CREATE TABLE IF NOT EXISTS probe_result (
    probe_run_id            TEXT PRIMARY KEY,
    probe_name              TEXT NOT NULL,
    result                  TEXT NOT NULL CHECK (result IN ('pass','fail','skip')),
    latency_ms              INTEGER NOT NULL,
    diagnostic              TEXT,
    checked_at              INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_probe_result_checked_at
    ON probe_result(checked_at DESC);

-- Cap history at the most recent 100 rows. The trigger fires AFTER each
-- INSERT and prunes anything older than the 100th-most-recent checked_at.
CREATE TRIGGER IF NOT EXISTS trg_probe_result_cap
AFTER INSERT ON probe_result
BEGIN
    DELETE FROM probe_result
    WHERE probe_run_id NOT IN (
        SELECT probe_run_id FROM probe_result
        ORDER BY checked_at DESC, probe_run_id DESC
        LIMIT 100
    );
END;
