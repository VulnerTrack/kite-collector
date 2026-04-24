-- 20260424000000_drop_identity_platform_endpoint.sql: RFC-0112 follow-up.
-- Drops the legacy enrolled_identity.platform_endpoint column from deploys
-- that applied 20260423000001 before commit fede515 removed it from the
-- CREATE TABLE body. Uses the portable "rebuild table" pattern so it
-- succeeds in both paths:
--
--   * Upgraded deploys (platform_endpoint present, NOT NULL): the column
--     list below copies every retained column into enrolled_identity_new
--     and discards platform_endpoint.
--   * Fresh installs (platform_endpoint was never created because the
--     edited 20260423000001 was applied in one shot): the INSERT ... SELECT
--     copies the same retained columns from a table that already lacks
--     platform_endpoint, the drop + rename still succeeds, and the end
--     state matches the upgraded path.
--
-- The migration runner wraps each file in a single transaction (see
-- sqlite.Migrate), so the CREATE/INSERT/DROP/RENAME sequence is atomic.
-- SQLite's legacy_alter_table behavior is left at its default since we
-- never reference the old table from views or triggers.

CREATE TABLE enrolled_identity_new (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    api_key_fingerprint     TEXT NOT NULL,
    api_key_wrapped         BLOB NOT NULL,
    first_enrolled_at       INTEGER NOT NULL,
    last_enrolled_at        INTEGER NOT NULL,
    last_check_passed_at    INTEGER,
    last_check_failed_at    INTEGER
) STRICT;

INSERT INTO enrolled_identity_new (
    id,
    api_key_fingerprint,
    api_key_wrapped,
    first_enrolled_at,
    last_enrolled_at,
    last_check_passed_at,
    last_check_failed_at
)
SELECT
    id,
    api_key_fingerprint,
    api_key_wrapped,
    first_enrolled_at,
    last_enrolled_at,
    last_check_passed_at,
    last_check_failed_at
FROM enrolled_identity;

DROP TABLE enrolled_identity;

ALTER TABLE enrolled_identity_new RENAME TO enrolled_identity;
