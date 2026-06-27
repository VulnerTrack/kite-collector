-- 20260503000000_scan_runs_analyzed_assets.sql: track AssetAnalyzed counts
-- per scan run so the dashboard's scan-history table can surface every event
-- state, including non-material rescans (introduced by db503fa as a separate
-- bucket from AssetUpdated).
--
-- ALTER TABLE ... ADD COLUMN is the cheap, lock-free path SQLite supports;
-- existing rows get the DEFAULT (0), which matches "this run never tracked
-- analyzed events" semantics.

ALTER TABLE scan_runs ADD COLUMN analyzed_assets INTEGER NOT NULL DEFAULT 0;
