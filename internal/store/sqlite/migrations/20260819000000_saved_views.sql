-- saved_views: user-defined two-table join views built in the dashboard's
-- view builder (RFC-less dashboard redesign work). The join definition is
-- stored structurally — tables, join type, ON columns, and a JSON column
-- projection — never as raw SQL: the introspection layer re-validates every
-- identifier against the live catalog on each render.
CREATE TABLE IF NOT EXISTS saved_views (
    id          TEXT PRIMARY KEY NOT NULL,
    name        TEXT NOT NULL UNIQUE,
    slug        TEXT NOT NULL UNIQUE,
    base_table  TEXT NOT NULL,
    join_table  TEXT NOT NULL,
    join_type   TEXT NOT NULL CHECK (join_type IN ('inner', 'left')),
    on_base     TEXT NOT NULL,
    on_join     TEXT NOT NULL,
    columns     TEXT NOT NULL, -- JSON array of {"table": ..., "column": ...}
    created_at  TEXT NOT NULL
);
