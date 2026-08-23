-- Materialized, AD-derived relationship graph. It is a projection of the
-- collector inventory, not an operator-authored CMDB graph: every scan
-- replaces nodes and edges whose source is `ad_derived`.

CREATE TABLE IF NOT EXISTS machine_graph_nodes (
    id              TEXT PRIMARY KEY NOT NULL,
    node_type       TEXT NOT NULL CHECK(node_type IN ('machine','ad_domain','ad_ou','ad_group','operating_system')),
    label           TEXT NOT NULL,
    machine_id      TEXT REFERENCES machines(id) ON DELETE CASCADE,
    source          TEXT NOT NULL CHECK(source IN ('ad_derived')),
    metadata        TEXT NOT NULL DEFAULT '{}',
    last_seen_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_machine_graph_nodes_machine
    ON machine_graph_nodes(machine_id);
CREATE INDEX IF NOT EXISTS idx_machine_graph_nodes_type_label
    ON machine_graph_nodes(node_type, label);

CREATE TABLE IF NOT EXISTS machine_graph_edges (
    id              TEXT PRIMARY KEY NOT NULL,
    from_node_id    TEXT NOT NULL REFERENCES machine_graph_nodes(id) ON DELETE CASCADE,
    to_node_id      TEXT NOT NULL REFERENCES machine_graph_nodes(id) ON DELETE CASCADE,
    relation_type   TEXT NOT NULL CHECK(relation_type IN ('depends_on','member_of','located_in','runs')),
    source          TEXT NOT NULL CHECK(source IN ('ad_derived')),
    metadata        TEXT NOT NULL DEFAULT '{}',
    last_seen_at    TEXT NOT NULL,
    UNIQUE(from_node_id, to_node_id, relation_type, source)
);

CREATE INDEX IF NOT EXISTS idx_machine_graph_edges_from
    ON machine_graph_edges(from_node_id, relation_type);
CREATE INDEX IF NOT EXISTS idx_machine_graph_edges_to
    ON machine_graph_edges(to_node_id, relation_type);
