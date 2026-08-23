-- Add human-readable relationship summaries to the AD asset view. These are
-- calculated at read time from the graph, so a new LDAP scan immediately
-- changes the displayed dependencies/dependents without a separate sync.
DROP VIEW IF EXISTS ad_assets;

CREATE VIEW ad_assets AS
SELECT
    n.id,
    'active_directory' AS asset_type,
    n.label AS domain_dns_name,
    n.metadata,
    n.last_seen_at,
    (
        SELECT count(*)
        FROM machine_graph_edges e
        WHERE e.to_node_id = n.id
          AND e.relation_type = 'depends_on'
    ) AS dependents_count,
    (
        SELECT group_concat(label, ', ')
        FROM (
            SELECT related.label AS label
            FROM machine_graph_edges e
            JOIN machine_graph_nodes related ON related.id = e.from_node_id
            WHERE e.to_node_id = n.id
              AND e.relation_type = 'depends_on'
            ORDER BY related.node_type, related.label
        )
    ) AS dependents,
    (
        SELECT count(*)
        FROM machine_graph_edges e
        WHERE e.from_node_id = n.id
          AND e.relation_type = 'depends_on'
    ) AS dependencies_count,
    (
        SELECT group_concat(label, ', ')
        FROM (
            SELECT related.label AS label
            FROM machine_graph_edges e
            JOIN machine_graph_nodes related ON related.id = e.to_node_id
            WHERE e.from_node_id = n.id
              AND e.relation_type = 'depends_on'
            ORDER BY related.node_type, related.label
        )
    ) AS dependencies
FROM machine_graph_nodes n
WHERE n.node_type = 'ad_domain'
  AND n.source = 'ad_derived';
