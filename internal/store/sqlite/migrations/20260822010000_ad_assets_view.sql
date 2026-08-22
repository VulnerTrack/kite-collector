-- The collector inventory uses the term "machines" for physical/virtual
-- endpoints. This read-only view exposes the logical AD service as an asset
-- without duplicating or operator-authoring records. Every row is rebuilt
-- from LDAP-derived graph nodes after a scan.
CREATE VIEW IF NOT EXISTS ad_assets AS
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
        SELECT count(*)
        FROM machine_graph_edges e
        WHERE e.from_node_id = n.id
          AND e.relation_type = 'depends_on'
    ) AS dependencies_count
FROM machine_graph_nodes n
WHERE n.node_type = 'ad_domain'
  AND n.source = 'ad_derived';
