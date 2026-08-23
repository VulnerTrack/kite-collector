-- Relationship rows for directory software. This is deliberately a view over
-- the AD graph: the dashboard always reflects the most recent LDAP scan and
-- never receives manually duplicated relationship records.
CREATE VIEW IF NOT EXISTS directory_software_relationships AS
SELECT
    d.id AS service_id,
    'Active Directory Domain Services' AS service_name,
    d.label AS domain_dns_name,
    'requires' AS relationship_set,
    'machine' AS related_type,
    m.label AS related_name,
    'runs_on' AS relationship_type
FROM machine_graph_nodes m
JOIN machine_graph_edges domain_edge
  ON domain_edge.from_node_id = m.id
 AND domain_edge.relation_type = 'depends_on'
JOIN machine_graph_nodes d
  ON d.id = domain_edge.to_node_id
 AND d.node_type = 'ad_domain'
WHERE m.node_type = 'machine'
  AND (CAST(COALESCE(json_extract(m.metadata, '$.ad_uac_flags'), 0) AS INTEGER) & 8192) != 0

UNION ALL

SELECT
    d.id AS service_id,
    'Active Directory Domain Services' AS service_name,
    d.label AS domain_dns_name,
    'requires' AS relationship_set,
    os.node_type AS related_type,
    os.label AS related_name,
    'runs_on' AS relationship_type
FROM machine_graph_nodes m
JOIN machine_graph_edges domain_edge
  ON domain_edge.from_node_id = m.id
 AND domain_edge.relation_type = 'depends_on'
JOIN machine_graph_nodes d
  ON d.id = domain_edge.to_node_id
 AND d.node_type = 'ad_domain'
JOIN machine_graph_edges os_edge
  ON os_edge.from_node_id = m.id
 AND os_edge.relation_type = 'runs'
JOIN machine_graph_nodes os ON os.id = os_edge.to_node_id
WHERE m.node_type = 'machine'
  AND (CAST(COALESCE(json_extract(m.metadata, '$.ad_uac_flags'), 0) AS INTEGER) & 8192) != 0

UNION ALL

SELECT
    d.id AS service_id,
    'Active Directory Domain Services' AS service_name,
    d.label AS domain_dns_name,
    'associated' AS relationship_set,
    related.node_type AS related_type,
    related.label AS related_name,
    incoming.relation_type AS relationship_type
FROM machine_graph_nodes d
JOIN machine_graph_edges incoming
  ON incoming.to_node_id = d.id
 AND incoming.relation_type = 'depends_on'
JOIN machine_graph_nodes related ON related.id = incoming.from_node_id
WHERE d.node_type = 'ad_domain';
