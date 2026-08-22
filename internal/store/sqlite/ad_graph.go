package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
	"github.com/vulnertrack/kite-collector/internal/telemetry/contract"
)

var _ store.MachineGraphStore = (*SQLiteStore)(nil)
var _ store.DirectorySoftwareStore = (*SQLiteStore)(nil)

// RebuildADMachineGraph materializes an auditable graph from AD machine
// discovery. The graph deliberately uses the collector's normalized machine
// inventory as its source of truth: a later LDAP scan replaces old edges
// rather than leaving stale group, OU, or domain relationships behind.
func (s *SQLiteStore) RebuildADMachineGraph(ctx context.Context) error {
	machines, err := s.ListMachines(ctx, store.MachineFilter{})
	if err != nil {
		return fmt.Errorf("ad graph: list machines: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("ad graph: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM machine_graph_nodes WHERE source = 'ad_derived'`); err != nil {
		return fmt.Errorf("ad graph: clear previous projection: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	materialized := 0
	for _, machine := range machines {
		if !hasADDomainTag(machine.Tags) {
			continue
		}
		if err := materializeADMachine(ctx, tx, machine, now); err != nil {
			return err
		}
		materialized++
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ad graph: commit: %w", err)
	}
	slog.Info("AD machine graph rebuilt", "ad_machines", materialized)
	return nil
}

func hasADDomainTag(tagsJSON string) bool {
	if strings.TrimSpace(tagsJSON) == "" {
		return false
	}
	var tags map[string]json.RawMessage
	return json.Unmarshal([]byte(tagsJSON), &tags) == nil && graphTagString(tags, contract.AttrADDomainDNSName) != ""
}

func materializeADMachine(ctx context.Context, tx *sql.Tx, machine model.Machine, seenAt string) error {
	if strings.TrimSpace(machine.Tags) == "" {
		return nil
	}
	var tags map[string]json.RawMessage
	if err := json.Unmarshal([]byte(machine.Tags), &tags); err != nil {
		return fmt.Errorf("ad graph: decode tags for %s: %w", machine.ID, err)
	}
	domain := graphTagString(tags, contract.AttrADDomainDNSName)
	if domain == "" {
		return nil // An LDAP record without a domain cannot form an AD graph edge.
	}

	machineID := "machine:" + machine.ID.String()
	if err := upsertGraphNode(ctx, tx, machineID, "machine", machine.Hostname, machine.ID.String(), graphMetadata(map[string]any{
		"asset_type":   "machine",
		"machine_type": machine.MachineType,
		"hostname":     machine.Hostname,
		"ad_uac_flags": graphTagUint(tags, contract.AttrADUACFlags),
	}), seenAt); err != nil {
		return err
	}
	domainID := graphID("ad_domain", domain)
	if err := upsertGraphNode(ctx, tx, domainID, "ad_domain", domain, "", graphMetadata(map[string]any{
		"asset_type":      "software",
		"software_kind":   "directory_service",
		"domain_dns_name": domain,
	}), seenAt); err != nil {
		return err
	}
	// A computer account requires the directory domain to authenticate and
	// apply directory policy. Inbound edges on the domain are therefore its
	// dependents; walking a computer also exposes its directory dependency.
	if err := upsertGraphEdge(ctx, tx, machineID, domainID, "depends_on", seenAt); err != nil {
		return err
	}

	if machine.OSFamily != "" || machine.OSVersion != "" {
		osLabel := strings.TrimSpace(strings.TrimSpace(machine.OSFamily) + " " + strings.TrimSpace(machine.OSVersion))
		osID := graphID("operating_system", osLabel)
		if err := upsertGraphNode(ctx, tx, osID, "operating_system", osLabel, "", graphMetadata(map[string]any{
			"asset_type": "operating_system",
		}), seenAt); err != nil {
			return err
		}
		if err := upsertGraphEdge(ctx, tx, machineID, osID, "runs", seenAt); err != nil {
			return err
		}
	}

	if ou := graphTagString(tags, contract.AttrADOUPath); ou != "" {
		ouID := graphID("ad_ou", ou)
		if err := upsertGraphNode(ctx, tx, ouID, "ad_ou", ou, "", graphMetadata(map[string]any{
			"asset_type":         "directory_configuration",
			"domain_dns_name":    domain,
			"distinguished_name": ou,
		}), seenAt); err != nil {
			return err
		}
		if err := upsertGraphEdge(ctx, tx, ouID, domainID, "depends_on", seenAt); err != nil {
			return err
		}
		if err := upsertGraphEdge(ctx, tx, machineID, ouID, "located_in", seenAt); err != nil {
			return err
		}
	}

	for _, group := range graphTagStrings(tags, contract.AttrADGroups) {
		groupID := graphID("ad_group", group)
		if err := upsertGraphNode(ctx, tx, groupID, "ad_group", group, "", graphMetadata(map[string]any{
			"asset_type":         "directory_group",
			"domain_dns_name":    domain,
			"distinguished_name": group,
		}), seenAt); err != nil {
			return err
		}
		if err := upsertGraphEdge(ctx, tx, groupID, domainID, "depends_on", seenAt); err != nil {
			return err
		}
		if err := upsertGraphEdge(ctx, tx, machineID, groupID, "member_of", seenAt); err != nil {
			return err
		}
	}
	return nil
}

func upsertGraphNode(ctx context.Context, tx *sql.Tx, id, nodeType, label, machineID, metadata, seenAt string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO machine_graph_nodes (id, node_type, label, machine_id, source, metadata, last_seen_at)
		VALUES (?, ?, ?, NULLIF(?, ''), 'ad_derived', ?, ?)
	`, id, nodeType, label, machineID, metadata, seenAt)
	if err != nil {
		return fmt.Errorf("ad graph: insert %s node %q: %w", nodeType, label, err)
	}
	return nil
}

func graphMetadata(values map[string]any) string {
	encoded, err := json.Marshal(values)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func upsertGraphEdge(ctx context.Context, tx *sql.Tx, fromID, toID, relation, seenAt string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO machine_graph_edges (id, from_node_id, to_node_id, relation_type, source, last_seen_at)
		VALUES (?, ?, ?, ?, 'ad_derived', ?)
	`, graphID("edge", fromID, toID, relation), fromID, toID, relation, seenAt)
	if err != nil {
		return fmt.Errorf("ad graph: insert %s edge: %w", relation, err)
	}
	return nil
}

func graphTagString(tags map[string]json.RawMessage, key string) string {
	var value string
	if err := json.Unmarshal(tags[key], &value); err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func graphTagStrings(tags map[string]json.RawMessage, key string) []string {
	var values []string
	if err := json.Unmarshal(tags[key], &values); err != nil {
		return nil
	}
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			unique[value] = struct{}{}
		}
	}
	values = values[:0]
	for value := range unique {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func graphTagUint(tags map[string]json.RawMessage, key string) uint32 {
	var value uint32
	if err := json.Unmarshal(tags[key], &value); err != nil {
		return 0
	}
	return value
}

// ListDirectorySoftware returns one service row for each AD domain controller.
// SERVER_TRUST_ACCOUNT (0x2000) marks a domain controller in AD.
func (s *SQLiteStore) ListDirectorySoftware(ctx context.Context) ([]store.DirectorySoftware, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT m.machine_id, d.label, '',
		       trim(m.label || CASE WHEN os.label IS NOT NULL THEN ', ' || os.label ELSE '' END),
		       COALESCE((
			   SELECT group_concat(label, ', ')
			   FROM (
			       SELECT related.label AS label
			       FROM machine_graph_edges incoming
			       JOIN machine_graph_nodes related ON related.id = incoming.from_node_id
			       WHERE incoming.to_node_id = d.id
			         AND incoming.relation_type = 'depends_on'
			       ORDER BY related.node_type, related.label
			   )
		       ), '')
		FROM machine_graph_nodes m
		JOIN machine_graph_edges e ON e.from_node_id = m.id AND e.relation_type = 'depends_on'
		JOIN machine_graph_nodes d ON d.id = e.to_node_id AND d.node_type = 'ad_domain'
		LEFT JOIN machine_graph_edges runs ON runs.from_node_id = m.id AND runs.relation_type = 'runs'
		LEFT JOIN machine_graph_nodes os ON os.id = runs.to_node_id
		WHERE m.node_type = 'machine'
		  AND (CAST(COALESCE(json_extract(m.metadata, '$.ad_uac_flags'), 0) AS INTEGER) & 8192) != 0
		ORDER BY d.label, m.label
	`)
	if err != nil {
		return nil, fmt.Errorf("list directory software: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []store.DirectorySoftware
	for rows.Next() {
		var machineID string
		var item store.DirectorySoftware
		if err := rows.Scan(&machineID, &item.DomainDNSName, &item.Version, &item.Dependencies, &item.Dependents); err != nil {
			return nil, fmt.Errorf("scan directory software: %w", err)
		}
		var parseErr error
		item.MachineID, parseErr = uuid.Parse(machineID)
		if parseErr != nil {
			return nil, fmt.Errorf("parse directory software machine id: %w", parseErr)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate directory software: %w", err)
	}
	return result, nil
}

func graphID(parts ...string) string {
	normalized := make([]string, len(parts))
	for i, part := range parts {
		normalized[i] = strings.ToLower(strings.TrimSpace(part))
	}
	sum := sha256.Sum256([]byte(strings.Join(normalized, "\x1f")))
	return fmt.Sprintf("graph:%x", sum)
}
