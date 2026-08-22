package sqlite

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/telemetry/contract"
)

func TestRebuildADMachineGraph_MaterializesDependenciesAndMembership(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	tags, err := json.Marshal(map[string]any{
		contract.AttrADDomainDNSName: "corp.example.test",
		contract.AttrADOUPath:        "OU=Servers,DC=corp,DC=example,DC=test",
		contract.AttrADGroups: []string{
			"CN=Tier 0,OU=Groups,DC=corp,DC=example,DC=test",
			"CN=Servers,OU=Groups,DC=corp,DC=example,DC=test",
		},
	})
	require.NoError(t, err)
	machine := makeMachine("dc-01.corp.example.test", model.MachineTypeServer)
	// AD facts can survive deduplication even when a separate source (such as
	// NetBIOS) owns the machine's discovery_source label.
	machine.DiscoverySource = "netbios"
	machine.OSFamily = "windows"
	machine.OSVersion = "Windows Server 2025"
	machine.Tags = string(tags)
	require.NoError(t, s.UpsertMachine(ctx, machine))

	require.NoError(t, s.RebuildADMachineGraph(ctx))

	var nodes, edges int
	require.NoError(t, s.db.QueryRowContext(ctx, `SELECT count(*) FROM machine_graph_nodes`).Scan(&nodes))
	require.NoError(t, s.db.QueryRowContext(ctx, `SELECT count(*) FROM machine_graph_edges`).Scan(&edges))
	assert.Equal(t, 6, nodes, "machine, domain, OS, OU, and two groups")
	assert.Equal(t, 8, edges, "machine dependencies plus OU/group directory dependencies")

	var gotMachineID, gotType string
	require.NoError(t, s.db.QueryRowContext(ctx, `
		SELECT machine_id, node_type FROM machine_graph_nodes WHERE label = ?
	`, machine.Hostname).Scan(&gotMachineID, &gotType))
	assert.Equal(t, machine.ID.String(), gotMachineID)
	assert.Equal(t, "machine", gotType)

	var relationCount int
	require.NoError(t, s.db.QueryRowContext(ctx, `
		SELECT count(*) FROM machine_graph_edges WHERE relation_type = 'member_of'
	`).Scan(&relationCount))
	assert.Equal(t, 2, relationCount)

	var assetType string
	require.NoError(t, s.db.QueryRowContext(ctx, `
		SELECT json_extract(metadata, '$.asset_type')
		FROM machine_graph_nodes
		WHERE node_type = 'ad_domain'
	`).Scan(&assetType))
	assert.Equal(t, "software", assetType)
}

func TestRebuildADMachineGraph_ReplacesStaleProjection(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	tags, err := json.Marshal(map[string]any{
		contract.AttrADDomainDNSName: "old.example.test",
	})
	require.NoError(t, err)
	machine := makeMachine("member-01.old.example.test", model.MachineTypeWorkstation)
	machine.DiscoverySource = "ldap"
	machine.Tags = string(tags)
	require.NoError(t, s.UpsertMachine(ctx, machine))
	require.NoError(t, s.RebuildADMachineGraph(ctx))

	machine.Tags = `{"ad.domain_dns_name":"new.example.test"}`
	require.NoError(t, s.UpsertMachine(ctx, machine))
	require.NoError(t, s.RebuildADMachineGraph(ctx))

	var oldDomainNodes, newDomainNodes int
	require.NoError(t, s.db.QueryRowContext(ctx, `
		SELECT count(*) FROM machine_graph_nodes WHERE node_type = 'ad_domain' AND label = 'old.example.test'
	`).Scan(&oldDomainNodes))
	require.NoError(t, s.db.QueryRowContext(ctx, `
		SELECT count(*) FROM machine_graph_nodes WHERE node_type = 'ad_domain' AND label = 'new.example.test'
	`).Scan(&newDomainNodes))
	assert.Zero(t, oldDomainNodes)
	assert.Equal(t, 1, newDomainNodes)
}
