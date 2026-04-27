package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/network"
	"github.com/vulnertrack/kite-collector/internal/safenet"
)

func TestSQLiteStore_WriteScanEvent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	scanID := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Truncate(time.Second)
	completed := now.Add(2 * time.Second)
	ev := network.ScanEvent{
		ScanID:           scanID,
		AgentID:          "agent-x",
		ScopeHash:        "abc123",
		StartedAt:        now,
		CompletedAt:      &completed,
		IPsEnumerated:    254,
		IPsScanned:       254,
		IPsResponsive:    3,
		PortsProbedJSON:  `[22,80,443]`,
		Outcome:          "completed",
		SafetyGuardCount: 0,
	}
	require.NoError(t, s.WriteScanEvent(ctx, ev))

	var (
		gotScanID, gotAgent, gotOutcome string
		ipsEnum, ipsScan, ipsResp       int
	)
	row := s.db.QueryRowContext(ctx, `
		SELECT scan_id, agent_id, outcome,
			ips_enumerated, ips_scanned, ips_responsive
		FROM network_scan_events WHERE scan_id = ?`, scanID)
	require.NoError(t, row.Scan(
		&gotScanID, &gotAgent, &gotOutcome, &ipsEnum, &ipsScan, &ipsResp))
	assert.Equal(t, scanID, gotScanID)
	assert.Equal(t, "agent-x", gotAgent)
	assert.Equal(t, "completed", gotOutcome)
	assert.Equal(t, 254, ipsEnum)
	assert.Equal(t, 254, ipsScan)
	assert.Equal(t, 3, ipsResp)
}

func TestSQLiteStore_WriteScanEvent_UpsertsByScanID(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	scanID := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Truncate(time.Second)

	require.NoError(t, s.WriteScanEvent(ctx, network.ScanEvent{
		ScanID: scanID, AgentID: "a", StartedAt: now,
		Outcome: "partial", IPsScanned: 1,
	}))
	require.NoError(t, s.WriteScanEvent(ctx, network.ScanEvent{
		ScanID: scanID, AgentID: "a", StartedAt: now,
		Outcome: "completed", IPsScanned: 5, IPsResponsive: 2,
	}))

	var outcome string
	var ipsScanned, ipsResp int
	row := s.db.QueryRowContext(ctx, `
		SELECT outcome, ips_scanned, ips_responsive
		FROM network_scan_events WHERE scan_id = ?`, scanID)
	require.NoError(t, row.Scan(&outcome, &ipsScanned, &ipsResp))
	assert.Equal(t, "completed", outcome)
	assert.Equal(t, 5, ipsScanned)
	assert.Equal(t, 2, ipsResp)
}

func TestSQLiteStore_WriteScanEvent_RejectsEmptyScanID(t *testing.T) {
	s := newTestStore(t)
	err := s.WriteScanEvent(context.Background(), network.ScanEvent{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scan_id is required")
}

func TestSQLiteStore_WriteOpenPorts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	scanID := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, s.WriteScanEvent(ctx, network.ScanEvent{
		ScanID: scanID, AgentID: "agent-x", StartedAt: now,
		Outcome: "completed",
	}))

	probes := []network.OpenPort{
		{IPAddress: "10.0.0.1", Port: 22, Protocol: "tcp", ProbeAt: now},
		{IPAddress: "10.0.0.1", Port: 80, ProbeAt: now}, // protocol defaults to tcp
		{IPAddress: "10.0.0.2", Port: 443, Protocol: "tcp", ProbeAt: now},
	}
	require.NoError(t, s.WriteOpenPorts(ctx, scanID, probes))

	var count int
	row := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM network_open_ports WHERE scan_id = ?`, scanID)
	require.NoError(t, row.Scan(&count))
	assert.Equal(t, 3, count)

	var protocol string
	row = s.db.QueryRowContext(ctx,
		`SELECT protocol FROM network_open_ports WHERE scan_id = ? AND port = 80`,
		scanID)
	require.NoError(t, row.Scan(&protocol))
	assert.Equal(t, "tcp", protocol)
}

func TestSQLiteStore_WriteOpenPorts_EmptyIsNoop(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.WriteOpenPorts(
		context.Background(), uuid.Must(uuid.NewV7()).String(), nil))
}

func TestSQLiteStore_WriteOpenPorts_RejectsEmptyScanID(t *testing.T) {
	s := newTestStore(t)
	err := s.WriteOpenPorts(context.Background(), "",
		[]network.OpenPort{{IPAddress: "10.0.0.1", Port: 22}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scan_id is required")
}

func TestSQLiteStore_WriteGuardEvent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	ev := safenet.NewGuardEvent(
		safenet.GuardSSRFScopeBlock, safenet.GuardActionRejected,
		"network.scanner", "scope=[169.254.169.254/32]", `{"cidr":"169.254.169.254/32"}`)
	ev.ScanID = "scan-xyz"

	require.NoError(t, s.WriteGuardEvent(ctx, ev))

	var (
		gtype, action, source, summary, details string
		scanID                                  *string
	)
	row := s.db.QueryRowContext(ctx, `
		SELECT guard_type, action_taken, source_component,
			input_summary, details_json, scan_id
		FROM safety_guard_events`)
	require.NoError(t, row.Scan(
		&gtype, &action, &source, &summary, &details, &scanID))
	assert.Equal(t, "ssrf_scope_block", gtype)
	assert.Equal(t, "rejected", action)
	assert.Equal(t, "network.scanner", source)
	assert.Equal(t, "scope=[169.254.169.254/32]", summary)
	assert.Equal(t, `{"cidr":"169.254.169.254/32"}`, details)
	require.NotNil(t, scanID)
	assert.Equal(t, "scan-xyz", *scanID)
}

func TestSQLiteStore_WriteGuardEvent_NullScanID(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	ev := safenet.NewGuardEvent(
		safenet.GuardPaginationByteCap, safenet.GuardActionRejected,
		"connector.vps.hetzner", "page=42 bytes=11534336", "")
	require.NoError(t, s.WriteGuardEvent(ctx, ev))

	var scanID *string
	row := s.db.QueryRowContext(ctx,
		`SELECT scan_id FROM safety_guard_events`)
	require.NoError(t, row.Scan(&scanID))
	assert.Nil(t, scanID, "guard fired outside a scan should leave scan_id NULL")
}

func TestSQLiteStore_GuardEventCheckConstraintRejectsUnknownGuardType(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	id := uuid.Must(uuid.NewV7()).String()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO safety_guard_events
			(id, guard_type, action_taken, triggered_at, source_component)
		VALUES (?, 'totally_made_up', 'rejected', ?, 'test')
	`, id, time.Now().UTC().Format(time.RFC3339Nano))
	require.Error(t, err, "CHECK constraint should block unknown guard types")
}
