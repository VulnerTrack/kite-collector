package network

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/safenet"
)

// TestScanner_Discover_DeadlineExceededLogsCatalogE004 drives the scan with a
// parent context already past its deadline, so the scan's own timeout context
// reports DeadlineExceeded immediately — deterministic, no real network — and
// asserts the timeout surfaces the catalogued KITE-E004 envelope.
func TestScanner_Discover_DeadlineExceededLogsCatalogE004(t *testing.T) {
	t.Setenv("KITE_MAX_SCAN_IPS", "1024")
	t.Setenv("KITE_ALLOW_LINK_LOCAL", "false")

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	sink := newFakeSink()
	s := NewWithSink(sink, "agent-test")

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()

	_, err := s.Discover(ctx, map[string]any{
		"scope":     []any{"192.0.2.0/30"}, // TEST-NET, 4 IPs
		"tcp_ports": []any{float64(80)},
	})
	require.NoError(t, err, "a deadline yields partial results, not a hard error")

	var rec map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["error_code"] == "KITE-E004" {
			rec = m
			break
		}
	}
	require.NotNil(t, rec, "expected a KITE-E004 deadline log line")
	assert.NotEmpty(t, rec["hint"], "E004 remediation hint must be present")
}

type fakeSink struct {
	ports  map[string][]OpenPort
	scans  []ScanEvent
	guards []safenet.GuardEvent
	mu     sync.Mutex
}

func newFakeSink() *fakeSink { return &fakeSink{ports: map[string][]OpenPort{}} }

func (f *fakeSink) WriteScanEvent(_ context.Context, ev ScanEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scans = append(f.scans, ev)
	return nil
}

func (f *fakeSink) WriteOpenPorts(_ context.Context, scanID string, ps []OpenPort) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ports[scanID] = append(f.ports[scanID], ps...)
	return nil
}

func (f *fakeSink) WriteGuardEvent(_ context.Context, ev safenet.GuardEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.guards = append(f.guards, ev)
	return nil
}

func TestScanner_Discover_RejectsOversizedScope(t *testing.T) {
	t.Setenv("KITE_MAX_SCAN_IPS", "1024")
	t.Setenv("KITE_ALLOW_LINK_LOCAL", "false")

	sink := newFakeSink()
	s := NewWithSink(sink, "agent-test")

	_, err := s.Discover(context.Background(), map[string]any{
		"scope":     []any{"10.0.0.0/8"},
		"tcp_ports": []any{float64(22)},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope exceeds maximum")

	require.Len(t, sink.guards, 1)
	assert.Equal(t, safenet.GuardIPCountCap, sink.guards[0].GuardType)
	require.Len(t, sink.scans, 1)
	assert.Equal(t, "capped_ips", sink.scans[0].Outcome)
}

func TestScanner_Discover_RejectsLinkLocal(t *testing.T) {
	t.Setenv("KITE_ALLOW_LINK_LOCAL", "false")

	sink := newFakeSink()
	s := NewWithSink(sink, "agent-test")

	_, err := s.Discover(context.Background(), map[string]any{
		"scope":     []any{"169.254.169.254/32"},
		"tcp_ports": []any{float64(80)},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "link-local")

	require.Len(t, sink.guards, 1)
	assert.Equal(t, safenet.GuardSSRFScopeBlock, sink.guards[0].GuardType)
}

func TestScanner_Discover_RejectsInvalidPorts(t *testing.T) {
	sink := newFakeSink()
	s := NewWithSink(sink, "agent-test")

	_, err := s.Discover(context.Background(), map[string]any{
		"scope":     []any{"192.168.1.0/30"},
		"tcp_ports": []any{float64(0), float64(65536)},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of valid range")

	require.Len(t, sink.guards, 1)
	assert.Equal(t, safenet.GuardPortRangeViolation, sink.guards[0].GuardType)
	assert.Equal(t, "validation_error", sink.scans[0].Outcome)
}

func TestScanner_Discover_ClampsConcurrency(t *testing.T) {
	t.Setenv("KITE_MAX_SCAN_CONCURRENCY", "8")
	t.Setenv("KITE_ALLOW_LINK_LOCAL", "false")

	sink := newFakeSink()
	s := NewWithSink(sink, "agent-test")

	// Use a tiny scope that can finish without exercising the network.
	_, err := s.Discover(context.Background(), map[string]any{
		"scope":          []any{"192.0.2.0/30"},
		"tcp_ports":      []any{float64(65000)},
		"max_concurrent": float64(1024),
		"timeout":        "10ms",
		"scan_timeout":   "1s",
	})
	require.NoError(t, err)

	var sawClamp bool
	for _, g := range sink.guards {
		if g.GuardType == safenet.GuardConcurrencyCap {
			sawClamp = true
			assert.Equal(t, safenet.GuardActionCapped, g.Action)
		}
	}
	assert.True(t, sawClamp, "expected a concurrency_cap guard event")
}

func TestScanner_Discover_AllowLinkLocalConfig(t *testing.T) {
	t.Setenv("KITE_ALLOW_LINK_LOCAL", "false")

	sink := newFakeSink()
	s := NewWithSink(sink, "agent-test")

	_, err := s.Discover(context.Background(), map[string]any{
		"scope":            []any{"169.254.169.254/32"},
		"tcp_ports":        []any{float64(80)},
		"timeout":          "10ms",
		"scan_timeout":     "500ms",
		"allow_link_local": true,
	})
	require.NoError(t, err, "explicit allow_link_local should bypass the block")

	for _, g := range sink.guards {
		assert.NotEqual(t, safenet.GuardSSRFScopeBlock, g.GuardType,
			"no SSRF guard expected when operator opts in")
	}
}

func TestScanner_Name(t *testing.T) {
	assert.Equal(t, "network", New().Name())
}
