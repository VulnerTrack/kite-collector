package osquery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// stubQuerier answers queries by longest-matching table keyword. err entries
// simulate daemon-side failures per table.
type stubQuerier struct {
	responses map[string][]map[string]string
	errs      map[string]error
	queries   []string
	pingErr   error
}

func (s *stubQuerier) Query(_ context.Context, sql string) ([]map[string]string, error) {
	s.queries = append(s.queries, sql)
	// Longest matching keyword wins so a specific key (e.g. the daemon-binary
	// self-lookup "FROM processes p, osquery_info i") beats a broader one it
	// happens to contain ("osquery_info"). Without this, map iteration order
	// makes the match non-deterministic when several keys are substrings.
	if kw := longestMatch(sql, s.errs); kw != "" {
		return nil, s.errs[kw]
	}
	if kw := longestMatchRows(sql, s.responses); kw != "" {
		return s.responses[kw], nil
	}
	return nil, nil
}

func longestMatch(sql string, m map[string]error) string {
	best := ""
	for kw := range m {
		if strings.Contains(sql, kw) && len(kw) > len(best) {
			best = kw
		}
	}
	return best
}

func longestMatchRows(sql string, m map[string][]map[string]string) string {
	best, found := "", false
	for kw := range m {
		if strings.Contains(sql, kw) && (!found || len(kw) > len(best)) {
			best, found = kw, true
		}
	}
	if !found {
		return ""
	}
	return best
}

func (s *stubQuerier) Ping(context.Context) error { return s.pingErr }

// healthyStub returns a stub that answers the identity tables like the sim's
// osqueryd does.
func healthyStub() *stubQuerier {
	return &stubQuerier{
		responses: map[string][]map[string]string{
			"osquery_info": {{"version": "5.15.0", "build_platform": "ubuntu20.04", "pid": "1"}},
			"system_info": {{
				"hostname": "sim-host", "uuid": "9c0d0e6a-1111-2222-3333-444455556666",
				"hardware_vendor": "QEMU", "hardware_model": "Standard PC",
				"cpu_type": "x86_64", "physical_memory": "2147483648",
			}},
			"os_version":  {{"name": "Ubuntu", "version": "24.04.2 LTS (Noble Numbat)", "platform": "ubuntu", "platform_like": "debian", "arch": "x86_64"}},
			"kernel_info": {{"version": "6.8.0-51-generic"}},
		},
		errs: map[string]error{},
	}
}

// sourceWith returns a Source whose client factory always yields q, plus a
// cfg with an explicit socket so env/auto-detection never interferes.
func sourceWith(q querier) (*Source, map[string]any) {
	s := &Source{newClient: func(string) querier { return q }}
	return s, map[string]any{"socket": "/tmp/test.em"}
}

func tagsOf(t *testing.T, m model.Machine) map[string]any {
	t.Helper()
	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(m.Tags), &tags))
	return tags
}

// ---------------------------------------------------------------------------
// Discover — happy path
// ---------------------------------------------------------------------------

func TestDiscover_HappyPath_OneMachine(t *testing.T) {
	s, cfg := sourceWith(healthyStub())
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, machines, 1)
}

func TestDiscover_MapsIdentityFields(t *testing.T) {
	s, cfg := sourceWith(healthyStub())
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	m := machines[0]
	assert.Equal(t, "sim-host", m.Hostname)
	assert.Equal(t, "linux", m.OSFamily)
	assert.Equal(t, "Ubuntu 24.04.2 LTS (Noble Numbat)", m.OSVersion)
	assert.Equal(t, "6.8.0-51-generic", m.KernelVersion)
	assert.Equal(t, "x86_64", m.Architecture)
	assert.Equal(t, "osquery", m.DiscoverySource)
	assert.Equal(t, model.MachineTypeServer, m.MachineType)
	assert.Equal(t, model.AuthorizationUnknown, m.IsAuthorized)
	assert.Equal(t, model.ManagedUnknown, m.IsManaged)
	assert.NotEqual(t, "", m.ID.String())
}

func TestDiscover_TagsCarryOsqueryIdentity(t *testing.T) {
	s, cfg := sourceWith(healthyStub())
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	assert.Equal(t, "5.15.0", tags["osquery_version"])
	assert.Equal(t, "ubuntu20.04", tags["build_platform"])
	assert.Equal(t, "9c0d0e6a-1111-2222-3333-444455556666", tags["hardware_uuid"])
	assert.Equal(t, "QEMU", tags["hardware_vendor"])
	assert.Equal(t, "Standard PC", tags["hardware_model"])
	// cpu_type and physical_memory are fetched by the system_info query and
	// must be surfaced, not discarded.
	assert.Equal(t, "x86_64", tags["cpu_type"])
	assert.Equal(t, float64(2147483648), tags["physical_memory_bytes"])
}

func TestDiscover_PartialSystemInfo_OmitsEmptyHardwareTags(t *testing.T) {
	// A daemon that returns system_info without hardware fields (VMs,
	// containers) must not emit empty/zero tags for them.
	stub := healthyStub()
	stub.responses["system_info"] = []map[string]string{{
		"hostname": "vm-01", "uuid": "", "hardware_vendor": "",
		"hardware_model": "", "cpu_type": "", "physical_memory": "0",
	}}
	s, cfg := sourceWith(stub)
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	for _, k := range []string{"hardware_uuid", "hardware_vendor", "hardware_model", "cpu_type", "physical_memory_bytes"} {
		_, present := tags[k]
		assert.False(t, present, "empty/zero %q must be omitted, not tagged", k)
	}
}

func TestDiscover_TimestampsAreUTCAndRecent(t *testing.T) {
	s, cfg := sourceWith(healthyStub())
	before := time.Now().UTC().Add(-time.Minute)
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	m := machines[0]
	assert.True(t, m.FirstSeenAt.After(before))
	assert.Equal(t, m.FirstSeenAt, m.LastSeenAt)
}

func TestDiscover_NoYaraConfigured_NoYaraTags(t *testing.T) {
	s, cfg := sourceWith(healthyStub())
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	_, present := tags["yara_scanned"]
	assert.False(t, present, "yara tags must not appear when yara is not configured")
}

func TestDiscover_FileEventsCountTagged(t *testing.T) {
	stub := healthyStub()
	stub.responses["file_events"] = []map[string]string{
		{"target_path": "/etc/passwd", "category": "kite_fim", "action": "UPDATED", "sha256": "aa", "time": "1700000000"},
		{"target_path": "/etc/shadow", "category": "kite_fim", "action": "UPDATED", "sha256": "bb", "time": "1700000001"},
	}
	s, cfg := sourceWith(stub)
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	assert.Equal(t, float64(2), tags["file_events_recent"])
	// No events_expiry flag response -> honest default window, not a bogus 24h.
	assert.Equal(t, float64(3600), tags["file_events_window_secs"])
	_, old := tags["file_events_24h"]
	assert.False(t, old, "the misleading 24h tag must be gone")
}

func TestDiscover_FileEventsWindow_UsesDaemonEventsExpiry(t *testing.T) {
	stub := healthyStub()
	stub.responses["events_expiry"] = []map[string]string{{"value": "600"}}
	s, cfg := sourceWith(stub)
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	assert.Equal(t, float64(600), tags["file_events_window_secs"],
		"the window must track the daemon's events_expiry, not a hardcoded value")
	// And the file_events query must have used the matching floor.
	var feSQL string
	for _, q := range stub.queries {
		if strings.Contains(q, "FROM file_events") {
			feSQL = q
		}
	}
	require.NotEmpty(t, feSQL)
	assert.Contains(t, feSQL, "time > ", "the query must carry a time constraint (disables events_optimize differential)")
}

func TestEventsExpiryWindow_FallsBackOnMissingOrBadFlag(t *testing.T) {
	// Flag absent -> default.
	stub := healthyStub()
	assert.Equal(t, int64(3600), eventsExpiryWindow(context.Background(), stub))
	// Flag present but non-positive -> default.
	stub2 := healthyStub()
	stub2.responses["events_expiry"] = []map[string]string{{"value": "0"}}
	assert.Equal(t, int64(3600), eventsExpiryWindow(context.Background(), stub2))
	// Flag query errors -> default.
	stub3 := healthyStub()
	stub3.errs["events_expiry"] = errors.New("flags table wedged")
	assert.Equal(t, int64(3600), eventsExpiryWindow(context.Background(), stub3))
}

func TestName_IsStable(t *testing.T) {
	assert.Equal(t, "osquery", New().Name())
}

func TestNew_UsesRealClientFactory(t *testing.T) {
	s := New()
	require.NotNil(t, s.newClient)
	c := s.newClient("/tmp/x.em")
	assert.IsType(t, &Client{}, c)
}

// ---------------------------------------------------------------------------
// Discover — empty / error states
// ---------------------------------------------------------------------------

func TestDiscover_NoSocketAnywhere_Errors(t *testing.T) {
	t.Setenv("KITE_OSQUERY_SOCKET", "")
	if detectSocket() != "" {
		t.Skip("host has a real osqueryd socket; cannot exercise the not-found path")
	}
	s := &Source{newClient: func(string) querier { return healthyStub() }}
	_, err := s.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_OSQUERY_SOCKET")
}

func TestDiscover_OsqueryInfoTransportError_Fails(t *testing.T) {
	stub := healthyStub()
	stub.errs["osquery_info"] = errors.New("dial unix: connection refused")
	s, cfg := sourceWith(stub)
	_, err := s.Discover(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "osquery_info")
}

func TestDiscover_OsqueryInfoEmpty_FailsLoudly(t *testing.T) {
	// A daemon that answers but returns no identity row is garbage — the
	// checks battery treats this as its own failure mode, and so do we.
	stub := healthyStub()
	stub.responses["osquery_info"] = nil
	s, cfg := sourceWith(stub)
	_, err := s.Discover(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no osquery_info row")
}

func TestDiscover_SystemInfoFails_MachineStillBuilt(t *testing.T) {
	stub := healthyStub()
	stub.errs["system_info"] = errors.New("table wedged")
	s, cfg := sourceWith(stub)
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err, "identity-table degradation must not abort discovery")
	assert.Equal(t, "", machines[0].Hostname)
	assert.Equal(t, "linux", machines[0].OSFamily, "os_version still answered")
}

func TestDiscover_OSVersionFails_MachineStillBuilt(t *testing.T) {
	stub := healthyStub()
	stub.errs["os_version"] = errors.New("table wedged")
	s, cfg := sourceWith(stub)
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "", machines[0].OSFamily)
	assert.Equal(t, "sim-host", machines[0].Hostname)
}

func TestDiscover_KernelInfoFails_MachineStillBuilt(t *testing.T) {
	stub := healthyStub()
	stub.errs["kernel_info"] = errors.New("table wedged")
	s, cfg := sourceWith(stub)
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "", machines[0].KernelVersion)
}

func TestDiscover_FileEventsError_TagAbsentButDiscoverSucceeds(t *testing.T) {
	stub := healthyStub()
	stub.errs["file_events"] = errors.New("events disabled")
	s, cfg := sourceWith(stub)
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	_, present := tags["file_events_24h"]
	assert.False(t, present)
}

// ---------------------------------------------------------------------------
// YARA — the silent-zero contract enforced at the source layer
// ---------------------------------------------------------------------------

func yaraCfg(paths ...string) map[string]any {
	anyPaths := make([]any, len(paths))
	for i, p := range paths {
		anyPaths[i] = p
	}
	return map[string]any{
		"socket":       "/tmp/test.em",
		"yara_sigfile": "/etc/osquery/yara/kite.yar",
		"yara_paths":   anyPaths,
	}
}

func TestYara_SigfileVisible_MatchesCollected(t *testing.T) {
	stub := healthyStub()
	stub.responses["FROM file"] = []map[string]string{{"path": "/etc/osquery/yara/kite.yar"}}
	stub.responses["FROM yara"] = []map[string]string{
		{"path": "/opt/payload.bin", "matches": "kite_sim_canary", "count": "1"},
	}
	s, _ := sourceWith(stub)
	machines, err := s.Discover(context.Background(), yaraCfg("/opt/payload.bin"))
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	assert.Equal(t, true, tags["yara_scanned"])
	assert.Equal(t, float64(1), tags["yara_match_count"])
	require.NotNil(t, tags["yara_matches"])
}

func TestYara_CleanScan_ZeroMatchesButScannedTrue(t *testing.T) {
	stub := healthyStub()
	stub.responses["FROM file"] = []map[string]string{{"path": "/etc/osquery/yara/kite.yar"}}
	stub.responses["FROM yara"] = []map[string]string{
		{"path": "/opt/clean.txt", "matches": "", "count": "0"},
	}
	s, _ := sourceWith(stub)
	machines, err := s.Discover(context.Background(), yaraCfg("/opt/clean.txt"))
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	assert.Equal(t, true, tags["yara_scanned"])
	assert.Equal(t, float64(0), tags["yara_match_count"])
	_, hasMatches := tags["yara_matches"]
	assert.False(t, hasMatches)
}

func TestYara_SigfileInvisible_ScanSkippedNotReportedClean(t *testing.T) {
	// THE trap from the edge battery: an invisible sigfile scans "clean".
	// The source must refuse to claim a scan happened.
	stub := healthyStub()
	stub.responses["FROM file"] = nil // daemon cannot see the sigfile
	stub.responses["FROM yara"] = []map[string]string{
		{"path": "/opt/payload.bin", "matches": "", "count": "0"}, // the lie
	}
	s, _ := sourceWith(stub)
	machines, err := s.Discover(context.Background(), yaraCfg("/opt/payload.bin"))
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	_, scanned := tags["yara_scanned"]
	assert.False(t, scanned, "an unprovable sigfile must not produce a 'scanned' result")
}

func TestYara_SigfileProbeError_ScanSkipped(t *testing.T) {
	stub := healthyStub()
	stub.errs["FROM file"] = errors.New("file table wedged")
	s, _ := sourceWith(stub)
	machines, err := s.Discover(context.Background(), yaraCfg("/opt/payload.bin"))
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	_, scanned := tags["yara_scanned"]
	assert.False(t, scanned)
}

func TestYara_OnePathFailsOthersStillScan(t *testing.T) {
	stub := healthyStub()
	stub.responses["FROM file"] = []map[string]string{{"path": "/etc/osquery/yara/kite.yar"}}
	calls := 0
	inner := stub
	s := &Source{newClient: func(string) querier {
		return querierFunc(func(ctx context.Context, sql string) ([]map[string]string, error) {
			if strings.Contains(sql, "FROM yara") {
				calls++
				if calls == 1 {
					return nil, errors.New("first path errors")
				}
				return []map[string]string{{"path": "/two", "matches": "kite_sim_canary", "count": "2"}}, nil
			}
			return inner.Query(ctx, sql)
		})
	}}
	machines, err := s.Discover(context.Background(), yaraCfg("/one", "/two"))
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	assert.Equal(t, true, tags["yara_scanned"])
	assert.Equal(t, float64(1), tags["yara_match_count"])
}

func TestYara_NoPaths_NotScanned(t *testing.T) {
	stub := healthyStub()
	s, _ := sourceWith(stub)
	cfg := map[string]any{"socket": "/tmp/test.em", "yara_sigfile": "/rules.yar"}
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	_, scanned := tagsOf(t, machines[0])["yara_scanned"]
	assert.False(t, scanned)
}

func TestYara_NoSigfile_NotScanned(t *testing.T) {
	stub := healthyStub()
	s, _ := sourceWith(stub)
	cfg := map[string]any{"socket": "/tmp/test.em", "yara_paths": []any{"/x"}}
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	_, scanned := tagsOf(t, machines[0])["yara_scanned"]
	assert.False(t, scanned)
}

func TestYara_PathsEscapedInSQL(t *testing.T) {
	stub := healthyStub()
	stub.responses["FROM file"] = []map[string]string{{"path": "x"}}
	s, _ := sourceWith(stub)
	_, err := s.Discover(context.Background(), yaraCfg("/tmp/o'brien.txt"))
	require.NoError(t, err)
	var yaraSQL string
	for _, q := range stub.queries {
		if strings.Contains(q, "FROM yara") {
			yaraSQL = q
		}
	}
	require.NotEmpty(t, yaraSQL)
	assert.Contains(t, yaraSQL, "o''brien", "single quotes must be doubled")
	assert.NotContains(t, yaraSQL, "o'brien.txt'", "unescaped quote must not survive")
}

// querierFunc adapts a func to the querier interface.
type querierFunc func(ctx context.Context, sql string) ([]map[string]string, error)

func (f querierFunc) Query(ctx context.Context, sql string) ([]map[string]string, error) {
	return f(ctx, sql)
}
func (f querierFunc) Ping(context.Context) error { return nil }

// ---------------------------------------------------------------------------
// FileEvents
// ---------------------------------------------------------------------------

func TestFileEvents_MapsRows(t *testing.T) {
	stub := healthyStub()
	stub.responses["file_events"] = []map[string]string{
		{"target_path": "/w/fim/a.txt", "category": "kite_fim", "action": "CREATED", "sha256": "cafe", "time": "1754955600"},
	}
	s, cfg := sourceWith(stub)
	events, err := s.FileEvents(context.Background(), cfg, 0)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "/w/fim/a.txt", events[0].TargetPath)
	assert.Equal(t, "CREATED", events[0].Action)
	assert.Equal(t, "cafe", events[0].SHA256)
	assert.Equal(t, int64(1754955600), events[0].Time)
}

func TestFileEvents_Empty(t *testing.T) {
	s, cfg := sourceWith(healthyStub())
	events, err := s.FileEvents(context.Background(), cfg, 0)
	require.NoError(t, err)
	assert.Empty(t, events)
}

func TestFileEvents_QueryError(t *testing.T) {
	stub := healthyStub()
	stub.errs["file_events"] = errors.New("events disabled")
	s, cfg := sourceWith(stub)
	_, err := s.FileEvents(context.Background(), cfg, 0)
	require.Error(t, err)
}

func TestFileEvents_SinceClauseInSQL(t *testing.T) {
	stub := healthyStub()
	s, cfg := sourceWith(stub)
	_, err := s.FileEvents(context.Background(), cfg, 1754955600)
	require.NoError(t, err)
	var sql string
	for _, q := range stub.queries {
		if strings.Contains(q, "file_events") {
			sql = q
		}
	}
	assert.Contains(t, sql, "time > 1754955600")
}

func TestFileEvents_NoSocket_Errors(t *testing.T) {
	t.Setenv("KITE_OSQUERY_SOCKET", "")
	if detectSocket() != "" {
		t.Skip("host has a real osqueryd socket")
	}
	s := &Source{newClient: func(string) querier { return healthyStub() }}
	_, err := s.FileEvents(context.Background(), map[string]any{}, 0)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// buildMachine — platform mapping table
// ---------------------------------------------------------------------------

func TestBuildMachine_PlatformMapping(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name        string
		platform    string
		wantFamily  string
		wantMachine model.MachineType
	}{
		{"ubuntu is linux server", "ubuntu", "linux", model.MachineTypeServer},
		{"rhel is linux server", "rhel", "linux", model.MachineTypeServer},
		{"arch is linux server", "arch", "linux", model.MachineTypeServer},
		{"windows is workstation", "windows", "windows", model.MachineTypeWorkstation},
		{"darwin is workstation", "darwin", "darwin", model.MachineTypeWorkstation},
		{"unknown platform stays empty", "", "", model.MachineTypeServer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := buildMachine(
				map[string]string{"version": "5.15.0"},
				map[string]string{"hostname": "h"},
				map[string]string{"platform": tc.platform, "name": "OS", "version": "1"},
				map[string]string{},
				now,
			)
			assert.Equal(t, tc.wantFamily, m.OSFamily)
			assert.Equal(t, tc.wantMachine, m.MachineType)
		})
	}
}

func TestBuildMachine_EmptyRowsProduceEmptyMachine(t *testing.T) {
	m := buildMachine(map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}, time.Now().UTC())
	assert.Equal(t, "", m.Hostname)
	assert.Equal(t, "", m.OSFamily)
	assert.Equal(t, "osquery", m.DiscoverySource)
}

func TestBuildMachine_OSVersionTrimmed(t *testing.T) {
	m := buildMachine(map[string]string{}, map[string]string{},
		map[string]string{"name": "Ubuntu", "version": ""}, map[string]string{}, time.Now().UTC())
	assert.Equal(t, "Ubuntu", m.OSVersion, "trailing space must be trimmed when version is empty")
}

// ---------------------------------------------------------------------------
// resolveSocket precedence + small helpers
// ---------------------------------------------------------------------------

func TestResolveSocket_CfgWins(t *testing.T) {
	t.Setenv("KITE_OSQUERY_SOCKET", "/env/socket.em")
	got := resolveSocket(map[string]any{"socket": "/cfg/socket.em"})
	assert.Equal(t, "/cfg/socket.em", got)
}

func TestResolveSocket_EnvWhenNoCfg(t *testing.T) {
	t.Setenv("KITE_OSQUERY_SOCKET", "/env/socket.em")
	assert.Equal(t, "/env/socket.em", resolveSocket(map[string]any{}))
}

func TestResolveSocket_EnvWhenCfgNotString(t *testing.T) {
	t.Setenv("KITE_OSQUERY_SOCKET", "/env/socket.em")
	assert.Equal(t, "/env/socket.em", resolveSocket(map[string]any{"socket": 42}))
}

func TestResolveSocket_NilCfg(t *testing.T) {
	t.Setenv("KITE_OSQUERY_SOCKET", "/env/socket.em")
	assert.Equal(t, "/env/socket.em", resolveSocket(nil))
}

func TestSQLEscape(t *testing.T) {
	cases := map[string]string{
		"plain":       "plain",
		"o'brien":     "o''brien",
		"''":          "''''",
		"":            "",
		"a'b'c":       "a''b''c",
		"nö quotes ✓": "nö quotes ✓",
	}
	for in, want := range cases {
		assert.Equal(t, want, sqlEscape(in), "sqlEscape(%q)", in)
	}
}

func TestToStrings_Variants(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, toStrings([]string{"a", "b"}))
	assert.Equal(t, []string{"a", "b"}, toStrings([]any{"a", "b"}))
	assert.Equal(t, []string{"a"}, toStrings([]any{"a", 42, nil}), "non-strings dropped")
	assert.Nil(t, toStrings("not-a-slice"))
	assert.Nil(t, toStrings(nil))
}

func TestToString_Variants(t *testing.T) {
	assert.Equal(t, "x", toString("x"))
	assert.Equal(t, "", toString(42))
	assert.Equal(t, "", toString(nil))
}

func TestFirst_EmptyAndPopulated(t *testing.T) {
	assert.Equal(t, map[string]string{}, first(nil))
	assert.Equal(t, map[string]string{}, first([]map[string]string{}))
	assert.Equal(t, "v", first([]map[string]string{{"k": "v"}})["k"])
}

// ---------------------------------------------------------------------------
// Log-practice pins: every degraded path must emit its code, exactly once,
// with honest attributes (no error=<nil>, distinct codes per failure mode).
// ---------------------------------------------------------------------------

// captureLogs redirects the default slog logger into a buffer for the test's
// duration so assertions can pin codes and attributes.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestLogs_SigfileInvisible_NoNilErrorAttr(t *testing.T) {
	// The daemon ANSWERED the probe with zero rows — there is no error, so
	// no error attribute may appear (error=<nil> misleads log pipelines that
	// filter on the presence of an error field).
	buf := captureLogs(t)
	stub := healthyStub()
	stub.responses["FROM file"] = nil
	s, _ := sourceWith(stub)
	_, err := s.Discover(context.Background(), yaraCfg("/opt/x"))
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, string(LogCodeYaraSigfileInvisible))
	assert.NotContains(t, out, string(LogCodeYaraSigfileProbeFailed))
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, string(LogCodeYaraSigfileInvisible)) {
			assert.NotContains(t, line, "error=", "no error attr on the no-error path")
		}
	}
}

func TestLogs_SigfileProbeFailure_DistinctCodeWithError(t *testing.T) {
	// The probe ERRORED — a different failure mode (daemon/table broken, not
	// a bad sigfile path), so a different code, and this one carries the
	// error.
	buf := captureLogs(t)
	stub := healthyStub()
	stub.errs["FROM file"] = errors.New("file table wedged")
	s, _ := sourceWith(stub)
	_, err := s.Discover(context.Background(), yaraCfg("/opt/x"))
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, string(LogCodeYaraSigfileProbeFailed))
	assert.Contains(t, out, "file table wedged")
	assert.NotContains(t, out, string(LogCodeYaraSigfileInvisible))
}

func TestLogs_FileEventsFailure_IsNotSilent(t *testing.T) {
	// A failed FIM summary must be visible: without the warning, "0 events"
	// and "events subsystem broken" are indistinguishable to an operator.
	buf := captureLogs(t)
	stub := healthyStub()
	stub.errs["file_events"] = errors.New("events disabled")
	s, cfg := sourceWith(stub)
	_, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), string(LogCodeDiscoverFileEventsFailed))
	assert.Contains(t, buf.String(), "events disabled")
}

func TestLogs_YaraMatches_NameTheRules(t *testing.T) {
	// The alert line must carry the rule names so on-call does not need to
	// pivot into the machine record to know WHAT matched.
	buf := captureLogs(t)
	stub := healthyStub()
	stub.responses["FROM file"] = []map[string]string{{"path": "x"}}
	stub.responses["FROM yara"] = []map[string]string{
		{"path": "/opt/a", "matches": "kite_sim_canary,kite_sim_hex_canary", "count": "2"},
	}
	s, _ := sourceWith(stub)
	_, err := s.Discover(context.Background(), yaraCfg("/opt/a"))
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, string(LogCodeYaraMatchesFound))
	assert.Contains(t, out, "kite_sim_canary")
	assert.Contains(t, out, "kite_sim_hex_canary")
}

func TestLogs_HappyPath_NoWarnings(t *testing.T) {
	// A fully healthy scan must not cry wolf: no WARN lines at all.
	buf := captureLogs(t)
	s, cfg := sourceWith(healthyStub())
	_, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "level=WARN")
}

func TestMatchedRuleNames_DedupOrderAndWhitespace(t *testing.T) {
	names := matchedRuleNames([]YaraMatch{
		{Matches: "b, a"},
		{Matches: "a,c"},
		{Matches: ""},
		{Matches: " , "},
	})
	assert.Equal(t, []string{"b", "a", "c"}, names)
}

func TestMatchedRuleNames_Empty(t *testing.T) {
	assert.Empty(t, matchedRuleNames(nil))
	assert.Empty(t, matchedRuleNames([]YaraMatch{{Matches: ""}}))
}

// ---------------------------------------------------------------------------
// Windows FIM fallback: file_events is POSIX-only (specs/posix/); a Windows
// daemon serves ntfs_journal_events. Verified against osquery HEAD specs.
// ---------------------------------------------------------------------------

func TestFileEvents_WindowsDaemon_FallsBackToNTFSJournal(t *testing.T) {
	stub := healthyStub()
	stub.errs["file_events"] = &queryError{method: "query", code: 1, message: "no such table: file_events"}
	stub.responses["ntfs_journal_events"] = []map[string]string{
		{"path": `C:\Users\a\secret.txt`, "category": "kite_fim", "action": "Write", "time": "1754955600"},
	}
	s, cfg := sourceWith(stub)
	events, err := s.FileEvents(context.Background(), cfg, 0)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, `C:\Users\a\secret.txt`, events[0].TargetPath)
	assert.Equal(t, "Write", events[0].Action)
	assert.Equal(t, "", events[0].SHA256, "NTFS journal has no sha256 column")
	assert.Equal(t, int64(1754955600), events[0].Time)
}

func TestFileEvents_TransportError_DoesNotFallBack(t *testing.T) {
	// Only an unknown-table REJECTION means "wrong platform table"; a
	// transport failure means the daemon is unreachable and retrying a
	// different table would just mask it.
	stub := healthyStub()
	stub.errs["file_events"] = errors.New("dial unix: connection refused")
	s, cfg := sourceWith(stub)
	_, err := s.FileEvents(context.Background(), cfg, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file_events")
	assert.NotContains(t, err.Error(), "ntfs_journal_events")
}

func TestFileEvents_OtherRejection_DoesNotFallBack(t *testing.T) {
	stub := healthyStub()
	stub.errs["file_events"] = &queryError{method: "query", code: 1, message: "Table file_events was queried without a required column"}
	s, cfg := sourceWith(stub)
	_, err := s.FileEvents(context.Background(), cfg, 0)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "ntfs_journal_events")
}

func TestFileEvents_NTFSAlsoMissing_SurfacesNTFSError(t *testing.T) {
	stub := healthyStub()
	stub.errs["file_events"] = &queryError{method: "query", code: 1, message: "no such table: file_events"}
	stub.errs["ntfs_journal_events"] = &queryError{method: "query", code: 1, message: "no such table: ntfs_journal_events"}
	s, cfg := sourceWith(stub)
	_, err := s.FileEvents(context.Background(), cfg, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ntfs_journal_events")
}

// ---------------------------------------------------------------------------
// Inline YARA rules (sigrule): no daemon-side file, compile-proof guard.
// Verified against osquery HEAD (specs/yara_file.table sigrule column,
// tables/yara/yara.cpp compile path) and the 5.15.0 sim.
// ---------------------------------------------------------------------------

const inlineRule = `rule inline_canary { strings: $m = "X" condition: $m }`

// selfProbeStub extends healthyStub to answer the daemon-binary lookup and to
// route yara queries by whether they carry sigrule/sigfile. rulesCompile
// controls whether the compile probe (yara vs the daemon binary) returns a
// row.
func rulesStub(rulesCompile bool, scan map[string][]map[string]string) *stubQuerier {
	stub := healthyStub()
	stub.responses["FROM processes p, osquery_info i"] = []map[string]string{{"path": "/opt/osquery/bin/osqueryd"}}
	stub.responses["/opt/osquery/bin/osqueryd"] = func() []map[string]string {
		if rulesCompile {
			return []map[string]string{{"count": "0"}}
		}
		return nil // broken rule -> zero rows
	}()
	for k, v := range scan {
		stub.responses[k] = v
	}
	return stub
}

func TestYaraInline_CompiledRule_Scans(t *testing.T) {
	stub := rulesStub(true, map[string][]map[string]string{
		"/opt/payload.bin": {{"path": "/opt/payload.bin", "matches": "inline_canary", "count": "1"}},
	})
	s, _ := sourceWith(stub)
	cfg := map[string]any{"socket": "/tmp/t.em", "yara_rules": inlineRule, "yara_paths": []any{"/opt/payload.bin"}}
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	assert.Equal(t, true, tags["yara_scanned"])
	assert.Equal(t, float64(1), tags["yara_match_count"])
}

func TestYaraInline_UncompilableRule_SkipsNotClean(t *testing.T) {
	// A malformed inline rule is silently dropped by osquery (0 rows). The
	// compile probe against the daemon binary catches it, and the scan is
	// SKIPPED — never reported as a clean result.
	buf := captureLogs(t)
	stub := rulesStub(false, map[string][]map[string]string{
		// Even if the daemon would answer the real scan, we must not reach it.
		"/opt/payload.bin": {{"path": "/opt/payload.bin", "matches": "", "count": "0"}},
	})
	s, _ := sourceWith(stub)
	cfg := map[string]any{"socket": "/tmp/t.em", "yara_rules": "rule broken {", "yara_paths": []any{"/opt/payload.bin"}}
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	_, scanned := tagsOf(t, machines[0])["yara_scanned"]
	assert.False(t, scanned)
	assert.Contains(t, buf.String(), string(LogCodeYaraRulesUncompilable))
}

func TestYaraInline_DaemonBinaryUnresolved_Skips(t *testing.T) {
	buf := captureLogs(t)
	stub := healthyStub()
	stub.responses["FROM processes p, osquery_info i"] = nil // cannot resolve self
	s, _ := sourceWith(stub)
	cfg := map[string]any{"socket": "/tmp/t.em", "yara_rules": inlineRule, "yara_paths": []any{"/x"}}
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	_, scanned := tagsOf(t, machines[0])["yara_scanned"]
	assert.False(t, scanned)
	assert.Contains(t, buf.String(), string(LogCodeYaraCompileProbeFailed))
}

func TestYaraInline_ProbeQueryError_Skips(t *testing.T) {
	buf := captureLogs(t)
	stub := healthyStub()
	stub.responses["FROM processes p, osquery_info i"] = []map[string]string{{"path": "/opt/osquery/bin/osqueryd"}}
	stub.errs["/opt/osquery/bin/osqueryd"] = errors.New("yara table wedged")
	s, _ := sourceWith(stub)
	cfg := map[string]any{"socket": "/tmp/t.em", "yara_rules": inlineRule, "yara_paths": []any{"/x"}}
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	_, scanned := tagsOf(t, machines[0])["yara_scanned"]
	assert.False(t, scanned)
	assert.Contains(t, buf.String(), string(LogCodeYaraCompileProbeFailed))
}

func TestYaraInline_TakesPrecedenceOverSigfile(t *testing.T) {
	// When both are configured, inline rules win: no `file` visibility probe
	// should run (no daemon-side file is involved).
	stub := rulesStub(true, map[string][]map[string]string{
		"/opt/x": {{"path": "/opt/x", "matches": "inline_canary", "count": "1"}},
	})
	s, _ := sourceWith(stub)
	cfg := map[string]any{
		"socket": "/tmp/t.em", "yara_rules": inlineRule,
		"yara_sigfile": "/etc/osquery/yara/kite.yar", "yara_paths": []any{"/opt/x"},
	}
	_, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	for _, q := range stub.queries {
		assert.NotContains(t, q, "FROM file WHERE", "sigfile visibility probe must not run in rule mode")
		assert.NotContains(t, q, "sigfile =", "scan must use sigrule, not sigfile")
	}
}

func TestYaraInline_RuleReachesDaemonViaSigrule(t *testing.T) {
	stub := rulesStub(true, map[string][]map[string]string{
		"/opt/x": {{"path": "/opt/x", "matches": "", "count": "0"}},
	})
	s, _ := sourceWith(stub)
	cfg := map[string]any{"socket": "/tmp/t.em", "yara_rules": inlineRule, "yara_paths": []any{"/opt/x"}}
	_, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	var scanSQL string
	for _, q := range stub.queries {
		if strings.Contains(q, "path = '/opt/x'") {
			scanSQL = q
		}
	}
	require.NotEmpty(t, scanSQL)
	assert.Contains(t, scanSQL, "sigrule = ")
	assert.Contains(t, scanSQL, "inline_canary")
}

func TestJoinRules_StringAndList(t *testing.T) {
	assert.Equal(t, "rule a {}", joinRules("rule a {}"))
	assert.Equal(t, "rule a {}\nrule b {}", joinRules([]any{"rule a {}", "rule b {}"}))
	assert.Equal(t, "rule a {}\nrule b {}", joinRules([]string{"rule a {}", "rule b {}"}))
	assert.Equal(t, "", joinRules(nil))
	assert.Equal(t, "", joinRules([]any{}))
	assert.Equal(t, "", joinRules(42))
}

func TestYaraInline_NoPaths_NotScanned(t *testing.T) {
	stub := rulesStub(true, nil)
	s, _ := sourceWith(stub)
	cfg := map[string]any{"socket": "/tmp/t.em", "yara_rules": inlineRule}
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	_, scanned := tagsOf(t, machines[0])["yara_scanned"]
	assert.False(t, scanned)
}

// ---------------------------------------------------------------------------
// False-clean guard: the credential proof does not exercise the yara table,
// so if every scan path errors (yara table absent — e.g. a FreeBSD daemon —
// or all paths unreadable) the scan must NOT be reported as clean.
// ---------------------------------------------------------------------------

func TestYara_AllPathsError_SigfileMode_NotReportedClean(t *testing.T) {
	buf := captureLogs(t)
	stub := healthyStub()
	stub.responses["FROM file"] = []map[string]string{{"path": "/etc/osquery/yara/kite.yar"}} // sigfile visible
	stub.errs["FROM yara"] = &queryError{method: "query", code: 1, message: "no such table: yara"}
	s, _ := sourceWith(stub)
	machines, err := s.Discover(context.Background(), yaraCfg("/a", "/b"))
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	_, scanned := tags["yara_scanned"]
	assert.False(t, scanned, "sigfile visible but yara table absent must not report a clean scan")
	assert.Contains(t, buf.String(), string(LogCodeYaraAllPathsFailed))
}

func TestYara_AllPathsError_RuleMode_NotReportedClean(t *testing.T) {
	buf := captureLogs(t)
	stub := rulesStub(true, nil) // compile probe passes
	// Path names chosen not to collide as substrings with the daemon binary
	// path the compile probe scans (/opt/osquery/bin/osqueryd).
	stub.errs["/scan/target-one"] = &queryError{method: "query", code: 1, message: "scan errored"}
	stub.errs["/scan/target-two"] = &queryError{method: "query", code: 1, message: "scan errored"}
	s, _ := sourceWith(stub)
	cfg := map[string]any{"socket": "/tmp/t.em", "yara_rules": inlineRule, "yara_paths": []any{"/scan/target-one", "/scan/target-two"}}
	machines, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	_, scanned := tagsOf(t, machines[0])["yara_scanned"]
	assert.False(t, scanned)
	assert.Contains(t, buf.String(), string(LogCodeYaraAllPathsFailed))
}

func TestYara_SomePathsError_StillReportsScan(t *testing.T) {
	// As long as at least one path scanned, the result stands — the errored
	// paths are logged per-path but the scan is real.
	stub := healthyStub()
	stub.responses["FROM file"] = []map[string]string{{"path": "/etc/osquery/yara/kite.yar"}}
	// /good scans (returns a clean row); /bad errors.
	stub.responses["/good"] = []map[string]string{{"path": "/good", "matches": "", "count": "0"}}
	stub.errs["/bad"] = &queryError{method: "query", code: 1, message: "unreadable"}
	s, _ := sourceWith(stub)
	machines, err := s.Discover(context.Background(), yaraCfg("/good", "/bad"))
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	assert.Equal(t, true, tags["yara_scanned"], "one good path means the scan really ran")
	assert.Equal(t, float64(0), tags["yara_match_count"])
}

// ---------------------------------------------------------------------------
// Per-path false-clean guard: osquery's doYARAScanPath pushes a row ONLY on
// ERROR_SUCCESS, so a missing/unreadable/directory path (or an empty glob)
// returns 0 rows rc=0 — NOT the same as a scanned-clean file (1 row, count 0).
// Verified against the 5.15.0 sim (missing/dir/empty-glob -> 0 rows).
// ---------------------------------------------------------------------------

func TestYara_UnscannablePath_NotCountedAsClean(t *testing.T) {
	// One real path (1 row, clean) + one missing path (0 rows). The missing
	// path must be reported as unscannable coverage, not folded into "clean".
	buf := captureLogs(t)
	stub := healthyStub()
	stub.responses["FROM file"] = []map[string]string{{"path": "/etc/osquery/yara/kite.yar"}}
	stub.responses["/real"] = []map[string]string{{"path": "/real", "matches": "", "count": "0"}}
	stub.responses["/missing"] = nil // 0 rows: daemon opened nothing
	s, _ := sourceWith(stub)
	machines, err := s.Discover(context.Background(), yaraCfg("/real", "/missing"))
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	assert.Equal(t, true, tags["yara_scanned"], "one real path scanned -> result stands")
	assert.Equal(t, float64(0), tags["yara_match_count"])
	assert.Equal(t, float64(1), tags["yara_paths_unscannable"], "the missing path is a coverage gap")
	assert.Contains(t, buf.String(), string(LogCodeYaraPathUnscannable))
}

func TestYara_EveryPathUnscannable_NotReportedClean(t *testing.T) {
	// All configured paths return 0 rows (all missing). Nothing was actually
	// scanned, so the result must NOT be reported as a clean bill of health.
	buf := captureLogs(t)
	stub := healthyStub()
	stub.responses["FROM file"] = []map[string]string{{"path": "/etc/osquery/yara/kite.yar"}}
	stub.responses["/gone-a"] = nil
	stub.responses["/gone-b"] = nil
	s, _ := sourceWith(stub)
	machines, err := s.Discover(context.Background(), yaraCfg("/gone-a", "/gone-b"))
	require.NoError(t, err)
	_, scanned := tagsOf(t, machines[0])["yara_scanned"]
	assert.False(t, scanned, "no path scanned -> no clean claim")
	assert.Contains(t, buf.String(), string(LogCodeYaraAllPathsFailed))
}

func TestYara_NoUnscannableTag_WhenAllPathsScan(t *testing.T) {
	// A fully-covered scan must not carry the coverage-gap tag at all.
	stub := healthyStub()
	stub.responses["FROM file"] = []map[string]string{{"path": "/etc/osquery/yara/kite.yar"}}
	stub.responses["/real"] = []map[string]string{{"path": "/real", "matches": "", "count": "0"}}
	s, _ := sourceWith(stub)
	machines, err := s.Discover(context.Background(), yaraCfg("/real"))
	require.NoError(t, err)
	tags := tagsOf(t, machines[0])
	assert.Equal(t, true, tags["yara_scanned"])
	_, present := tags["yara_paths_unscannable"]
	assert.False(t, present, "no coverage gaps -> no unscannable tag")
}
