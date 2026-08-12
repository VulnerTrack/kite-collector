package osquery

import (
	"context"
	"encoding/json"
	"errors"
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
	for kw, err := range s.errs {
		if strings.Contains(sql, kw) {
			return nil, err
		}
	}
	for kw, rows := range s.responses {
		if strings.Contains(sql, kw) {
			return rows, nil
		}
	}
	return nil, nil
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
	assert.Equal(t, float64(2), tags["file_events_24h"])
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
