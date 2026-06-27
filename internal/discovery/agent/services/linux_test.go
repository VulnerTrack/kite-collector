//go:build linux

package services

import (
	"context"
	"strings"
	"testing"
)

const sampleListUnits = `[
  {"unit":"ssh.service","load":"loaded","active":"active","sub":"running","description":"OpenBSD Secure Shell server"},
  {"unit":"cron.service","load":"loaded","active":"active","sub":"running","description":"Regular background program processing daemon"},
  {"unit":"telnet.socket","load":"loaded","active":"failed","sub":"failed","description":"Telnet Server Activation Socket"},
  {"unit":"docker.service","load":"loaded","active":"inactive","sub":"dead","description":"Docker Application Container Engine"}
]`

const sampleListUnitFiles = `[
  {"unit_file":"ssh.service","state":"enabled","preset":"enabled"},
  {"unit_file":"cron.service","state":"enabled","preset":"enabled"},
  {"unit_file":"telnet.socket","state":"masked","preset":"disabled"},
  {"unit_file":"docker.service","state":"disabled","preset":"disabled"}
]`

func TestCollectMergesUnitsAndFiles(t *testing.T) {
	c := &linuxCollector{
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if hasArg(args, "list-units") {
				return []byte(sampleListUnits), nil
			}
			if hasArg(args, "list-unit-files") {
				return []byte(sampleListUnitFiles), nil
			}
			t.Fatalf("unexpected args: %v", args)
			return nil, nil
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 services, got %d", len(got))
	}
	// Deterministic sort: alphabetical by name within ManagerSystemd.
	want := []string{"cron.service", "docker.service", "ssh.service", "telnet.socket"}
	for i, s := range got {
		if s.Name != want[i] {
			t.Fatalf("pos %d: got %q want %q", i, s.Name, want[i])
		}
		if s.Manager != ManagerSystemd {
			t.Fatalf("pos %d manager=%q", i, s.Manager)
		}
	}

	// Spot-check the merge: ssh = running+auto, telnet = failed+masked.
	by := map[string]Service{}
	for _, s := range got {
		by[s.Name] = s
	}
	if by["ssh.service"].State != StateRunning {
		t.Fatalf("ssh state=%q", by["ssh.service"].State)
	}
	if by["ssh.service"].StartMode != StartAuto {
		t.Fatalf("ssh start_mode=%q", by["ssh.service"].StartMode)
	}
	if by["telnet.socket"].State != StateFailed {
		t.Fatalf("telnet state=%q", by["telnet.socket"].State)
	}
	if by["telnet.socket"].StartMode != StartMasked {
		t.Fatalf("telnet start_mode=%q", by["telnet.socket"].StartMode)
	}
	if by["docker.service"].State != StateStopped {
		t.Fatalf("docker (sub=dead) must collapse to stopped, got %q",
			by["docker.service"].State)
	}
	if by["docker.service"].StartMode != StartDisabled {
		t.Fatalf("docker start_mode=%q", by["docker.service"].StartMode)
	}
}

func TestCollectSoftFailsOnUnitFilesError(t *testing.T) {
	c := &linuxCollector{
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if hasArg(args, "list-units") {
				return []byte(sampleListUnits), nil
			}
			return nil, &execFailure{}
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must soft-fail on list-unit-files: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 runtime-only services, got %d", len(got))
	}
	for _, s := range got {
		if s.StartMode != StartUnknown {
			t.Fatalf("%s start_mode=%q, want unknown when list-unit-files fails",
				s.Name, s.StartMode)
		}
	}
}

func TestParseSystemctlUnitsAcceptsNDJSON(t *testing.T) {
	// Older systemd versions emit one object per line when --no-legend is set.
	raw := `{"unit":"a.service","load":"loaded","active":"active","sub":"running","description":"A"}
{"unit":"b.service","load":"loaded","active":"inactive","sub":"dead","description":"B"}`
	units, err := parseSystemctlUnits([]byte(raw))
	if err != nil {
		t.Fatalf("parse ndjson: %v", err)
	}
	if len(units) != 2 || units[0].Unit != "a.service" || units[1].Unit != "b.service" {
		t.Fatalf("ndjson decode wrong: %+v", units)
	}
}

func TestParseSystemctlUnitsEmptyInput(t *testing.T) {
	units, err := parseSystemctlUnits([]byte("   \n\t"))
	if err != nil {
		t.Fatalf("empty input must not error: %v", err)
	}
	if len(units) != 0 {
		t.Fatalf("want 0 units, got %d", len(units))
	}
}

func TestMapSystemctlActiveSubWins(t *testing.T) {
	cases := []struct {
		active, sub string
		want        State
	}{
		{"active", "running", StateRunning},
		{"active", "exited", StateStopped},
		{"failed", "failed", StateFailed},
		{"activating", "start", StateActivating},
		{"deactivating", "stop", StateDeactivating},
		{"inactive", "dead", StateStopped},
		{"", "", StateUnknown},
	}
	for _, tc := range cases {
		if got := mapSystemctlActive(tc.active, tc.sub); got != tc.want {
			t.Fatalf("mapSystemctlActive(%q,%q)=%q, want %q",
				tc.active, tc.sub, got, tc.want)
		}
	}
}

func TestMapSystemctlStartFromUnitFileState(t *testing.T) {
	cases := map[string]StartMode{
		"enabled":         StartAuto,
		"enabled-runtime": StartAuto,
		"alias":           StartAuto,
		"disabled":        StartDisabled,
		"static":          StartStatic,
		"masked":          StartMasked,
		"masked-runtime":  StartMasked,
		"indirect":        StartOnDemand,
		"generated":       StartAuto,
		"":                StartUnknown,
		"wat":             StartUnknown,
	}
	for in, want := range cases {
		if got := mapSystemctlStart(in); got != want {
			t.Fatalf("mapSystemctlStart(%q)=%q, want %q", in, got, want)
		}
	}
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want || strings.HasSuffix(a, "/"+want) {
			return true
		}
	}
	return false
}

// execFailure is a tiny sentinel error type for test stubs so we don't
// have to import "errors" just to make a sentinel.
type execFailure struct{}

func (*execFailure) Error() string { return "exec failed" }
