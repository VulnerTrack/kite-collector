package containers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
)

// errDoer is an httpDoer whose Do always fails, simulating a Docker socket
// that is present but whose daemon does not answer.
type errDoer struct{ err error }

func (d errDoer) Do(*http.Request) (*http.Response, error) { return nil, d.err }

func TestDockerCollect_DaemonUnreachableReturnsCatalogE001(t *testing.T) {
	c := &dockerEngineCollector{
		baseURL: "http://docker.invalid",
		client:  errDoer{err: errors.New("dial unix /var/run/docker.sock: connect: connection refused")},
		runtime: RuntimeDocker,
	}

	if _, err := c.Collect(context.Background()); err != nil {
		var ke *kiteerrors.Error
		if !errors.As(err, &ke) {
			t.Fatalf("expected a *kiteerrors.Error, got %T: %v", err, err)
		}
		if ke.Code != "KITE-E001" {
			t.Errorf("Code = %q, want KITE-E001", ke.Code)
		}
		if ke.Hint == "" {
			t.Error("expected the E001 remediation hint to be populated")
		}
	} else {
		t.Fatal("expected an error when the daemon is unreachable")
	}
}

func TestPinnedEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(RuntimeDocker), "docker"},
		{string(RuntimePodman), "podman"},
		{string(RuntimeContainerd), "containerd"},
		{string(RuntimeCRIO), "cri-o"},
		{string(RuntimeLXC), "lxc"},
		{string(RuntimeUnknown), "unknown"},
		{string(StateCreated), "created"},
		{string(StateRunning), "running"},
		{string(StatePaused), "paused"},
		{string(StateRestarting), "restarting"},
		{string(StateExited), "exited"},
		{string(StateDead), "dead"},
		{string(StateUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestNormalizeState(t *testing.T) {
	cases := map[string]State{
		"created":    StateCreated,
		"running":    StateRunning,
		"RUNNING":    StateRunning, // containerd uppercase
		"paused":     StatePaused,
		"restarting": StateRestarting,
		"exited":     StateExited,
		"stopped":    StateExited, // containerd
		"dead":       StateDead,
		"":           StateUnknown,
		"garbage":    StateUnknown,
	}
	for in, want := range cases {
		if got := NormalizeState(in); got != want {
			t.Fatalf("NormalizeState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEncodeJSONHelpers(t *testing.T) {
	// Empty inputs must produce valid JSON (never NULL).
	if got := EncodePorts(nil); got != "[]" {
		t.Fatalf("EncodePorts(nil) = %q, want []", got)
	}
	if got := EncodeMounts(nil); got != "[]" {
		t.Fatalf("EncodeMounts(nil) = %q, want []", got)
	}
	if got := EncodeStrings(nil); got != "[]" {
		t.Fatalf("EncodeStrings(nil) = %q, want []", got)
	}
	if got := EncodeLabels(nil); got != "{}" {
		t.Fatalf("EncodeLabels(nil) = %q, want {}", got)
	}

	// Round-trip a non-empty mount.
	ms := []Mount{{Source: "/var/lib/x", Destination: "/data", Type: "bind", ReadOnly: false}}
	enc := EncodeMounts(ms)
	var back []Mount
	if err := json.Unmarshal([]byte(enc), &back); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if back[0] != ms[0] {
		t.Fatalf("round-trip mismatch: got %+v want %+v", back[0], ms[0])
	}
}

func TestSortContainersDeterministic(t *testing.T) {
	in := []Container{
		{Runtime: RuntimeDocker, ContainerID: "z"},
		{Runtime: RuntimeContainerd, ContainerID: "a"},
		{Runtime: RuntimeDocker, ContainerID: "a"},
		{Runtime: RuntimePodman, ContainerID: "m"},
	}
	SortContainers(in)
	want := []struct {
		r  Runtime
		id string
	}{
		{RuntimeContainerd, "a"},
		{RuntimeDocker, "a"},
		{RuntimeDocker, "z"},
		{RuntimePodman, "m"},
	}
	for i, c := range in {
		if c.Runtime != want[i].r || c.ContainerID != want[i].id {
			t.Fatalf("pos %d: got (%q,%q), want (%q,%q)",
				i, c.Runtime, c.ContainerID, want[i].r, want[i].id)
		}
	}
}

func TestParseRootUID(t *testing.T) {
	cases := map[string]*int{
		"":           intPtr(0), // image default — conservatively root
		"root":       intPtr(0),
		"root:wheel": intPtr(0),
		"0":          intPtr(0),
		"0:0":        intPtr(0),
		"1000":       intPtr(1000),
		"1000:1000":  intPtr(1000),
		"alice":      nil, // non-numeric username — unresolvable here
	}
	for in, want := range cases {
		got := parseRootUID(in)
		if (got == nil) != (want == nil) {
			t.Fatalf("parseRootUID(%q): nil mismatch, got %v want %v", in, got, want)
		}
		if got != nil && *got != *want {
			t.Fatalf("parseRootUID(%q) = %d, want %d", in, *got, *want)
		}
	}
}

func TestDockerCollectorEndToEnd(t *testing.T) {
	srv := newMockDockerServer(t)
	defer srv.Close()

	c := &dockerEngineCollector{
		socket:  srv.URL,
		baseURL: srv.URL,
		client:  srv.Client(),
		runtime: RuntimeDocker,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 containers, got %d", len(got))
	}

	by := map[string]Container{}
	for _, k := range got {
		by[k.Name] = k
	}

	web := by["web"]
	if web.State != StateRunning {
		t.Fatalf("web state=%q", web.State)
	}
	if !web.Privileged {
		t.Fatalf("web should be privileged per fixture inspect")
	}
	if !web.HostNetwork {
		t.Fatalf("web should be host-network per fixture inspect")
	}
	if web.RootUID == nil || *web.RootUID != 0 {
		t.Fatalf("web image-default user → root_uid=0, got %v", web.RootUID)
	}
	if web.ImageDigest != "sha256:abc123" {
		t.Fatalf("web image digest lost: %q", web.ImageDigest)
	}
	if len(web.Ports) != 1 || web.Ports[0].HostPort != 8080 {
		t.Fatalf("web ports lost: %+v", web.Ports)
	}

	db := by["db"]
	if db.Privileged {
		t.Fatalf("db should not be privileged")
	}
	if db.RootUID == nil || *db.RootUID != 1000 {
		t.Fatalf("db numeric uid → 1000, got %v", db.RootUID)
	}
}

func TestDockerCollectorNoSocketReturnsEmpty(t *testing.T) {
	c := &dockerEngineCollector{socket: "", client: nil, runtime: RuntimeDocker}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("no-socket must not error, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("no-socket must return empty, got %d", len(got))
	}
}

func TestChainCollectorAggregatesAndSkipsErrors(t *testing.T) {
	good := stubCollector{out: []Container{
		{Runtime: RuntimeDocker, ContainerID: "x", State: StateRunning},
	}}
	bad := stubCollector{err: errors.New("daemon down")}
	chain := &chainCollector{collectors: []Collector{good, bad, good}}

	got, err := chain.Collect(context.Background())
	if err != nil {
		t.Fatalf("chain Collect: %v", err)
	}
	// good fires twice + bad logs+skips = 2 containers total.
	if len(got) != 2 {
		t.Fatalf("want 2 containers (2 × good), got %d", len(got))
	}
}

func TestChainCollectorRespectsCap(t *testing.T) {
	bulk := stubCollector{out: make([]Container, MaxContainers+10)}
	for i := range bulk.out {
		bulk.out[i] = Container{Runtime: RuntimeDocker, ContainerID: itoa(i)}
	}
	chain := &chainCollector{collectors: []Collector{bulk}}
	got, err := chain.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != MaxContainers {
		t.Fatalf("want %d (cap), got %d", MaxContainers, len(got))
	}
}

// -- fixtures ---------------------------------------------------------------

// newMockDockerServer returns an httptest server that answers the Engine
// API calls used by dockerEngineCollector. Two containers: "web" (privileged
// + host network, image-default user → root) and "db" (uid 1000, no host net).
func newMockDockerServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/"+dockerAPIVersion+"/containers/json",
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode([]dockerContainerSummary{
				{
					ID:      "web-id-aaaa",
					Names:   []string{"/web"},
					Image:   "nginx:1.25",
					ImageID: "sha256:nginxhash",
					State:   "running",
					Status:  "Up 2 hours",
					Ports: []dockerPortEntry{
						{PrivatePort: 80, PublicPort: 8080, Type: "tcp"},
					},
					Labels: map[string]string{"role": "web"},
				},
				{
					ID:      "db-id-bbbb",
					Names:   []string{"/db"},
					Image:   "postgres:16",
					ImageID: "sha256:pghash",
					State:   "running",
					Status:  "Up 5 hours",
					Labels:  map[string]string{"role": "db"},
				},
			})
		})

	mux.HandleFunc("/"+dockerAPIVersion+"/containers/web-id-aaaa/json",
		func(w http.ResponseWriter, _ *http.Request) {
			d := dockerInspect{Image: "sha256:abc123"}
			d.State.Status = "running"
			d.State.StartedAt = "2026-06-23T10:00:00Z"
			d.HostConfig.Privileged = true
			d.HostConfig.NetworkMode = "host"
			d.HostConfig.PidMode = ""
			d.Config.User = "" // image default → conservatively root
			_ = json.NewEncoder(w).Encode(d)
		})

	mux.HandleFunc("/"+dockerAPIVersion+"/containers/db-id-bbbb/json",
		func(w http.ResponseWriter, _ *http.Request) {
			d := dockerInspect{Image: "sha256:def456"}
			d.State.Status = "running"
			d.State.StartedAt = "2026-06-23T07:00:00Z"
			d.HostConfig.NetworkMode = "bridge"
			d.Config.User = "1000:1000"
			_ = json.NewEncoder(w).Encode(d)
		})

	return httptest.NewServer(mux)
}

type stubCollector struct {
	err error
	out []Container
}

func (s stubCollector) Name() string { return "stub" }
func (s stubCollector) Collect(_ context.Context) ([]Container, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.out, nil
}

func intPtr(i int) *int { return &i }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [11]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// silence unused-import grumble when test set evolves
var _ = strings.TrimSpace
