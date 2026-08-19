package docker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMockLiveAPI serves the live-view Engine endpoints: container list with
// health-bearing status text, one-shot stats, image list, image history.
func newMockLiveAPI(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(mockLiveAPIMux(t))
	t.Cleanup(srv.Close)
	return srv
}

// mockLiveAPIMux is the handler behind newMockLiveAPI, split out so the
// unix-socket transport test can serve the same API over a socket listener.
func mockLiveAPIMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		containers := []containerSummary{
			{
				ID:      "abc123def456789012345678",
				Names:   []string{"/clickhouse"},
				Image:   "clickhouse/clickhouse-server:latest",
				ImageID: "sha256:deadbeefcafe",
				State:   "running",
				Status:  "Up 3 hours (healthy)",
				Created: 1700000000,
				Ports:   []portMapping{{PrivatePort: 8123, PublicPort: 8123, Type: "tcp"}},
				Labels: map[string]string{
					"com.docker.compose.project": "vie",
					"com.docker.compose.service": "clickhouse",
				},
			},
			{
				ID:      "def789abc123456789012345",
				Names:   []string{"/one-shot"},
				Image:   "alpine:3.19",
				ImageID: "sha256:cafebabe",
				State:   "exited",
				Status:  "Exited (0) 2 hours ago",
				Created: 1700000100,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(containers)
	})

	mux.HandleFunc("/v1.43/containers/abc123def456789012345678/stats",
		func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "false", r.URL.Query().Get("stream"))
			assert.Equal(t, "true", r.URL.Query().Get("one-shot"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"cpu_stats": {"cpu_usage": {"total_usage": 500}, "system_cpu_usage": 10000, "online_cpus": 4},
				"memory_stats": {"usage": 2048, "limit": 4096, "stats": {"inactive_file": 1024}},
				"pids_stats": {"current": 7},
				"networks": {"eth0": {"rx_bytes": 100, "tx_bytes": 50}}
			}`))
		})

	mux.HandleFunc("/v1.43/images/json", func(w http.ResponseWriter, _ *http.Request) {
		images := []imageSummary{
			{ID: "sha256:deadbeefcafe", RepoTags: []string{"clickhouse/clickhouse-server:latest"}, Size: 1200, Created: 1690000000},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(images)
	})

	mux.HandleFunc("/v1.43/images/deadbeefcafe/history",
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
				{"Id": "sha256:deadbeefcafe", "Created": 1690000000, "CreatedBy": "/bin/sh -c #(nop)  CMD [\"clickhouse\"]", "Size": 0, "Tags": ["clickhouse/clickhouse-server:latest"]},
				{"Id": "<missing>", "Created": 1689990000, "CreatedBy": "/bin/sh -c apt-get update", "Size": 52428800, "Tags": null}
			]`))
		})

	return mux
}

func TestListLive_ParsesStateHealthAndComposeLabels(t *testing.T) {
	srv := newMockLiveAPI(t)
	lc := NewLiveClient(srv.URL)

	live, err := lc.ListLive(context.Background())
	require.NoError(t, err)
	require.Len(t, live, 2)

	ch := live[0]
	assert.Equal(t, "clickhouse", ch.Name)
	assert.Equal(t, "running", ch.State)
	assert.Equal(t, "healthy", ch.Health)
	assert.Equal(t, "Up 3 hours (healthy)", ch.Status)
	assert.Equal(t, "vie", ch.ComposeProject)
	assert.Equal(t, "clickhouse", ch.ComposeService)
	assert.Equal(t, "8123/tcp->8123", ch.Ports)

	exited := live[1]
	assert.Equal(t, "exited", exited.State)
	assert.Empty(t, exited.Health, "no health marker in status → empty health")
	assert.Empty(t, exited.ComposeProject)
}

func TestParseHealthFromStatus(t *testing.T) {
	assert.Equal(t, "healthy", parseHealthFromStatus("Up 2 hours (healthy)"))
	assert.Equal(t, "unhealthy", parseHealthFromStatus("Up 5 minutes (unhealthy)"))
	assert.Equal(t, "starting", parseHealthFromStatus("Up 10 seconds (health: starting)"))
	assert.Empty(t, parseHealthFromStatus("Up 2 hours"))
	assert.Empty(t, parseHealthFromStatus("Exited (0) 3 hours ago"))
}

func TestContainerStats_ReturnsRawDocumentAsMap(t *testing.T) {
	srv := newMockLiveAPI(t)
	lc := NewLiveClient(srv.URL)

	raw, err := lc.ContainerStats(context.Background(), "abc123def456789012345678")
	require.NoError(t, err)

	mem, ok := raw["memory_stats"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(2048), mem["usage"])
}

func TestContainerStats_RejectsUnsafeID(t *testing.T) {
	lc := NewLiveClient("http://localhost:0")
	_, err := lc.ContainerStats(context.Background(), "../secrets")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid container ID")
}

func TestImageHistory_StripsDigestPrefixAndParsesLayers(t *testing.T) {
	srv := newMockLiveAPI(t)
	lc := NewLiveClient(srv.URL)

	layers, err := lc.ImageHistory(context.Background(), "sha256:deadbeefcafe")
	require.NoError(t, err)
	require.Len(t, layers, 2)

	assert.Equal(t, "sha256:deadbeefcafe", layers[0].ID)
	assert.Equal(t, []string{"clickhouse/clickhouse-server:latest"}, layers[0].Tags)
	assert.Equal(t, "<missing>", layers[1].ID)
	assert.Equal(t, int64(52428800), layers[1].Size)
	assert.Contains(t, layers[1].CreatedBy, "apt-get update")
}

func TestImageHistory_RejectsRepoTagAndTraversal(t *testing.T) {
	lc := NewLiveClient("http://localhost:0")
	_, err := lc.ImageHistory(context.Background(), "repo/name:tag")
	require.Error(t, err, "repository references carry slashes and are rejected")
	_, err = lc.ImageHistory(context.Background(), "../../etc")
	require.Error(t, err)
}

func TestListImagesLive_ReturnsInventory(t *testing.T) {
	srv := newMockLiveAPI(t)
	lc := NewLiveClient(srv.URL)

	images, err := lc.ListImagesLive(context.Background())
	require.NoError(t, err)
	require.Len(t, images, 1)
	assert.Equal(t, int64(1200), images[0].Size)
	assert.Equal(t, []string{"clickhouse/clickhouse-server:latest"}, images[0].RepoTags)
}

// TestLiveClient_UnixSocketTransport exercises the transport branch every
// real deployment uses: the daemon behind unix:///var/run/docker.sock. All
// other tests dial TCP (httptest's default), so without this the socket
// DialContext path would ship untested.
func TestLiveClient_UnixSocketTransport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix domain sockets are not applicable on windows")
	}
	// A short base dir keeps the socket path under the ~108-byte sun_path
	// limit that a deeply nested TMPDIR would blow through.
	dir, err := os.MkdirTemp("", "kite-sock-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sock := filepath.Join(dir, "docker.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Skipf("cannot listen on unix socket in this environment: %v", err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: mockLiveAPIMux(t), ReadHeaderTimeout: 5 * time.Second}}
	srv.Start()
	t.Cleanup(srv.Close)

	lc := NewLiveClient("unix://" + sock)
	live, err := lc.ListLive(context.Background())
	require.NoError(t, err)
	require.Len(t, live, 2)
	assert.Equal(t, "clickhouse", live[0].Name)

	layers, err := lc.ImageHistory(context.Background(), "sha256:deadbeefcafe")
	require.NoError(t, err)
	assert.Len(t, layers, 2)
}

// TestContainerStats_HonorsContextTimeout pins the property the monitor
// relies on: a hung engine cannot stall a tick past its context deadline.
func TestContainerStats_HonorsContextTimeout(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/{id}/stats", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	lc := NewLiveClient(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := lc.ContainerStats(ctx, "abc123def456789012345678")
	require.Error(t, err)
	assert.Less(t, time.Since(start), 2*time.Second,
		"cancellation must propagate promptly, not wait out the client timeout")
}

func TestResolveHost_Precedence(t *testing.T) {
	assert.Equal(t, "tcp://explicit:2375", ResolveHost("tcp://explicit:2375"),
		"configured host wins")

	t.Setenv("KITE_DOCKER_HOST", "tcp://from-env:2375")
	assert.Equal(t, "tcp://from-env:2375", ResolveHost(""),
		"KITE_DOCKER_HOST beats socket autodetection")
}
