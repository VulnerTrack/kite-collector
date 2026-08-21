package docker

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newEnvDockerAPI serves one running container WITH Config.Env, one
// running container without env (skipped), and one exited container
// (skipped) — the exact filter matrix ListContainerEnvs applies.
func newEnvDockerAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"Id":"aaaaaaaaaaaaaaaaaaaaaaaa","Names":["/api"],"Image":"redis:7","State":"running"},
			{"Id":"bbbbbbbbbbbbbbbbbbbbbbbb","Names":["/bare"],"Image":"scratch","State":"running"},
			{"Id":"cccccccccccccccccccccccc","Names":["/old"],"Image":"redis:7","State":"exited"}
		]`))
	})
	mux.HandleFunc("/v1.43/containers/aaaaaaaaaaaaaaaaaaaaaaaa/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Name":"/api","Config":{"Env":["AWS_ACCESS_KEY_ID=AKIA","PATH=/bin"]}}`))
	})
	mux.HandleFunc("/v1.43/containers/bbbbbbbbbbbbbbbbbbbbbbbb/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Name":"/bare","Config":{"Env":[]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// ListContainerEnvs walks the same list+inspect pipeline as Discover:
// only RUNNING containers WITH env vars surface, and host resolution
// honours cfg over env over socket detection.
func TestListContainerEnvs(t *testing.T) {
	srv := newEnvDockerAPI(t)

	envs, err := (&Docker{}).ListContainerEnvs(context.Background(),
		map[string]any{"host": srv.URL})
	require.NoError(t, err)
	require.Len(t, envs, 1, "env-less and exited containers are skipped")
	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaa", envs[0].ID)
	assert.Equal(t, "api", envs[0].Name, "the leading slash is trimmed")
	assert.Equal(t, []string{"AWS_ACCESS_KEY_ID=AKIA", "PATH=/bin"}, envs[0].Env)

	// KITE_DOCKER_HOST is the fallback when cfg carries no host.
	t.Setenv("KITE_DOCKER_HOST", srv.URL)
	envs2, err := (&Docker{}).ListContainerEnvs(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, len(envs), len(envs2))
}

func TestListContainerEnvs_NoHostAnywhere(t *testing.T) {
	t.Setenv("KITE_DOCKER_HOST", "")
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir()) // no podman socket in here
	// detectSocket probes fixed well-known paths; on hosts where a real
	// docker.sock exists this test would dial it, so only assert the
	// no-socket branch when detection finds nothing.
	if detectSocket() != "" {
		t.Skip("a real container runtime socket exists on this host")
	}
	_, err := (&Docker{}).ListContainerEnvs(context.Background(), nil)
	require.Error(t, err, "no host, no env, no socket → explicit error")
}

// The unix:// transport branch: the same API served over a unix socket.
func TestListContainerEnvs_UnixSocket(t *testing.T) {
	srv := newEnvDockerAPI(t)

	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	require.NoError(t, err)
	proxy := &http.Server{Handler: srv.Config.Handler} //#nosec G112 -- test-local unix socket server
	go func() { _ = proxy.Serve(ln) }()
	defer func() { _ = proxy.Close() }()

	envs, err := (&Docker{}).ListContainerEnvs(context.Background(),
		map[string]any{"host": "unix://" + sock})
	require.NoError(t, err)
	assert.NotEmpty(t, envs)
}

func TestToString(t *testing.T) {
	assert.Equal(t, "x", toString("x"))
	assert.Equal(t, "", toString(nil))
	assert.Equal(t, "", toString(42), "non-strings decay to empty")
}
