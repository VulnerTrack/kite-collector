package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// -------------------------------------------------------------------------
// Mock Docker API server
// -------------------------------------------------------------------------

func newMockDockerAPI(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		containers := []containerSummary{
			{
				ID:      "abc123def456789012345678",
				Names:   []string{"/nginx-web"},
				Image:   "nginx:1.25",
				ImageID: "sha256:deadbeef",
				State:   "running",
				Created: 1700000000,
				Ports: []portMapping{
					{PrivatePort: 80, PublicPort: 8080, Type: "tcp"},
				},
				Labels: map[string]string{
					"com.docker.compose.project": "myapp",
				},
			},
			{
				ID:      "def789abc123456789012345",
				Names:   []string{"/redis-cache"},
				Image:   "redis:7",
				ImageID: "sha256:cafebabe",
				State:   "running",
				Created: 1700000100,
				Labels:  map[string]string{},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(containers)
	})

	mux.HandleFunc("/v1.43/containers/abc123def456789012345678/json",
		func(w http.ResponseWriter, _ *http.Request) {
			detail := containerDetail{}
			detail.HostConfig.Privileged = true
			detail.HostConfig.NetworkMode = "host"
			detail.HostConfig.PidMode = "host"
			detail.HostConfig.RestartPolicy.Name = "always"
			detail.HostConfig.Binds = []string{"/data:/var/lib/data:rw"}
			detail.Config.User = ""
			detail.Config.Healthcheck = &struct {
				Test []string `json:"Test"`
			}{
				Test: []string{"CMD", "curl", "-f", "http://localhost/"},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(detail)
		})

	mux.HandleFunc("/v1.43/containers/def789abc123456789012345/json",
		func(w http.ResponseWriter, _ *http.Request) {
			detail := containerDetail{}
			detail.HostConfig.Privileged = false
			detail.HostConfig.NetworkMode = "bridge"
			detail.HostConfig.RestartPolicy.Name = "no"
			detail.Config.User = "appuser"
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(detail)
		})

	mux.HandleFunc("/v1.43/images/json", func(w http.ResponseWriter, _ *http.Request) {
		images := []imageSummary{
			{ID: "sha256:deadbeef", RepoTags: []string{"nginx:1.25"}, RepoDigests: []string{"nginx@sha256:1111"}, Size: 150_000_000, Created: 1700000000},
			{ID: "sha256:cafebabe", RepoTags: []string{"redis:7"}, RepoDigests: []string{"redis@sha256:2222", "docker.io/library/redis@sha256:2222"}, Size: 120_000_000, Created: 1700000100},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(images)
	})

	return httptest.NewServer(mux)
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

func TestDocker_Name(t *testing.T) {
	d := New()
	assert.Equal(t, "docker", d.Name())
}

func TestDocker_Discover_Success(t *testing.T) {
	srv := newMockDockerAPI(t)
	defer srv.Close()

	d := New()
	cfg := map[string]any{"host": srv.URL}

	machines, err := d.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Len(t, machines, 2)

	// Verify first container.
	nginx := machines[0]
	assert.Equal(t, "nginx-web", nginx.Hostname)
	assert.Equal(t, model.MachineTypeContainer, nginx.MachineType)
	assert.Equal(t, "linux", nginx.OSFamily)
	assert.Equal(t, "nginx:1.25", nginx.OSVersion)
	assert.Equal(t, "docker", nginx.DiscoverySource)
	assert.Equal(t, model.AuthorizationUnknown, nginx.IsAuthorized)

	// Verify tags contain security metadata.
	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(nginx.Tags), &tags))
	assert.Equal(t, true, tags["privileged"])
	assert.Equal(t, "host", tags["network_mode"])
	assert.Equal(t, "host", tags["pid_mode"])
	assert.Equal(t, "always", tags["restart_policy"])
	assert.Equal(t, true, tags["healthcheck"])
	assert.Equal(t, "myapp", tags["compose_project"])
	assert.Equal(t, "80/tcp->8080", tags["ports"])

	// Identity hashes: short id for display, full id + both image digests
	// for matching.
	assert.Equal(t, "abc123def456", tags["container_id"])
	assert.Equal(t, "abc123def456789012345678", tags[model.TagContainerID])
	assert.Equal(t, "sha256:deadbeef", tags[model.TagImageID])
	assert.Equal(t, "sha256:1111", tags[model.TagImageDigest])
	assert.Equal(t, []any{"nginx@sha256:1111"}, tags[model.TagImageRepoDigests])

	// Services: nginx from the image, http from the exposed port, folded.
	nginxServices := model.ServicesFromTags(nginx.Tags)
	require.Len(t, nginxServices, 2)
	assert.Equal(t, model.MachineService{Name: "http", Category: model.ServiceCategoryWeb, Port: 80, Protocol: "tcp", Exposure: "published", Source: "port"}, nginxServices[0])
	assert.Equal(t, model.MachineService{Name: "nginx", Category: model.ServiceCategoryWeb, Version: "1.25", Source: "image"}, nginxServices[1])

	// Verify second container (non-privileged).
	redis := machines[1]
	assert.Equal(t, "redis-cache", redis.Hostname)

	var redisTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(redis.Tags), &redisTags))
	assert.Equal(t, false, redisTags["privileged"])
	assert.Equal(t, "bridge", redisTags["network_mode"])
	assert.Equal(t, "appuser", redisTags["user"])
	assert.Equal(t, "sha256:2222", redisTags[model.TagImageDigest])
	assert.Equal(t, []any{"docker.io/library/redis@sha256:2222", "redis@sha256:2222"}, redisTags[model.TagImageRepoDigests], "repo digests are sorted")

	// The lifecycle event lifts the hashes and services off the tags.
	var evt model.MachineEvent
	evt.FromMachine(redis)
	assert.Equal(t, "def789abc123456789012345", evt.ContainerID)
	assert.Equal(t, "sha256:cafebabe", evt.ImageID)
	assert.Equal(t, "sha256:2222", evt.ImageDigest)
	require.Len(t, evt.Services, 1)
	assert.Equal(t, "redis", evt.Services[0].Name)
	assert.Equal(t, model.ServiceCategoryCache, evt.Services[0].Category)
}

func TestImageDigestIndexAndContentDigest(t *testing.T) {
	idx := imageDigestIndex([]imageSummary{
		{ID: "sha256:a", RepoDigests: []string{"z@sha256:1", "a@sha256:1", ""}},
		{ID: "sha256:b", RepoDigests: []string{"<none>@<none>"}},
		{ID: "sha256:c"},
		{ID: ""},
	})
	assert.Equal(t, map[string][]string{"sha256:a": {"a@sha256:1", "z@sha256:1"}}, idx)
	assert.Equal(t, "sha256:1", contentDigest(idx["sha256:a"]))
	assert.Equal(t, "", contentDigest(nil))
	assert.Equal(t, "", contentDigest([]string{"broken@"}))
}

func TestContainerServices(t *testing.T) {
	// Unrecognised custom image: the well-known ports still name services;
	// ambiguous and duplicate ports do not.
	services := containerServices(containerSummary{
		Image: "ghcr.io/acme/backend:v3",
		Ports: []portMapping{
			{PrivatePort: 5432, Type: "tcp"},
			{PrivatePort: 5432, PublicPort: 15432, Type: "tcp"},
			{PrivatePort: 9000, Type: "tcp"},
			{PrivatePort: 389, PublicPort: 389, Type: "tcp"},
		},
	})
	require.Len(t, services, 2)
	assert.Equal(t, "postgresql", services[0].Name)
	assert.Equal(t, "published", services[0].Exposure, "published by its second host binding")
	assert.Equal(t, "ldap", services[1].Name)
	assert.Equal(t, "published", services[1].Exposure)

	// Samba AD DC image → Active Directory, plus its well-known ports.
	services = containerServices(containerSummary{
		Image: "nowsci/samba-domain:latest",
		Ports: []portMapping{{PrivatePort: 389, Type: "tcp"}, {PrivatePort: 88, Type: "tcp"}, {PrivatePort: 445, Type: "tcp"}},
	})
	cats := model.ServiceCategories(services)
	assert.Equal(t, []string{model.ServiceCategoryDirectory, model.ServiceCategoryFileSharing}, cats)
	names := make([]string, 0, len(services))
	for _, s := range services {
		names = append(names, s.Name)
	}
	assert.ElementsMatch(t, []string{"active_directory", "ldap", "kerberos", "smb"}, names)

	assert.Nil(t, containerServices(containerSummary{Image: "ghcr.io/acme/backend:v3"}))
}

func TestDocker_Discover_UnreachableHost(t *testing.T) {
	d := New()
	cfg := map[string]any{"host": "unix:///tmp/nonexistent-kite-test.sock"}
	_, err := d.Discover(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "docker: list containers")
}

func TestDocker_Discover_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	d := New()
	cfg := map[string]any{"host": srv.URL}

	_, err := d.Discover(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list containers")
}

func TestContainerToMachine_UUIDv7(t *testing.T) {
	srv := newMockDockerAPI(t)
	defer srv.Close()

	d := New()
	cfg := map[string]any{"host": srv.URL}

	machines, err := d.Discover(context.Background(), cfg)
	require.NoError(t, err)

	for _, a := range machines {
		assert.NotEmpty(t, a.ID, "machine must have a UUID")
	}
}

func TestFormatPorts(t *testing.T) {
	tests := []struct {
		name   string
		expect string
		ports  []portMapping
	}{
		{"empty", "", nil},
		{"public", "80/tcp->8080", []portMapping{{Type: "tcp", PrivatePort: 80, PublicPort: 8080}}},
		{"private_only", "6379/tcp", []portMapping{{Type: "tcp", PrivatePort: 6379}}},
		{"multiple", "80/tcp->8080, 443/tcp->8443", []portMapping{
			{Type: "tcp", PrivatePort: 80, PublicPort: 8080},
			{Type: "tcp", PrivatePort: 443, PublicPort: 8443},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, formatPorts(tt.ports))
		})
	}
}

func TestDetectSocket_NoSocket(t *testing.T) {
	// In a test environment, Docker/Podman sockets likely don't exist.
	// Just verify the function doesn't panic.
	_ = detectSocket()
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "abc", truncate("abcdef", 3))
	assert.Equal(t, "ab", truncate("ab", 5))
	assert.Equal(t, "", truncate("", 3))
}
