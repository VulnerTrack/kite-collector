package containers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// dockerAPIVersion is pinned to a widely-supported version; both Docker
// (≥20.10) and Podman (≥3.0) implement it. Higher versions degrade
// gracefully to whatever the engine supports.
const dockerAPIVersion = "v1.43"

// engineSocket returns the first reachable Docker/Podman-compatible socket
// path on this host, or "" when none is found. Order of precedence:
//
//  1. KITE_DOCKER_HOST env (operator override)
//  2. /var/run/docker.sock (Docker default; root or 'docker' group)
//  3. $XDG_RUNTIME_DIR/podman/podman.sock (Podman rootless)
//  4. /run/podman/podman.sock (Podman rootful)
//  5. /var/run/podman/podman.sock (Podman alt path)
func engineSocket() string {
	if v := os.Getenv("KITE_DOCKER_HOST"); v != "" {
		return v
	}
	candidates := []string{
		"/var/run/docker.sock",
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		candidates = append(candidates, xdg+"/podman/podman.sock")
	}
	candidates = append(candidates,
		"/run/podman/podman.sock",
		"/var/run/podman/podman.sock",
	)
	for _, p := range candidates {
		// Paths are either fixed literals or operator-supplied env values
		// (KITE_DOCKER_HOST, XDG_RUNTIME_DIR) — never network input.
		if fi, err := os.Stat(p); err == nil && fi.Mode()&os.ModeSocket != 0 { //#nosec G304,G703 -- operator-configured socket paths
			return "unix://" + p
		}
	}
	return ""
}

// dockerEngineCollector implements the Docker Engine API (used by both
// Docker and Podman — Podman is wire-compatible).
type dockerEngineCollector struct {
	socket  string
	baseURL string // origin to use in API requests (unix sockets use "http://docker", TCP uses the real URL)
	client  httpDoer
	runtime Runtime // "docker" or "podman" — best-effort detection
}

// httpDoer is the test seam — production uses the real *http.Client.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// NewDockerCollector returns a collector backed by the Docker Engine API.
// When the socket is unreachable Collect returns an empty slice (not an
// error) so the multi-runtime chain can move on to the next backend.
func NewDockerCollector() Collector {
	sock := engineSocket()
	return &dockerEngineCollector{
		socket:  sock,
		baseURL: baseURLFor(sock),
		client:  newDockerHTTPClient(sock),
		runtime: detectRuntime(sock),
	}
}

// baseURLFor returns the origin (scheme + host) to use when building
// Engine API URLs. Unix-socket transports require a syntactically valid
// HTTP URL even though the host is ignored by the dialer.
func baseURLFor(socket string) string {
	if strings.HasPrefix(socket, "unix://") || socket == "" {
		return "http://docker"
	}
	return strings.TrimRight(socket, "/")
}

func (c *dockerEngineCollector) Name() string { return "docker-engine" }

// detectRuntime infers Docker vs Podman from the socket path. Best-effort —
// a Podman socket symlinked into the Docker location reports as docker;
// that's acceptable because the wire format and column shape are identical.
func detectRuntime(socket string) Runtime {
	if strings.Contains(socket, "podman") {
		return RuntimePodman
	}
	return RuntimeDocker
}

// newDockerHTTPClient returns an *http.Client that dials unix:// or tcp://
// based on the socket scheme. Returns nil when socket is empty.
func newDockerHTTPClient(socket string) httpDoer {
	if socket == "" {
		return nil
	}
	if strings.HasPrefix(socket, "unix://") {
		sockPath := strings.TrimPrefix(socket, "unix://")
		return &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 10 * time.Second}).
						DialContext(ctx, "unix", sockPath)
				},
			},
		}
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// dockerContainerSummary mirrors the subset of /containers/json fields we
// consume. Engine returns many more, but we project to what host_containers
// actually needs.
type dockerContainerSummary struct {
	Labels          map[string]string `json:"Labels"`
	NetworkSettings struct {
		Networks map[string]struct{} `json:"Networks"`
	} `json:"NetworkSettings"`
	ID         string `json:"Id"`
	Image      string `json:"Image"`
	ImageID    string `json:"ImageID"`
	Command    string `json:"Command"`
	State      string `json:"State"`
	Status     string `json:"Status"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	Names  []string           `json:"Names"`
	Ports  []dockerPortEntry  `json:"Ports"`
	Mounts []dockerMountEntry `json:"Mounts"`
}

type dockerPortEntry struct {
	IP          string `json:"IP,omitempty"`
	Type        string `json:"Type"`
	PrivatePort uint16 `json:"PrivatePort"`
	PublicPort  uint16 `json:"PublicPort,omitempty"`
}

type dockerMountEntry struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

// dockerInspect mirrors the subset of /containers/{id}/json fields we
// consume for security posture (privileged, host_network, user).
type dockerInspect struct {
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
		PidMode     string `json:"PidMode"`
		Privileged  bool   `json:"Privileged"`
	} `json:"HostConfig"`
	Config struct {
		User string `json:"User"`
	} `json:"Config"`
	Image string `json:"Image"`
	State struct {
		Status     string `json:"Status"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
		ExitCode   int    `json:"ExitCode"`
	} `json:"State"`
}

// Collect lists containers and inspects each for security posture.
func (c *dockerEngineCollector) Collect(ctx context.Context) ([]Container, error) {
	if c.client == nil {
		return []Container{}, nil
	}
	summaries, err := c.listContainers(ctx)
	if err != nil {
		// Socket present but unresponsive — log via returned error so the
		// engine chain can decide what to do.
		return []Container{}, fmt.Errorf("docker engine list: %w", err)
	}
	if len(summaries) > MaxContainers {
		summaries = summaries[:MaxContainers]
	}

	out := make([]Container, 0, len(summaries))
	for _, s := range summaries {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-collect: %w", err)
		}
		out = append(out, c.summarize(ctx, s))
	}
	SortContainers(out)
	return out, nil
}

// listContainers calls /containers/json?all=true (include stopped).
func (c *dockerEngineCollector) listContainers(ctx context.Context) ([]dockerContainerSummary, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/"+dockerAPIVersion+"/containers/json?all=true", nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("read list body: %w", err)
	}
	var out []dockerContainerSummary
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode list: %w", err)
	}
	return out, nil
}

// inspect calls /containers/{id}/json to fetch security posture fields not
// available in the summary listing.
func (c *dockerEngineCollector) inspect(ctx context.Context, id string) (*dockerInspect, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/"+dockerAPIVersion+"/containers/"+id+"/json", nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("inspect request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inspect returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("read inspect body: %w", err)
	}
	var out dockerInspect
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode inspect: %w", err)
	}
	return &out, nil
}

// summarize converts a summary + inspect-detail into our Container shape.
// inspect failures are non-fatal — we still emit a row with partial fields.
func (c *dockerEngineCollector) summarize(ctx context.Context, s dockerContainerSummary) Container {
	name := ""
	if len(s.Names) > 0 {
		name = strings.TrimPrefix(s.Names[0], "/")
	}
	cn := Container{
		Runtime:     c.runtime,
		ContainerID: s.ID,
		Name:        name,
		Image:       s.Image,
		ImageID:     s.ImageID,
		State:       NormalizeState(s.State),
		Status:      s.Status,
		Command:     s.Command,
		Ports:       toPortMappings(s.Ports),
		Mounts:      toMounts(s.Mounts),
		Networks:    networkKeys(s.NetworkSettings.Networks),
		Labels:      s.Labels,
		HostNetwork: strings.EqualFold(s.HostConfig.NetworkMode, "host"),
	}
	if detail, err := c.inspect(ctx, s.ID); err == nil && detail != nil {
		cn.Privileged = detail.HostConfig.Privileged
		cn.HostNetwork = cn.HostNetwork ||
			strings.EqualFold(detail.HostConfig.NetworkMode, "host")
		cn.HostPID = strings.EqualFold(detail.HostConfig.PidMode, "host")
		cn.StartedAt = detail.State.StartedAt
		cn.FinishedAt = detail.State.FinishedAt
		cn.ExitCode = detail.State.ExitCode
		cn.ImageDigest = detail.Image
		// Config.User is "uid" or "uid:gid" or "username[:group]" or "".
		// Empty user means the image's USER directive applies — assume
		// root unless we can prove otherwise.
		uid := parseRootUID(detail.Config.User)
		cn.RootUID = uid
	}
	return cn
}

// parseRootUID returns:
//   - &0 when User is empty (image-default, conservatively root)
//   - &0 when User starts with "0" or "root"
//   - &uid when User is a numeric uid > 0
//   - nil when User is a non-numeric username we can't resolve (unknown)
func parseRootUID(user string) *int {
	if user == "" {
		zero := 0
		return &zero
	}
	if strings.HasPrefix(user, "root:") || user == "root" {
		zero := 0
		return &zero
	}
	// Numeric uid (optionally followed by ":gid")
	uidStr := user
	if i := strings.IndexByte(user, ':'); i >= 0 {
		uidStr = user[:i]
	}
	uid := 0
	for _, c := range uidStr {
		if c < '0' || c > '9' {
			return nil // non-numeric username — can't resolve to uid here
		}
		uid = uid*10 + int(c-'0')
	}
	return &uid
}

func toPortMappings(ps []dockerPortEntry) []PortMapping {
	out := make([]PortMapping, 0, len(ps))
	for _, p := range ps {
		out = append(out, PortMapping{
			HostIP:        p.IP,
			HostPort:      p.PublicPort,
			ContainerPort: p.PrivatePort,
			Proto:         p.Type,
		})
	}
	return out
}

func toMounts(ms []dockerMountEntry) []Mount {
	out := make([]Mount, 0, len(ms))
	for _, m := range ms {
		out = append(out, Mount{
			Type:        m.Type,
			Source:      m.Source,
			Destination: m.Destination,
			ReadOnly:    !m.RW,
		})
	}
	return out
}

func networkKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ErrSocketUnreachable is returned by Collect when the engine socket is
// configured but the daemon doesn't answer (so the caller can fall through
// to the next runtime in the chain without treating it as a hard failure).
var ErrSocketUnreachable = errors.New("container engine socket unreachable")
