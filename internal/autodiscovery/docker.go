package autodiscovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

const dockerAPIVersion = "v1.43"

// probeDockerContainers queries the Docker/Podman Engine API for running
// containers and matches them against known service signatures by image name
// and container name.
func probeDockerContainers(ctx context.Context, socketPath string, services []ServiceSignature) []DiscoveredService {
	client := newDockerProbeClient(socketPath)

	containers, err := client.listContainers(ctx)
	if err != nil {
		slog.Warn("autodiscovery: docker probe failed", "error", err)
		return nil
	}

	var results []DiscoveredService

	for _, c := range containers {
		for _, sig := range services {
			if !matchContainer(c, sig) {
				continue
			}

			endpoint := containerEndpoint(c, sig)
			status, missing := determineStatus(sig)

			results = append(results, DiscoveredService{
				Name:        sig.Name,
				DisplayName: sig.DisplayName,
				Endpoint:    endpoint,
				Method:      "docker_container",
				Status:      status,
				Credentials: missing,
				SetupHint:   sig.SetupHint,
			})
			break // one match per container
		}
	}

	return results
}

// matchContainer checks if a container matches a service signature by image
// name prefix or container name substring.
func matchContainer(c dockerContainer, sig ServiceSignature) bool {
	for _, img := range sig.DockerImages {
		if strings.HasPrefix(c.Image, img) {
			return true
		}
	}
	for _, pat := range sig.DockerNames {
		for _, name := range c.Names {
			cleaned := strings.TrimPrefix(name, "/")
			if strings.Contains(cleaned, pat) {
				return true
			}
		}
	}
	return false
}

// containerEndpoint determines the best reachable endpoint for a container.
// It prefers host-mapped ports, falling back to the container name with the
// service's default port.
func containerEndpoint(c dockerContainer, sig ServiceSignature) string {
	// Look for a host-mapped port matching a known default port.
	for _, p := range c.Ports {
		if p.PublicPort <= 0 {
			continue
		}
		for _, dp := range sig.DefaultPorts {
			if p.PrivatePort == dp {
				host := "127.0.0.1"
				if p.IP != "" && p.IP != "0.0.0.0" {
					host = p.IP
				}
				return buildEndpoint(host, p.PublicPort, sig.TLS)
			}
		}
	}

	// If any host port is mapped, use the first one.
	for _, p := range c.Ports {
		if p.PublicPort > 0 {
			host := "127.0.0.1"
			if p.IP != "" && p.IP != "0.0.0.0" {
				host = p.IP
			}
			return buildEndpoint(host, p.PublicPort, sig.TLS)
		}
	}

	// Fall back to container name with default port.
	name := containerName(c)
	if name != "" && len(sig.DefaultPorts) > 0 {
		return buildEndpoint(name, sig.DefaultPorts[0], sig.TLS)
	}

	return name
}

func containerName(c dockerContainer) string {
	if len(c.Names) == 0 {
		return ""
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

// -------------------------------------------------------------------------
// Minimal Docker API client
// -------------------------------------------------------------------------

type dockerProbeClient struct {
	http *http.Client
	base string
}

func newDockerProbeClient(socketPath string) *dockerProbeClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &dockerProbeClient{
		base: "http://localhost",
		http: &http.Client{Transport: transport, Timeout: 10 * time.Second},
	}
}

type dockerContainer struct {
	ID    string              `json:"Id"`
	Image string              `json:"Image"`
	Names []string            `json:"Names"`
	State string              `json:"State"`
	Ports []dockerPortMapping `json:"Ports"`
}

type dockerPortMapping struct {
	IP          string `json:"IP"`
	Type        string `json:"Type"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
}

func (c *dockerProbeClient) listContainers(ctx context.Context) ([]dockerContainer, error) {
	url := fmt.Sprintf("%s/%s/containers/json", c.base, dockerAPIVersion)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //#nosec G107 -- localhost Docker API
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker API request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker API HTTP %d", resp.StatusCode)
	}

	var containers []dockerContainer
	if err = json.Unmarshal(body, &containers); err != nil {
		return nil, fmt.Errorf("parse containers: %w", err)
	}

	return containers, nil
}
