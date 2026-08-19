// Live-view operations over the same raw Engine-API HTTP client that
// Discover uses. These power the dashboard's Containers page: an
// at-a-glance list of every container, one-shot resource stats for
// custom metric graphs, and the ancestor-layer history of an image.
//
// The operation set is ported from lazydocker (ContainerList,
// ContainerStats, ImageHistory) but keeps this package's no-SDK rule:
// everything is a plain HTTP GET against the Engine API.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/safenet"
)

// ResolveHost resolves the Docker/Podman Engine endpoint using the same
// precedence Discover applies: explicit value → KITE_DOCKER_HOST env →
// socket auto-detection. Returns "" when no engine is reachable, which
// callers should surface as "Docker unavailable" rather than an error.
func ResolveHost(configured string) string {
	if configured != "" {
		return configured
	}
	if env := os.Getenv("KITE_DOCKER_HOST"); env != "" {
		return env
	}
	return detectSocket()
}

// LiveClient exposes the live-view Engine API operations. It is a thin
// exported facade over the unexported dockerClient so the dashboard can
// reuse the socket/TCP transport without this package growing an SDK.
type LiveClient struct {
	c *dockerClient
}

// NewLiveClient returns a client for the given engine host
// (unix:///var/run/docker.sock, tcp://..., or http://...).
func NewLiveClient(host string) *LiveClient {
	return &LiveClient{c: newClient(host)}
}

// LiveContainer is one at-a-glance row of the container environment:
// identity, compose grouping, state, and parsed health.
type LiveContainer struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Image          string            `json:"image"`
	ImageID        string            `json:"image_id"`
	State          string            `json:"state"`  // created/running/paused/restarting/exited/dead
	Health         string            `json:"health"` // healthy/unhealthy/starting/"" (no healthcheck)
	Status         string            `json:"status"` // human text, e.g. "Up 2 hours (healthy)"
	ComposeProject string            `json:"compose_project,omitempty"`
	ComposeService string            `json:"compose_service,omitempty"`
	Ports          string            `json:"ports,omitempty"`
	Labels         map[string]string `json:"-"`
	Created        time.Time         `json:"created"`
}

// ListLive returns every container (running or not) with compose grouping
// and health parsed out of the summary status text — one API call, no
// per-container inspects, so it is cheap enough to run on every render.
func (lc *LiveClient) ListLive(ctx context.Context) ([]LiveContainer, error) {
	containers, err := lc.c.listContainers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]LiveContainer, 0, len(containers))
	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		out = append(out, LiveContainer{
			ID:             c.ID,
			Name:           name,
			Image:          c.Image,
			ImageID:        c.ImageID,
			State:          c.State,
			Health:         parseHealthFromStatus(c.Status),
			Status:         c.Status,
			ComposeProject: c.Labels["com.docker.compose.project"],
			ComposeService: c.Labels["com.docker.compose.service"],
			Ports:          formatPorts(c.Ports),
			Labels:         c.Labels,
			Created:        time.Unix(c.Created, 0).UTC(),
		})
	}
	return out, nil
}

// parseHealthFromStatus extracts the health state the daemon embeds in the
// summary status text ("Up 2 hours (healthy)", "(health: starting)").
// Parsing the summary avoids one inspect round-trip per container.
func parseHealthFromStatus(status string) string {
	switch {
	case strings.Contains(status, "(healthy)"):
		return "healthy"
	case strings.Contains(status, "(unhealthy)"):
		return "unhealthy"
	case strings.Contains(status, "(health: starting)"):
		return "starting"
	}
	return ""
}

// ContainerStats fetches a single resource-usage sample for one container
// and returns the raw stats document as a generic map. one-shot=true skips
// the daemon's 1s pre-cpu priming pause; callers derive CPU% from deltas
// between their own consecutive samples (the lazydocker approach), which
// keeps a fleet-wide poll from blocking N seconds per tick.
//
// The generic map — rather than a typed struct — is deliberate: it lets
// operators graph ANY numeric field the daemon reports by dotted path
// (e.g. "memory_stats.stats.pgmajfault") without this package needing to
// enumerate every field of every engine version.
func (lc *LiveClient) ContainerStats(ctx context.Context, id string) (map[string]any, error) {
	safeID, err := safenet.SanitizePathSegment(id)
	if err != nil {
		return nil, fmt.Errorf("invalid container ID: %w", err)
	}
	body, err := lc.c.get(ctx, "/containers/"+safeID+"/stats?stream=false&one-shot=true")
	if err != nil {
		return nil, err
	}
	var stats map[string]any
	if err = json.Unmarshal(body, &stats); err != nil {
		return nil, fmt.Errorf("parse stats: %w", err)
	}
	return stats, nil
}

// ImageLayer is one ancestor layer of an image, oldest instruction last as
// returned by the Engine API (same order `docker history` prints).
type ImageLayer struct {
	ID        string    `json:"id"`         // layer ID or "<missing>" for squashed intermediates
	CreatedBy string    `json:"created_by"` // the Dockerfile instruction that produced the layer
	Comment   string    `json:"comment,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	Size      int64     `json:"size"`
	Created   time.Time `json:"created"`
}

// ImageHistory returns the ancestor layers of an image — the equivalent of
// lazydocker's image History panel / `docker history`. Accepts image IDs
// only (full "sha256:..." or bare hex, long or short) — repo:tag references
// are rejected because repository names contain slashes, and every caller
// already holds the ID from the container or image listing.
func (lc *LiveClient) ImageHistory(ctx context.Context, id string) ([]ImageLayer, error) {
	safeID, err := sanitizeImageID(id)
	if err != nil {
		return nil, err
	}
	body, err := lc.c.get(ctx, "/images/"+safeID+"/history")
	if err != nil {
		return nil, err
	}
	var raw []struct {
		ID        string   `json:"Id"`
		CreatedBy string   `json:"CreatedBy"`
		Comment   string   `json:"Comment"`
		Tags      []string `json:"Tags"`
		Size      int64    `json:"Size"`
		Created   int64    `json:"Created"`
	}
	if err = json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse image history: %w", err)
	}
	layers := make([]ImageLayer, 0, len(raw))
	for _, l := range raw {
		layers = append(layers, ImageLayer{
			ID:        l.ID,
			CreatedBy: l.CreatedBy,
			Comment:   l.Comment,
			Tags:      l.Tags,
			Size:      l.Size,
			Created:   time.Unix(l.Created, 0).UTC(),
		})
	}
	return layers, nil
}

// ImageInfo is one row of the image inventory shown alongside containers.
type ImageInfo struct {
	ID       string    `json:"id"`
	RepoTags []string  `json:"repo_tags,omitempty"`
	Size     int64     `json:"size"`
	Created  time.Time `json:"created"`
}

// ListImagesLive returns the engine's image inventory.
func (lc *LiveClient) ListImagesLive(ctx context.Context) ([]ImageInfo, error) {
	images, err := lc.c.listImages(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ImageInfo, 0, len(images))
	for _, img := range images {
		out = append(out, ImageInfo{
			ID:       img.ID,
			RepoTags: img.RepoTags,
			Size:     img.Size,
			Created:  time.Unix(img.Created, 0).UTC(),
		})
	}
	return out, nil
}

// sanitizeImageID validates an image ID for use as a URL path segment.
// Image IDs carry a "sha256:" digest prefix that SanitizePathSegment
// rejects; the Engine API resolves the bare hex just as well, so the
// prefix is stripped rather than escaped.
func sanitizeImageID(id string) (string, error) {
	if rest, ok := strings.CutPrefix(id, "sha256:"); ok {
		id = rest
	}
	safeID, err := safenet.SanitizePathSegment(id)
	if err != nil {
		return "", fmt.Errorf("invalid image ID: %w", err)
	}
	return safeID, nil
}
