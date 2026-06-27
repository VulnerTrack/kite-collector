// Package containers enumerates per-host container inventory from any
// installed runtime (Docker, Podman, containerd, CRI-O, LXC). Distinct
// from internal/discovery/docker which emits assets at the *cross-host*
// inventory level — this package emits the per-host child records that
// feed CWE-732 / CWE-269 / CWE-668 audit rules.
//
// Every collector is **read-only** — it queries the runtime API, never
// starts, stops, removes, exec's into, or modifies any container.
// Read-only is enforced by guideline 4.2 of the kite-collector project.
//
// Container rows feed the CWE/CAPEC audit pipeline:
//
//   - CWE-732 (Incorrect Permission Assignment) — `privileged=1` (the
//     --privileged flag) effectively grants the container access to all
//     host devices and capabilities.
//   - CWE-269 (Improper Privilege Management) — `root_uid=0` (running
//     as root inside) combined with mounts from /etc, /var/run, /proc.
//   - CWE-668 (Exposure of Resource to Wrong Sphere) — `host_network=1`
//     (--network=host) bypasses the container's network namespace.
//   - Supply-chain — `image_digest` joins to SBOM rows for known-vuln
//     pinning across the fleet.
package containers

import (
	"context"
	"encoding/json"
	"sort"
)

// MaxContainers bounds per-scan output. A typical host has 5-50 containers;
// a Kubernetes node might have 100-200. The 4096 ceiling protects the
// SQLite write path from a misconfigured runaway Compose stack.
const MaxContainers = 4096

// Runtime is the source-of-record for a container row. Strings are pinned
// to the host_containers.runtime CHECK enum.
type Runtime string

const (
	RuntimeDocker     Runtime = "docker"
	RuntimePodman     Runtime = "podman"
	RuntimeContainerd Runtime = "containerd"
	RuntimeCRIO       Runtime = "cri-o"
	RuntimeLXC        Runtime = "lxc"
	RuntimeUnknown    Runtime = "unknown"
)

// State normalises lifecycle state. Strings are pinned to the
// host_containers.state CHECK enum.
type State string

const (
	StateCreated    State = "created"
	StateRunning    State = "running"
	StatePaused     State = "paused"
	StateRestarting State = "restarting"
	StateExited     State = "exited"
	StateDead       State = "dead"
	StateUnknown    State = "unknown"
)

// PortMapping is a single host:container port forward.
type PortMapping struct {
	Proto         string `json:"proto"` // "tcp" | "udp"
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      uint16 `json:"host_port,omitempty"`
	ContainerPort uint16 `json:"container_port"`
}

// Mount is a single bind/volume mount on a container.
type Mount struct {
	Source      string `json:"src"`
	Destination string `json:"dst"`
	Type        string `json:"type"` // "bind" | "volume" | "tmpfs"
	ReadOnly    bool   `json:"ro"`
}

// Container is the cross-runtime record produced by every collector. It
// mirrors the column shape of host_containers — the slice/map fields are
// JSON-encoded when persisted (see EncodePorts/EncodeMounts helpers).
type Container struct {
	RootUID     *int              `json:"root_uid,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	ImageDigest string            `json:"image_digest,omitempty"`
	Name        string            `json:"name,omitempty"`
	ImageID     string            `json:"image_id,omitempty"`
	Runtime     Runtime           `json:"runtime"`
	State       State             `json:"state"`
	Status      string            `json:"status,omitempty"`
	Command     string            `json:"command,omitempty"`
	StartedAt   string            `json:"started_at,omitempty"`
	FinishedAt  string            `json:"finished_at,omitempty"`
	ContainerID string            `json:"container_id"`
	Image       string            `json:"image,omitempty"`
	Ports       []PortMapping     `json:"ports,omitempty"`
	Mounts      []Mount           `json:"mounts,omitempty"`
	Networks    []string          `json:"networks,omitempty"`
	ExitCode    int               `json:"exit_code,omitempty"`
	HostNetwork bool              `json:"host_network"`
	HostPID     bool              `json:"host_pid"`
	Privileged  bool              `json:"privileged"`
}

// Collector is the read-only contract every runtime implementation
// satisfies.
type Collector interface {
	// Name returns a stable identifier for telemetry (e.g. "docker-engine").
	Name() string
	// Collect enumerates containers from this runtime. Read-only. Returns
	// an empty slice when the runtime is not running on this host (the
	// Docker socket doesn't exist, containerd isn't installed, etc) —
	// callers can then try the next runtime in the chain.
	Collect(ctx context.Context) ([]Container, error)
}

// EncodePorts returns a JSON array suitable for the ports_json column.
// Empty slice returns "[]" (not "null") so the column is never NULL.
func EncodePorts(ps []PortMapping) string {
	if len(ps) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ps)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// EncodeMounts returns a JSON array suitable for the mounts_json column.
func EncodeMounts(ms []Mount) string {
	if len(ms) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ms)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// EncodeStrings returns a JSON array suitable for networks_json and
// similar string-slice columns.
func EncodeStrings(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// EncodeLabels returns a JSON object suitable for the labels_json column.
func EncodeLabels(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// NormalizeState maps runtime-specific status strings to our pinned enum.
// Docker uses "created"/"running"/"paused"/"restarting"/"exited"/"dead";
// Podman uses the same (it implements the Docker API). containerd uses
// "CREATED"/"RUNNING"/"PAUSED"/"STOPPED"/"UNKNOWN".
func NormalizeState(raw string) State {
	switch toLowerASCII(raw) {
	case "created":
		return StateCreated
	case "running":
		return StateRunning
	case "paused":
		return StatePaused
	case "restarting":
		return StateRestarting
	case "exited", "stopped":
		return StateExited
	case "dead":
		return StateDead
	}
	return StateUnknown
}

// toLowerASCII is faster than strings.ToLower for the small set of
// ASCII-only states we expect; avoids importing the strings package
// (and the unicode tables it pulls).
func toLowerASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// SortContainers returns a deterministic ordering: by runtime then by
// container ID. Useful for golden-file tests and stable diffs.
func SortContainers(cs []Container) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Runtime != cs[j].Runtime {
			return cs[i].Runtime < cs[j].Runtime
		}
		return cs[i].ContainerID < cs[j].ContainerID
	})
}
