// Package vms enumerates per-host virtual-machine inventory from any
// installed hypervisor (libvirt/KVM, VirtualBox, Hyper-V, VMware, UTM,
// Parallels, Multipass). Distinct from cross-host VM discovery (where
// each VM is itself an asset) — this package answers "what hypervisor
// workload does this physical host run?" which is the signal needed for
// capacity rollup + blast-radius analysis.
//
// Every collector is **read-only** — it queries the hypervisor API or
// shell-outs to its CLI, never starts, stops, snapshots, clones, or
// otherwise modifies any VM. Read-only is enforced by guideline 4.2 of
// the kite-collector project.
//
// VM rows feed the CWE/CAPEC audit pipeline:
//
//   - CWE-668 (Exposure of Resource to Wrong Sphere) — `running` VMs
//     cloned from a production template (template_id set) indicate
//     hot-cloned environments that share keys/credentials.
//   - CWE-693 (Protection Mechanism Failure) — VMs `paused` for long
//     stretches = halted security workloads (e.g. IDS appliance paused).
//   - Capacity governance — sum(vcpus, ram_bytes) per host gives the
//     over-commit ratio against the host's physical capacity.
package vms

import (
	"context"
	"sort"
)

// MaxVMs bounds per-scan output. A typical host runs 0-20 VMs; a
// virtualisation cluster node might run 100+. The 1024 ceiling protects
// the SQLite write path from a misconfigured runaway-spawning template.
const MaxVMs = 1024

// Hypervisor is the source-of-record for a VM row. Strings are pinned
// to the host_vms.hypervisor CHECK enum.
type Hypervisor string

const (
	HypervisorLibvirt    Hypervisor = "libvirt"
	HypervisorHyperV     Hypervisor = "hyperv"
	HypervisorVirtualBox Hypervisor = "virtualbox"
	HypervisorVMware     Hypervisor = "vmware"
	HypervisorUTM        Hypervisor = "utm"
	HypervisorParallels  Hypervisor = "parallels"
	HypervisorMultipass  Hypervisor = "multipass"
	HypervisorQEMU       Hypervisor = "qemu"
	HypervisorUnknown    Hypervisor = "unknown"
)

// State is the normalised lifecycle state. Strings are pinned to the
// host_vms.state CHECK enum.
type State string

const (
	StateRunning   State = "running"
	StatePaused    State = "paused"
	StateSuspended State = "suspended"
	StateShutdown  State = "shutdown" // gracefully shutting down
	StateShutoff   State = "shutoff"  // off (libvirt's "shut off")
	StateCrashed   State = "crashed"
	StateSaved     State = "saved"   // VirtualBox: state file on disk
	StateAborted   State = "aborted" // VirtualBox / Hyper-V
	StateUnknown   State = "unknown"
)

// VM is the cross-hypervisor record produced by every collector. Mirrors
// the column shape of host_vms so the store layer can persist rows
// without a translation step.
type VM struct {
	Name       string     `json:"name,omitempty"`
	OSType     string     `json:"os_type,omitempty"`
	TemplateID string     `json:"template_id,omitempty"`
	RuntimeURI string     `json:"runtime_uri,omitempty"`
	ConfigPath string     `json:"config_path,omitempty"`
	StartedAt  string     `json:"started_at,omitempty"`
	VMUUID     string     `json:"vm_uuid"`
	Hypervisor Hypervisor `json:"hypervisor"`
	State      State      `json:"state"`
	RAMBytes   uint64     `json:"ram_bytes,omitempty"`
	DiskBytes  uint64     `json:"disk_bytes,omitempty"`
	VCPUs      int        `json:"vcpus,omitempty"`
}

// Collector is the read-only contract every hypervisor implementation
// satisfies.
type Collector interface {
	// Name returns a stable identifier for telemetry (e.g. "libvirt-virsh").
	Name() string
	// Collect enumerates VMs from this hypervisor. Read-only. Returns an
	// empty slice when the hypervisor is not installed/running so the
	// multi-hypervisor chain can fall through to the next backend.
	Collect(ctx context.Context) ([]VM, error)
}

// NormalizeState maps hypervisor-specific status strings to our pinned
// enum. Libvirt uses "running"/"paused"/"shut off"/"shutdown"/"crashed";
// VirtualBox uses "running"/"paused"/"poweroff"/"saved"/"aborted";
// Hyper-V uses "Running"/"Off"/"Saved"/"Paused".
func NormalizeState(raw string) State {
	switch toLowerASCII(raw) {
	case "running":
		return StateRunning
	case "paused":
		return StatePaused
	case "suspended":
		return StateSuspended
	case "shutdown", "shutting down":
		return StateShutdown
	case "shut off", "shutoff", "poweroff", "off", "powered off":
		return StateShutoff
	case "crashed":
		return StateCrashed
	case "saved":
		return StateSaved
	case "aborted":
		return StateAborted
	}
	return StateUnknown
}

// toLowerASCII keeps NormalizeState dependency-free (no unicode tables).
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

// SortVMs returns a deterministic ordering: by hypervisor, then by UUID.
func SortVMs(vs []VM) {
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Hypervisor != vs[j].Hypervisor {
			return vs[i].Hypervisor < vs[j].Hypervisor
		}
		return vs[i].VMUUID < vs[j].VMUUID
	})
}
