package vms

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// libvirtCollector enumerates KVM/QEMU VMs via the `virsh` CLI. Shelling
// out is intentional — talking the libvirt-go FFI requires CGO + libvirt
// headers at build time, which would block our CGO_ENABLED=0 static
// release matrix. `virsh` ships with every libvirt deployment and exposes
// a stable text interface that's parseable across versions back to 1.x.
//
// We run two commands per scan:
//   - `virsh -q list --all --uuid --name` for the (uuid, name) pairs
//   - `virsh dominfo <uuid>` per VM for state + capacity (vcpus, ram)
//
// Both calls go to qemu:///system (the system-wide libvirt URI). If the
// operator runs a session-mode libvirt instance, KITE_LIBVIRT_URI lets
// them override.
type libvirtCollector struct {
	run      runner
	lookPath pathLookup
	uri      string
}

type (
	runner     func(ctx context.Context, name string, args ...string) ([]byte, error)
	pathLookup func(string) (string, error)
)

func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //#nosec G204 -- args are fixed literals + libvirt-derived UUIDs
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("exec %s: %w", name, err)
	}
	return out, nil
}

// NewLibvirtCollector returns a collector backed by the system `virsh` CLI.
// When virsh is not on PATH, Collect returns an empty slice so the
// multi-hypervisor chain can move on to the next backend.
func NewLibvirtCollector() Collector {
	uri := "qemu:///system"
	return &libvirtCollector{
		run:      defaultRunner,
		uri:      uri,
		lookPath: exec.LookPath,
	}
}

func (c *libvirtCollector) Name() string { return "libvirt-virsh" }

// Collect lists every defined VM (running + shutoff) and enriches each
// with the dominfo capacity fields.
func (c *libvirtCollector) Collect(ctx context.Context) ([]VM, error) {
	if _, lookErr := c.lookPath("virsh"); lookErr != nil {
		return []VM{}, nil //nolint:nilerr // virsh missing is a "not applicable", not a collector error
	}

	listRaw, err := c.run(ctx, "virsh", "-c", c.uri, "-q",
		"list", "--all", "--uuid", "--name")
	if err != nil {
		return []VM{}, fmt.Errorf("virsh list: %w", err)
	}
	pairs := parseVirshList(string(listRaw))
	if len(pairs) > MaxVMs {
		pairs = pairs[:MaxVMs]
	}

	out := make([]VM, 0, len(pairs))
	for _, p := range pairs {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-collect: %w", err)
		}
		vm := VM{
			Hypervisor: HypervisorLibvirt,
			VMUUID:     p.uuid,
			Name:       p.name,
			State:      StateUnknown,
			RuntimeURI: c.uri,
		}
		if infoRaw, err := c.run(ctx, "virsh", "-c", c.uri, "dominfo", p.uuid); err == nil {
			enrichFromDominfo(&vm, string(infoRaw))
		}
		out = append(out, vm)
	}
	SortVMs(out)
	return out, nil
}

// virshPair is one (uuid, name) row from `virsh list --uuid --name`.
type virshPair struct {
	uuid string
	name string
}

// parseVirshList parses the two-column UUID + name output. The `-q`
// (quiet) flag suppresses the header so we get pure data rows. Empty
// lines and rows missing either column are silently skipped — virsh
// tolerates partial output during live migration windows.
func parseVirshList(raw string) []virshPair {
	var out []virshPair
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// fields[0] is the UUID; the rest is the name (may contain spaces).
		uuid := fields[0]
		name := strings.Join(fields[1:], " ")
		if len(uuid) != 36 || strings.Count(uuid, "-") != 4 {
			continue // not a UUID-shaped first field; row probably malformed
		}
		out = append(out, virshPair{uuid: uuid, name: name})
	}
	return out
}

// enrichFromDominfo parses `virsh dominfo <uuid>` and fills State, VCPUs,
// RAMBytes, OSType on vm. Output format is "Key: Value" per line, with
// keys like "State", "CPU(s)", "Max memory", "OS Type".
func enrichFromDominfo(vm *VM, raw string) {
	for _, line := range strings.Split(raw, "\n") {
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "State":
			vm.State = NormalizeState(val)
		case "CPU(s)":
			if n, err := strconv.Atoi(val); err == nil {
				vm.VCPUs = n
			}
		case "Max memory":
			// "Max memory: 4194304 KiB" — convert to bytes.
			fields := strings.Fields(val)
			if len(fields) >= 1 {
				if kb, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
					vm.RAMBytes = kb * 1024
				}
			}
		case "OS Type":
			vm.OSType = val
		}
	}
}
