package vms

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// virtualboxCollector enumerates VMs via `VBoxManage`. Cross-platform —
// the same binary ships on Linux, macOS, and Windows.
//
// `VBoxManage list vms` returns one line per defined VM:
//
//	"vm-name" {uuid}
//
// then we run `VBoxManage showvminfo <uuid> --machinereadable` per VM
// for the structured key=value capacity fields (memory, cpus, VMState).
type virtualboxCollector struct {
	run      runner
	lookPath pathLookup
}

// NewVirtualBoxCollector returns a VirtualBox-backed collector. Empty
// slice when VBoxManage is not on PATH.
func NewVirtualBoxCollector() Collector {
	return &virtualboxCollector{
		run:      defaultRunner,
		lookPath: exec.LookPath,
	}
}

func (c *virtualboxCollector) Name() string { return "virtualbox-vboxmanage" }

func (c *virtualboxCollector) Collect(ctx context.Context) ([]VM, error) {
	if _, lookErr := c.lookPath("VBoxManage"); lookErr != nil {
		return []VM{}, nil //nolint:nilerr // VBoxManage missing is a "not applicable", not an error
	}

	listRaw, err := c.run(ctx, "VBoxManage", "list", "vms")
	if err != nil {
		return []VM{}, fmt.Errorf("vboxmanage list vms: %w", err)
	}
	pairs := parseVBoxList(string(listRaw))
	if len(pairs) > MaxVMs {
		pairs = pairs[:MaxVMs]
	}

	out := make([]VM, 0, len(pairs))
	for _, p := range pairs {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-collect: %w", err)
		}
		vm := VM{
			Hypervisor: HypervisorVirtualBox,
			VMUUID:     p.uuid,
			Name:       p.name,
			State:      StateUnknown,
		}
		if infoRaw, err := c.run(ctx, "VBoxManage", "showvminfo",
			p.uuid, "--machinereadable"); err == nil {
			enrichFromVBoxInfo(&vm, string(infoRaw))
		}
		out = append(out, vm)
	}
	SortVMs(out)
	return out, nil
}

// vboxPair is one VM identified by `VBoxManage list vms`.
type vboxPair struct {
	uuid string
	name string
}

// parseVBoxList parses lines like:  "vm-name" {uuid}
// Quoted name first, brace-wrapped UUID second.
func parseVBoxList(raw string) []vboxPair {
	var out []vboxPair
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Find the last '{' which starts the UUID.
		brace := strings.LastIndexByte(line, '{')
		end := strings.LastIndexByte(line, '}')
		if brace < 0 || end <= brace+1 {
			continue
		}
		uuid := line[brace+1 : end]
		if len(uuid) != 36 {
			continue
		}
		// Name is everything before the UUID, trimmed and unquoted.
		name := strings.TrimSpace(line[:brace])
		name = strings.Trim(name, `"`)
		out = append(out, vboxPair{uuid: uuid, name: name})
	}
	return out
}

// enrichFromVBoxInfo parses `--machinereadable` key=value lines.
//
//	VMState="running"
//	memory=4096          (MiB)
//	cpus=2
//	ostype="Ubuntu_64"
//	CfgFile="/path/to/foo.vbox"
func enrichFromVBoxInfo(vm *VM, raw string) {
	for _, line := range strings.Split(raw, "\n") {
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.Trim(strings.TrimSpace(line[idx+1:]), `"`)
		switch key {
		case "VMState":
			vm.State = NormalizeState(val)
		case "memory":
			if mb, err := strconv.ParseUint(val, 10, 64); err == nil {
				vm.RAMBytes = mb * 1024 * 1024
			}
		case "cpus":
			if n, err := strconv.Atoi(val); err == nil {
				vm.VCPUs = n
			}
		case "ostype":
			vm.OSType = val
		case "CfgFile":
			vm.ConfigPath = val
		case "VMStateChangeTime":
			vm.StartedAt = val
		}
	}
}
