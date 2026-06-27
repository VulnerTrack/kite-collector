package vms

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPinnedEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(HypervisorLibvirt), "libvirt"},
		{string(HypervisorHyperV), "hyperv"},
		{string(HypervisorVirtualBox), "virtualbox"},
		{string(HypervisorVMware), "vmware"},
		{string(HypervisorUTM), "utm"},
		{string(HypervisorParallels), "parallels"},
		{string(HypervisorMultipass), "multipass"},
		{string(HypervisorQEMU), "qemu"},
		{string(HypervisorUnknown), "unknown"},
		{string(StateRunning), "running"},
		{string(StatePaused), "paused"},
		{string(StateSuspended), "suspended"},
		{string(StateShutdown), "shutdown"},
		{string(StateShutoff), "shutoff"},
		{string(StateCrashed), "crashed"},
		{string(StateSaved), "saved"},
		{string(StateAborted), "aborted"},
		{string(StateUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestNormalizeState(t *testing.T) {
	cases := map[string]State{
		"running":       StateRunning,
		"Running":       StateRunning, // Hyper-V capitalises
		"paused":        StatePaused,
		"suspended":     StateSuspended,
		"shutdown":      StateShutdown,
		"shutting down": StateShutdown,
		"shut off":      StateShutoff, // libvirt
		"shutoff":       StateShutoff,
		"poweroff":      StateShutoff, // VirtualBox
		"Off":           StateShutoff, // Hyper-V
		"crashed":       StateCrashed,
		"saved":         StateSaved,
		"aborted":       StateAborted,
		"":              StateUnknown,
		"weird":         StateUnknown,
	}
	for in, want := range cases {
		if got := NormalizeState(in); got != want {
			t.Fatalf("NormalizeState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSortVMsDeterministic(t *testing.T) {
	in := []VM{
		{Hypervisor: HypervisorVirtualBox, VMUUID: "uuid-bbb"},
		{Hypervisor: HypervisorLibvirt, VMUUID: "uuid-zzz"},
		{Hypervisor: HypervisorVirtualBox, VMUUID: "uuid-aaa"},
		{Hypervisor: HypervisorLibvirt, VMUUID: "uuid-aaa"},
	}
	SortVMs(in)
	want := []struct {
		h    Hypervisor
		uuid string
	}{
		{HypervisorLibvirt, "uuid-aaa"},
		{HypervisorLibvirt, "uuid-zzz"},
		{HypervisorVirtualBox, "uuid-aaa"},
		{HypervisorVirtualBox, "uuid-bbb"},
	}
	for i, v := range in {
		if v.Hypervisor != want[i].h || v.VMUUID != want[i].uuid {
			t.Fatalf("pos %d: got (%q,%q), want (%q,%q)",
				i, v.Hypervisor, v.VMUUID, want[i].h, want[i].uuid)
		}
	}
}

// -- libvirt --------------------------------------------------------------

func TestParseVirshList(t *testing.T) {
	raw := ` 12345678-1234-1234-1234-123456789abc   web-01
 abcdef00-0000-0000-0000-000000000000   db with spaces in name
                                        garbage row
 invalid-uuid-here                      should-skip
`
	pairs := parseVirshList(raw)
	if len(pairs) != 2 {
		t.Fatalf("want 2 pairs, got %d: %+v", len(pairs), pairs)
	}
	if pairs[0].uuid != "12345678-1234-1234-1234-123456789abc" || pairs[0].name != "web-01" {
		t.Fatalf("first pair wrong: %+v", pairs[0])
	}
	if pairs[1].name != "db with spaces in name" {
		t.Fatalf("name with spaces lost: %q", pairs[1].name)
	}
}

func TestEnrichFromDominfo(t *testing.T) {
	raw := `Id:             1
Name:           web-01
UUID:           12345678-1234-1234-1234-123456789abc
OS Type:        hvm
State:          running
CPU(s):         4
Max memory:     4194304 KiB
Used memory:    2097152 KiB
`
	vm := VM{}
	enrichFromDominfo(&vm, raw)
	if vm.State != StateRunning {
		t.Fatalf("state=%q, want running", vm.State)
	}
	if vm.VCPUs != 4 {
		t.Fatalf("vcpus=%d, want 4", vm.VCPUs)
	}
	if vm.RAMBytes != 4194304*1024 {
		t.Fatalf("ram=%d bytes, want %d", vm.RAMBytes, 4194304*1024)
	}
	if vm.OSType != "hvm" {
		t.Fatalf("os_type=%q", vm.OSType)
	}
}

func TestLibvirtCollectorEndToEnd(t *testing.T) {
	c := &libvirtCollector{
		uri:      "qemu:///system",
		lookPath: func(string) (string, error) { return "/usr/bin/virsh", nil },
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if hasFlag(args, "list") {
				return []byte(` 11111111-1111-1111-1111-111111111111   alpha
 22222222-2222-2222-2222-222222222222   beta
`), nil
			}
			if hasFlag(args, "dominfo") {
				// Different memory + state per VM keyed off the UUID arg.
				uuid := args[len(args)-1]
				if strings.HasPrefix(uuid, "1111") {
					return []byte("State:          running\nCPU(s):         2\nMax memory:     2097152 KiB\nOS Type:        hvm\n"), nil
				}
				return []byte("State:          shut off\nCPU(s):         1\nMax memory:     1048576 KiB\n"), nil
			}
			return nil, errors.New("unexpected args")
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 VMs, got %d", len(got))
	}
	// Sorted by UUID — alpha (1111…) first.
	alpha := got[0]
	if alpha.Name != "alpha" || alpha.State != StateRunning || alpha.VCPUs != 2 {
		t.Fatalf("alpha wrong: %+v", alpha)
	}
	if alpha.RuntimeURI != "qemu:///system" {
		t.Fatalf("runtime_uri not stamped: %q", alpha.RuntimeURI)
	}
	beta := got[1]
	if beta.State != StateShutoff {
		t.Fatalf("beta state=%q, want shutoff", beta.State)
	}
}

func TestLibvirtCollectorMissingVirsh(t *testing.T) {
	c := &libvirtCollector{
		lookPath: func(string) (string, error) { return "", errors.New("not found") },
		run: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatalf("run must not be invoked when virsh is missing")
			return nil, nil
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing virsh must not error, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- virtualbox -----------------------------------------------------------

func TestParseVBoxList(t *testing.T) {
	raw := `"web-01" {11111111-1111-1111-1111-111111111111}
"db has spaces" {22222222-2222-2222-2222-222222222222}
malformed line without braces
"truncated-uuid" {short}
`
	pairs := parseVBoxList(raw)
	if len(pairs) != 2 {
		t.Fatalf("want 2 pairs, got %d: %+v", len(pairs), pairs)
	}
	if pairs[0].name != "web-01" || pairs[1].name != "db has spaces" {
		t.Fatalf("names lost: %+v", pairs)
	}
}

func TestEnrichFromVBoxInfo(t *testing.T) {
	raw := `name="web-01"
UUID="11111111-1111-1111-1111-111111111111"
VMState="running"
VMStateChangeTime="2026-06-23T11:00:00.000000000"
memory=4096
cpus=4
ostype="Ubuntu_64"
CfgFile="/Users/me/VirtualBox VMs/web-01/web-01.vbox"
`
	vm := VM{}
	enrichFromVBoxInfo(&vm, raw)
	if vm.State != StateRunning {
		t.Fatalf("state=%q", vm.State)
	}
	if vm.VCPUs != 4 {
		t.Fatalf("vcpus=%d", vm.VCPUs)
	}
	if vm.RAMBytes != 4096*1024*1024 {
		t.Fatalf("ram=%d bytes", vm.RAMBytes)
	}
	if vm.OSType != "Ubuntu_64" {
		t.Fatalf("os_type=%q", vm.OSType)
	}
	if !strings.HasSuffix(vm.ConfigPath, "web-01.vbox") {
		t.Fatalf("config_path=%q", vm.ConfigPath)
	}
}

func TestVirtualBoxCollectorMissing(t *testing.T) {
	c := &virtualboxCollector{
		lookPath: func(string) (string, error) { return "", errors.New("nope") },
		run: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatalf("run must not run when VBoxManage missing")
			return nil, nil
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- chain ---------------------------------------------------------------

func TestChainCollectorAggregatesAndSkipsErrors(t *testing.T) {
	good := stubCollector{out: []VM{
		{Hypervisor: HypervisorLibvirt, VMUUID: "u1", State: StateRunning},
	}}
	bad := stubCollector{err: errors.New("hypervisor down")}
	chain := &chainCollector{collectors: []Collector{good, bad, good}}

	got, err := chain.Collect(context.Background())
	if err != nil {
		t.Fatalf("chain Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 VMs (good × 2), got %d", len(got))
	}
}

func TestChainCollectorRespectsCap(t *testing.T) {
	bulk := stubCollector{out: make([]VM, MaxVMs+5)}
	for i := range bulk.out {
		bulk.out[i] = VM{Hypervisor: HypervisorLibvirt, VMUUID: itoa(i)}
	}
	chain := &chainCollector{collectors: []Collector{bulk}}
	got, err := chain.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != MaxVMs {
		t.Fatalf("want %d (cap), got %d", MaxVMs, len(got))
	}
}

// -- helpers --------------------------------------------------------------

type stubCollector struct {
	err error
	out []VM
}

func (s stubCollector) Name() string { return "stub" }
func (s stubCollector) Collect(_ context.Context) ([]VM, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.out, nil
}

func hasFlag(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [11]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
