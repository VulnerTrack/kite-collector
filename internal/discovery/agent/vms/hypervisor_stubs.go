package vms

import "context"

// Stubs for hypervisors not yet wired. Each returns an empty slice so the
// multi-hypervisor chain can call them unconditionally without runtime
// branches. Replace each with a real implementation as it lands.

// NewVMwareCollector returns a stub VMware Workstation/Fusion collector.
//
// TODO(cdms-iter): wire `vmrun list` for running VMs and parse the .vmx
// inventory file for the full set.
func NewVMwareCollector() Collector { return hypervisorStub{name: "vmware-stub", h: HypervisorVMware} }

// NewUTMCollector returns a stub UTM (macOS) collector.
//
// TODO(cdms-iter): UTM doesn't ship a CLI; enumerate `.utm` bundles in
// `~/Library/Containers/com.utmapp.UTM/Data/Documents/` and parse
// `config.plist` for capacity/state.
func NewUTMCollector() Collector { return hypervisorStub{name: "utm-stub", h: HypervisorUTM} }

// NewParallelsCollector returns a stub Parallels Desktop collector.
//
// TODO(cdms-iter): wire `prlctl list -a --info --json`.
func NewParallelsCollector() Collector {
	return hypervisorStub{name: "parallels-stub", h: HypervisorParallels}
}

// NewMultipassCollector returns a stub Multipass collector.
//
// TODO(cdms-iter): wire `multipass list --format=json` — easiest
// remaining hypervisor (clean JSON output, no per-instance second call).
func NewMultipassCollector() Collector {
	return hypervisorStub{name: "multipass-stub", h: HypervisorMultipass}
}

type hypervisorStub struct {
	name string
	h    Hypervisor
}

func (s hypervisorStub) Name() string { return s.name }
func (s hypervisorStub) Collect(_ context.Context) ([]VM, error) {
	return []VM{}, nil
}
