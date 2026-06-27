//go:build !windows

package vms

import "context"

// NewHyperVCollector returns the no-op stub on non-Windows platforms.
// Hyper-V only exists on Windows hosts; the chain calls this on every
// OS so we keep the symbol present for cross-OS builds.
func NewHyperVCollector() Collector {
	return hyperVStub{}
}

type hyperVStub struct{}

func (hyperVStub) Name() string { return "hyperv-stub" }

func (hyperVStub) Collect(_ context.Context) ([]VM, error) {
	return []VM{}, nil
}
