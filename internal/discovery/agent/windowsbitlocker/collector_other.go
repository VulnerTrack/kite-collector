//go:build !windows

package windowsbitlocker

import "context"

type noopCollector struct{}

// NewCollector returns a no-op collector on non-Windows OSes. The
// audit pipeline still gets a row with Source=no-probe so it can
// distinguish "host has no BitLocker telemetry" from "we didn't try".
func NewCollector() Collector {
	return &noopCollector{}
}

func (noopCollector) Name() string { return "windows-bitlocker-noop" }

func (noopCollector) Collect(_ context.Context) ([]Volume, error) {
	return nil, nil
}
