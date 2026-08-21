//go:build !windows

package windowslicense

import "context"

// stubCollector is the no-op implementation for non-Windows hosts.
// Linux / macOS / BSD have no equivalent OS-activation surface — the
// audit pipeline simply skips the row when Info.HasData() is false.
type stubCollector struct{}

// NewCollector returns the no-op stub on non-Windows platforms.
func NewCollector() Collector { return stubCollector{} }

func (stubCollector) Name() string { return "windows-license-stub" }

func (stubCollector) Collect(_ context.Context) (Info, error) {
	return Info{}, nil
}
