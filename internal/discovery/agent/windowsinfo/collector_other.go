//go:build !windows

package windowsinfo

import "context"

// stubCollector is the no-op implementation for non-Windows hosts.
// macOS will be handled via `system_profiler` (future iteration);
// Linux + BSD have no equivalent surface — the audit pipeline simply
// skips Windows-specific joins when Info.Hostname is empty.
type stubCollector struct{}

// NewCollector returns the no-op stub on non-Windows platforms.
func NewCollector() Collector { return stubCollector{} }

func (stubCollector) Name() string { return "windows-info-stub" }

func (stubCollector) Collect(_ context.Context) (Info, error) {
	return Info{}, nil
}
