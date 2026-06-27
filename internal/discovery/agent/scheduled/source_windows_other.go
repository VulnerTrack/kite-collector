//go:build !windows

package scheduled

import "context"

// NewWindowsTaskSchedulerCollector returns the no-op stub on non-
// Windows platforms — the chain calls it unconditionally so we keep
// the symbol present for cross-OS builds.
func NewWindowsTaskSchedulerCollector() Collector { return windowsTaskStub{} }

type windowsTaskStub struct{}

func (windowsTaskStub) Name() string { return "windows-task-scheduler-stub" }

func (windowsTaskStub) Collect(_ context.Context) ([]Job, error) {
	return []Job{}, nil
}
