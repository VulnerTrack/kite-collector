//go:build !windows

package windowshardware

import "context"

type stubCollector struct{}

// NewCollector returns the no-op stub on non-Windows platforms.
func NewCollector() Collector { return stubCollector{} }

func (stubCollector) Name() string { return "windows-hardware-stub" }

func (stubCollector) Collect(_ context.Context) (Hardware, error) {
	return Hardware{}, nil
}
