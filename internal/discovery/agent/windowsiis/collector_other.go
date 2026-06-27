//go:build !windows

package windowsiis

import "context"

type stubCollector struct{}

// NewCollector returns the no-op stub on non-Windows platforms.
func NewCollector() Collector { return stubCollector{} }

func (stubCollector) Name() string { return "windows-iis-stub" }

func (stubCollector) Collect(_ context.Context) (Inventory, error) {
	return Inventory{}, nil
}
