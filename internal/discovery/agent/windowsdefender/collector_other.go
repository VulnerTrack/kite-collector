//go:build !windows

package windowsdefender

import "context"

type stubCollector struct{}

// NewCollector returns the no-op stub on non-Windows platforms.
// The audit pipeline treats State{Source: SourceNoProbe} as "host
// is not Windows; defender posture not applicable".
func NewCollector() Collector { return stubCollector{} }

func (stubCollector) Name() string { return "windows-defender-stub" }

func (stubCollector) Collect(_ context.Context) (State, error) {
	return State{Source: SourceNoProbe}, nil
}
