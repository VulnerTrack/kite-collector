//go:build !linux

package kernelmod

import "context"

// stubCollector is the no-op implementation for non-Linux platforms.
// macOS (kextstat), Windows (SCM kernel drivers), and FreeBSD
// (kldstat) each warrant their own future iteration — this stub
// keeps the package importable cross-platform until that work lands.
type stubCollector struct{}

// NewCollector returns the stub collector on non-Linux platforms.
func NewCollector() Collector { return stubCollector{} }

func (stubCollector) Name() string { return "kernelmod-stub" }

func (stubCollector) Collect(_ context.Context) ([]Module, error) {
	return nil, nil
}
