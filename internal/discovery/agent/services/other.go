//go:build !linux && !darwin && !windows

package services

import "context"

// NewCollector returns a no-op collector on platforms (freebsd, openbsd)
// where we haven't yet wired a manager-specific implementation. The
// build-tag exclusion list mirrors the goreleaser release matrix.
func NewCollector() Collector { return noopCollector{} }

type noopCollector struct{}

func (noopCollector) Name() string { return string(ManagerUnknown) }

func (noopCollector) Collect(_ context.Context) ([]Service, error) {
	return []Service{}, nil
}
