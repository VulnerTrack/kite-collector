//go:build darwin

package services

import "context"

// NewCollector returns the macOS launchd Service collector.
//
// TODO(cdms-iter): wire `launchctl list` parsing. Until then, the collector
// returns an empty slice rather than an error so cross-platform callers can
// run unchanged. Stub keeps the build green on darwin while we ship the
// Linux implementation first.
func NewCollector() Collector { return darwinCollector{} }

type darwinCollector struct{}

func (darwinCollector) Name() string { return "launchd" }

func (darwinCollector) Collect(_ context.Context) ([]Service, error) {
	return []Service{}, nil
}
