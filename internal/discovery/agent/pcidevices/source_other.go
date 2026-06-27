//go:build !linux

package pcidevices

import "context"

// stubSource returns no devices and no error on non-Linux builds.
// macOS / Windows / FreeBSD implementations land later — for now,
// the cross-OS contract is satisfied (the collector succeeds and
// returns an empty inventory) so downstream pipelines don't break.
type stubSource struct{}

func newSource() Source { return stubSource{} }

func (stubSource) Enumerate(_ context.Context) ([]Device, error) {
	return nil, nil
}
