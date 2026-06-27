//go:build !linux

package tpmdevices

import "context"

type stubSource struct{}

func newSource() Source { return stubSource{} }

func (stubSource) Enumerate(_ context.Context) ([]Device, error) {
	return nil, nil
}
