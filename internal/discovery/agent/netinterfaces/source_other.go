//go:build !linux

package netinterfaces

import "context"

type stubSource struct{}

func newSource() Source { return stubSource{} }

func (stubSource) Enumerate(_ context.Context) ([]Iface, error) {
	return nil, nil
}
