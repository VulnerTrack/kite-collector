//go:build !linux

package sensors

import "context"

type stubSource struct{}

func newSource() Source { return stubSource{} }

func (stubSource) Enumerate(_ context.Context) ([]Sensor, error) {
	return nil, nil
}
