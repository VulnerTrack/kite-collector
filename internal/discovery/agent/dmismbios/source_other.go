//go:build !linux

package dmismbios

import "context"

type stubSource struct{}

func newSource() Source { return stubSource{} }

func (stubSource) Read(_ context.Context) (Record, error) {
	return Record{ChassisType: ChassisUnknown}, nil
}
