//go:build !linux

package phpprojects

import "context"

type stubSource struct{}

func newSource() Source { return stubSource{} }

func (stubSource) Enumerate(_ context.Context) ([]Project, error) {
	return nil, nil
}
