//go:build !darwin

package macosposture

import "context"

type noopCollector struct{}

// NewCollector returns a no-probe collector on non-Darwin OSes. The
// audit pipeline still gets a row with Source=no-probe so it can
// distinguish "host isn't macOS" from "we forgot to probe".
func NewCollector() Collector {
	return &noopCollector{}
}

func (noopCollector) Name() string { return "macos-posture-noop" }

func (noopCollector) Collect(_ context.Context) (State, error) {
	return State{Source: SourceNoProbe}, nil
}
