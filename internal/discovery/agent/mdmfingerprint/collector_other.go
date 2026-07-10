//go:build !darwin && !linux && !windows

package mdmfingerprint

import "context"

// NewCollector returns a no-probe collector on OSes we have not yet
// fingerprinted. The audit pipeline still gets a State so it can tell
// "unknown OS" apart from "we forgot to wire the probe".
func NewCollector() Collector {
	return noopCollector{}
}

type noopCollector struct{}

func (noopCollector) Name() string { return "mdm-fingerprint-noop" }
func (noopCollector) Collect(_ context.Context) (State, error) {
	return State{Source: SourceNoProbe}, nil
}
