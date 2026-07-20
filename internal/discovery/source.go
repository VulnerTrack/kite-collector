package discovery

import (
	"context"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Source is the interface that every discovery backend must implement.
// Each source knows how to enumerate machines from a particular origin
// (network scan, local agent probe, cloud API, etc.).
type Source interface {
	// Name returns a stable, lowercase identifier for this source
	// (e.g. "network", "agent"). It is used as a key when looking up
	// per-source configuration.
	Name() string

	// Discover runs the source's machine enumeration logic and returns
	// zero or more discovered machines. cfg carries the source-specific
	// key/value pairs from the collector configuration file.
	Discover(ctx context.Context, cfg map[string]any) ([]model.Machine, error)
}
