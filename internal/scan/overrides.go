package scan

import (
	"errors"
	"fmt"

	"github.com/vulnertrack/kite-collector/internal/config"
)

// TriggerRequest is the optional JSON body accepted by POST /api/v1/scans.
// Both fields are optional — an empty body means "use the operator-declared
// config verbatim". Sources, when non-empty, must be a subset of the names
// declared in cfg.Discovery.Sources (RFC-0104 R6). ScopeOverride is reserved
// for a future CIDR-level override DSL; today it is accepted as a free-form
// map and validated shallowly (unknown keys rejected to keep the attack
// surface narrow).
type TriggerRequest struct {
	ScopeOverride map[string]any `json:"scope_override,omitempty"`
	Sources       []string       `json:"sources,omitempty"`
}

// ErrScopeOutOfBounds is returned when a TriggerRequest names sources that
// are not present in the operator-declared configuration. Widening the scope
// via the HTTP surface is intentionally not allowed — the HTTP body can only
// narrow what operators already opted into.
var ErrScopeOutOfBounds = errors.New("scan: requested scope is outside the operator-declared allowlist")

// allowedScopeOverrideKeys lists the keys accepted inside ScopeOverride.
// Anything else triggers a validation error. The set is intentionally small
// so the surface is obvious in code review; widen it as concrete overrides
// land.
var allowedScopeOverrideKeys = map[string]struct{}{
	"include_sources": {},
	"exclude_sources": {},
}

// ApplyOverrides validates req against cfg and returns a copy of cfg with the
// narrowed source list applied. The input cfg is never mutated. When req is
// zero-valued (no sources, no scope override) cfg is returned unchanged.
func ApplyOverrides(cfg *config.Config, req TriggerRequest) (*config.Config, error) {
	if cfg == nil {
		return nil, errors.New("scan: ApplyOverrides requires a non-nil config")
	}

	for k := range req.ScopeOverride {
		if _, ok := allowedScopeOverrideKeys[k]; !ok {
			return nil, fmt.Errorf("scan: unknown scope_override key %q", k)
		}
	}

	if len(req.Sources) == 0 {
		return cfg, nil
	}

	declared := cfg.Discovery.Sources
	filtered := make(map[string]config.SourceConfig, len(req.Sources))
	for _, name := range req.Sources {
		src, ok := declared[name]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrScopeOutOfBounds, name)
		}
		filtered[name] = src
	}

	out := *cfg
	out.Discovery = config.DiscoveryConfig{Sources: filtered}
	return &out, nil
}
