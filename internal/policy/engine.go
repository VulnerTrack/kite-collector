package policy

import (
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Engine evaluates severity rules and staleness thresholds against assets.
type Engine struct {
	rules          []model.SeverityRule
	staleThreshold time.Duration
}

// New creates a policy Engine with the given severity rules and stale
// threshold.
func New(rules []model.SeverityRule, staleThreshold time.Duration) *Engine {
	return &Engine{
		rules:          rules,
		staleThreshold: staleThreshold,
	}
}

// EvaluateSeverity returns the severity for an asset by finding the first
// matching rule.
//
// A rule matches when:
//   - Its Environment is empty or equals the asset's Environment.
//   - Its IsAuthorized is empty or equals the asset's IsAuthorized.
//   - Its IsManaged is empty or equals the asset's IsManaged.
//
// If no rule matches, the default severity depends on the asset's
// authorization state: unauthorized assets default to "high", everything
// else defaults to "medium".
func (e *Engine) EvaluateSeverity(asset model.Asset) model.Severity {
	for _, rule := range e.rules {
		if ruleMatches(rule, asset) {
			return rule.Severity
		}
	}

	// Default: unauthorized assets are high severity, others medium.
	if asset.IsAuthorized == model.AuthorizationUnauthorized {
		return model.SeverityHigh
	}
	return model.SeverityMedium
}

// ruleMatches returns true when every non-empty field in the rule matches the
// corresponding field on the asset.
func ruleMatches(rule model.SeverityRule, asset model.Asset) bool {
	if rule.Environment != "" && rule.Environment != asset.Environment {
		return false
	}
	if rule.IsAuthorized != "" && rule.IsAuthorized != asset.IsAuthorized {
		return false
	}
	if rule.IsManaged != "" && rule.IsManaged != asset.IsManaged {
		return false
	}
	return true
}

// IsStale reports whether the asset's LastSeenAt timestamp is older than the
// configured stale threshold relative to the current time.
func (e *Engine) IsStale(asset model.Asset) bool {
	if asset.LastSeenAt.IsZero() {
		return true
	}
	return time.Since(asset.LastSeenAt) > e.staleThreshold
}
