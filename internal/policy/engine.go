package policy

import (
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Engine evaluates severity rules and staleness thresholds against machines.
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

// EvaluateSeverity returns the severity for an machine by finding the first
// matching rule.
//
// A rule matches when:
//   - Its Environment is empty or equals the machine's Environment.
//   - Its IsAuthorized is empty or equals the machine's IsAuthorized.
//   - Its IsManaged is empty or equals the machine's IsManaged.
//
// If no rule matches, the default severity depends on the machine's
// authorization state: unauthorized machines default to "high", everything
// else defaults to "medium".
func (e *Engine) EvaluateSeverity(machine model.Machine) model.Severity {
	for _, rule := range e.rules {
		if ruleMatches(rule, machine) {
			return rule.Severity
		}
	}

	// Default: unauthorized machines are high severity, others medium.
	if machine.IsAuthorized == model.AuthorizationUnauthorized {
		return model.SeverityHigh
	}
	return model.SeverityMedium
}

// ruleMatches returns true when every non-empty field in the rule matches the
// corresponding field on the machine.
func ruleMatches(rule model.SeverityRule, machine model.Machine) bool {
	if rule.Environment != "" && rule.Environment != machine.Environment {
		return false
	}
	if rule.IsAuthorized != "" && rule.IsAuthorized != machine.IsAuthorized {
		return false
	}
	if rule.IsManaged != "" && rule.IsManaged != machine.IsManaged {
		return false
	}
	return true
}

// IsStale reports whether the machine's LastSeenAt timestamp is older than the
// configured stale threshold relative to the current time.
func (e *Engine) IsStale(machine model.Machine) bool {
	if machine.LastSeenAt.IsZero() {
		return true
	}
	return time.Since(machine.LastSeenAt) > e.staleThreshold
}
