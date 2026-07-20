package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// ---------------------------------------------------------------------------
// EvaluateSeverity
// ---------------------------------------------------------------------------

func TestEvaluateSeverity_MatchingRule(t *testing.T) {
	rules := []model.SeverityRule{
		{
			Environment:  "production",
			IsAuthorized: model.AuthorizationUnauthorized,
			IsManaged:    model.ManagedUnmanaged,
			Severity:     model.SeverityCritical,
		},
	}
	eng := New(rules, 168*time.Hour)

	machine := model.Machine{
		Environment:  "production",
		IsAuthorized: model.AuthorizationUnauthorized,
		IsManaged:    model.ManagedUnmanaged,
	}

	assert.Equal(t, model.SeverityCritical, eng.EvaluateSeverity(machine))
}

func TestEvaluateSeverity_FirstMatchWins(t *testing.T) {
	rules := []model.SeverityRule{
		{Environment: "production", Severity: model.SeverityHigh},
		{Environment: "production", Severity: model.SeverityLow},
	}
	eng := New(rules, 168*time.Hour)

	machine := model.Machine{Environment: "production"}
	assert.Equal(t, model.SeverityHigh, eng.EvaluateSeverity(machine),
		"first matching rule must win")
}

func TestEvaluateSeverity_DefaultUnauthorized_High(t *testing.T) {
	eng := New(nil, 168*time.Hour) // no rules

	machine := model.Machine{IsAuthorized: model.AuthorizationUnauthorized}
	assert.Equal(t, model.SeverityHigh, eng.EvaluateSeverity(machine))
}

func TestEvaluateSeverity_DefaultAuthorized_Medium(t *testing.T) {
	eng := New(nil, 168*time.Hour) // no rules

	machine := model.Machine{IsAuthorized: model.AuthorizationAuthorized}
	assert.Equal(t, model.SeverityMedium, eng.EvaluateSeverity(machine))
}

func TestEvaluateSeverity_DefaultUnknown_Medium(t *testing.T) {
	eng := New(nil, 168*time.Hour) // no rules

	machine := model.Machine{IsAuthorized: model.AuthorizationUnknown}
	assert.Equal(t, model.SeverityMedium, eng.EvaluateSeverity(machine))
}

func TestEvaluateSeverity_WildcardRule(t *testing.T) {
	// A rule with empty fields matches every machine.
	rules := []model.SeverityRule{
		{Severity: model.SeverityLow},
	}
	eng := New(rules, 168*time.Hour)

	machine := model.Machine{
		Environment:  "staging",
		IsAuthorized: model.AuthorizationAuthorized,
		IsManaged:    model.ManagedManaged,
	}
	assert.Equal(t, model.SeverityLow, eng.EvaluateSeverity(machine))
}

func TestEvaluateSeverity_PartialMatch(t *testing.T) {
	// Rule requires production + unauthorized, machine is production + authorized
	rules := []model.SeverityRule{
		{
			Environment:  "production",
			IsAuthorized: model.AuthorizationUnauthorized,
			Severity:     model.SeverityCritical,
		},
	}
	eng := New(rules, 168*time.Hour)

	machine := model.Machine{
		Environment:  "production",
		IsAuthorized: model.AuthorizationAuthorized,
	}
	// Rule doesn't match, so default applies (authorized => medium)
	assert.Equal(t, model.SeverityMedium, eng.EvaluateSeverity(machine))
}

// ---------------------------------------------------------------------------
// IsStale
// ---------------------------------------------------------------------------

func TestIsStale_OldMachine_ReturnsTrue(t *testing.T) {
	eng := New(nil, 24*time.Hour)

	machine := model.Machine{
		LastSeenAt: time.Now().UTC().Add(-48 * time.Hour),
	}
	assert.True(t, eng.IsStale(machine))
}

func TestIsStale_RecentMachine_ReturnsFalse(t *testing.T) {
	eng := New(nil, 24*time.Hour)

	machine := model.Machine{
		LastSeenAt: time.Now().UTC().Add(-1 * time.Hour),
	}
	assert.False(t, eng.IsStale(machine))
}

func TestIsStale_ExactlyAtThreshold(t *testing.T) {
	eng := New(nil, 24*time.Hour)

	// Machine seen exactly 24h ago -- time.Since will be >= threshold
	machine := model.Machine{
		LastSeenAt: time.Now().UTC().Add(-24 * time.Hour),
	}
	// Due to execution time, Since will be slightly > threshold
	assert.True(t, eng.IsStale(machine))
}

func TestIsStale_ZeroTime_ReturnsTrue(t *testing.T) {
	eng := New(nil, 24*time.Hour)

	machine := model.Machine{} // zero-value LastSeenAt
	assert.True(t, eng.IsStale(machine))
}
