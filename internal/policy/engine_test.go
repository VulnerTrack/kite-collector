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

	asset := model.Asset{
		Environment:  "production",
		IsAuthorized: model.AuthorizationUnauthorized,
		IsManaged:    model.ManagedUnmanaged,
	}

	assert.Equal(t, model.SeverityCritical, eng.EvaluateSeverity(asset))
}

func TestEvaluateSeverity_FirstMatchWins(t *testing.T) {
	rules := []model.SeverityRule{
		{Environment: "production", Severity: model.SeverityHigh},
		{Environment: "production", Severity: model.SeverityLow},
	}
	eng := New(rules, 168*time.Hour)

	asset := model.Asset{Environment: "production"}
	assert.Equal(t, model.SeverityHigh, eng.EvaluateSeverity(asset),
		"first matching rule must win")
}

func TestEvaluateSeverity_DefaultUnauthorized_High(t *testing.T) {
	eng := New(nil, 168*time.Hour) // no rules

	asset := model.Asset{IsAuthorized: model.AuthorizationUnauthorized}
	assert.Equal(t, model.SeverityHigh, eng.EvaluateSeverity(asset))
}

func TestEvaluateSeverity_DefaultAuthorized_Medium(t *testing.T) {
	eng := New(nil, 168*time.Hour) // no rules

	asset := model.Asset{IsAuthorized: model.AuthorizationAuthorized}
	assert.Equal(t, model.SeverityMedium, eng.EvaluateSeverity(asset))
}

func TestEvaluateSeverity_DefaultUnknown_Medium(t *testing.T) {
	eng := New(nil, 168*time.Hour) // no rules

	asset := model.Asset{IsAuthorized: model.AuthorizationUnknown}
	assert.Equal(t, model.SeverityMedium, eng.EvaluateSeverity(asset))
}

func TestEvaluateSeverity_WildcardRule(t *testing.T) {
	// A rule with empty fields matches every asset.
	rules := []model.SeverityRule{
		{Severity: model.SeverityLow},
	}
	eng := New(rules, 168*time.Hour)

	asset := model.Asset{
		Environment:  "staging",
		IsAuthorized: model.AuthorizationAuthorized,
		IsManaged:    model.ManagedManaged,
	}
	assert.Equal(t, model.SeverityLow, eng.EvaluateSeverity(asset))
}

func TestEvaluateSeverity_PartialMatch(t *testing.T) {
	// Rule requires production + unauthorized, asset is production + authorized
	rules := []model.SeverityRule{
		{
			Environment:  "production",
			IsAuthorized: model.AuthorizationUnauthorized,
			Severity:     model.SeverityCritical,
		},
	}
	eng := New(rules, 168*time.Hour)

	asset := model.Asset{
		Environment:  "production",
		IsAuthorized: model.AuthorizationAuthorized,
	}
	// Rule doesn't match, so default applies (authorized => medium)
	assert.Equal(t, model.SeverityMedium, eng.EvaluateSeverity(asset))
}

// ---------------------------------------------------------------------------
// IsStale
// ---------------------------------------------------------------------------

func TestIsStale_OldAsset_ReturnsTrue(t *testing.T) {
	eng := New(nil, 24*time.Hour)

	asset := model.Asset{
		LastSeenAt: time.Now().UTC().Add(-48 * time.Hour),
	}
	assert.True(t, eng.IsStale(asset))
}

func TestIsStale_RecentAsset_ReturnsFalse(t *testing.T) {
	eng := New(nil, 24*time.Hour)

	asset := model.Asset{
		LastSeenAt: time.Now().UTC().Add(-1 * time.Hour),
	}
	assert.False(t, eng.IsStale(asset))
}

func TestIsStale_ExactlyAtThreshold(t *testing.T) {
	eng := New(nil, 24*time.Hour)

	// Asset seen exactly 24h ago -- time.Since will be >= threshold
	asset := model.Asset{
		LastSeenAt: time.Now().UTC().Add(-24 * time.Hour),
	}
	// Due to execution time, Since will be slightly > threshold
	assert.True(t, eng.IsStale(asset))
}

func TestIsStale_ZeroTime_ReturnsTrue(t *testing.T) {
	eng := New(nil, 24*time.Hour)

	asset := model.Asset{} // zero-value LastSeenAt
	assert.True(t, eng.IsStale(asset))
}
