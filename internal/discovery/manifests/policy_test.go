package manifests

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/manifests/parsers"
	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestPolicyEngine_Blocklist_AllVersions(t *testing.T) {
	pe := NewPolicyEngine(PolicyConfig{
		Mode: "blocklist_only",
		Blocklist: []BlocklistRule{
			{Name: "^colors$", Reason: "protestware", Remediation: "Remove or replace with safe alternative"},
		},
	})

	assetID := uuid.New()
	now := time.Now().UTC()

	findings := pe.Evaluate(parsers.Dependency{Name: "colors", Version: "1.4.2"}, assetID, now)
	require.Len(t, findings, 1)
	assert.Equal(t, model.SeverityCritical, findings[0].Severity)
	assert.Equal(t, "blocklist:^colors$", findings[0].CheckID)
	assert.Contains(t, findings[0].Title, "colors 1.4.2")
}

func TestPolicyEngine_Blocklist_VersionConstraint(t *testing.T) {
	pe := NewPolicyEngine(PolicyConfig{
		Mode: "blocklist_only",
		Blocklist: []BlocklistRule{
			{Name: "log4j-core", Version: "<2.17.1", Reason: "Log4Shell", Remediation: "Upgrade to >= 2.17.1"},
		},
	})

	assetID := uuid.New()
	now := time.Now().UTC()

	// Version below threshold — blocked.
	findings := pe.Evaluate(parsers.Dependency{Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1"}, assetID, now)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Remediation, "2.17.1")

	// Version at threshold — not blocked.
	findings = pe.Evaluate(parsers.Dependency{Name: "org.apache.logging.log4j:log4j-core", Version: "2.17.1"}, assetID, now)
	assert.Empty(t, findings)

	// Version above threshold — not blocked.
	findings = pe.Evaluate(parsers.Dependency{Name: "org.apache.logging.log4j:log4j-core", Version: "2.21.0"}, assetID, now)
	assert.Empty(t, findings)
}

func TestPolicyEngine_Blocklist_NoMatch(t *testing.T) {
	pe := NewPolicyEngine(PolicyConfig{
		Mode: "blocklist_only",
		Blocklist: []BlocklistRule{
			{Name: "^evil-package$"},
		},
	})

	findings := pe.Evaluate(parsers.Dependency{Name: "express", Version: "4.18.2"}, uuid.New(), time.Now())
	assert.Empty(t, findings)
}

func TestPolicyEngine_Allowlist(t *testing.T) {
	pe := NewPolicyEngine(PolicyConfig{
		Mode: "allowlist_only",
		Allowlist: []AllowlistRule{
			{Name: "^express$"},
			{Name: "^lodash$"},
		},
	})

	assetID := uuid.New()
	now := time.Now().UTC()

	// Approved dependency — no findings.
	findings := pe.Evaluate(parsers.Dependency{Name: "express", Version: "4.18.2"}, assetID, now)
	assert.Empty(t, findings)

	// Unapproved dependency — flagged.
	findings = pe.Evaluate(parsers.Dependency{Name: "unknown-pkg", Version: "1.0.0"}, assetID, now)
	require.Len(t, findings, 1)
	assert.Equal(t, model.SeverityMedium, findings[0].Severity)
	assert.Equal(t, "allowlist:not_approved", findings[0].CheckID)
}

func TestPolicyEngine_BothMode(t *testing.T) {
	pe := NewPolicyEngine(PolicyConfig{
		Mode: "both",
		Blocklist: []BlocklistRule{
			{Name: "^colors$", Reason: "protestware"},
		},
		Allowlist: []AllowlistRule{
			{Name: "^express$"},
		},
	})

	assetID := uuid.New()
	now := time.Now().UTC()

	// Blocklisted and not in allowlist — two findings.
	findings := pe.Evaluate(parsers.Dependency{Name: "colors", Version: "1.4.2"}, assetID, now)
	require.Len(t, findings, 2)

	severities := map[model.Severity]bool{}
	for _, f := range findings {
		severities[f.Severity] = true
	}
	assert.True(t, severities[model.SeverityCritical])
	assert.True(t, severities[model.SeverityMedium])
}

func TestPolicyEngine_CaseInsensitive(t *testing.T) {
	pe := NewPolicyEngine(PolicyConfig{
		Mode: "blocklist_only",
		Blocklist: []BlocklistRule{
			{Name: "^Colors$"},
		},
	})

	findings := pe.Evaluate(parsers.Dependency{Name: "colors", Version: "1.0.0"}, uuid.New(), time.Now())
	require.Len(t, findings, 1)
}

func TestPolicyEngine_EmptyVersion(t *testing.T) {
	pe := NewPolicyEngine(PolicyConfig{
		Mode: "blocklist_only",
		Blocklist: []BlocklistRule{
			{Name: "bad-pkg", Version: "<2.0.0"},
		},
	})

	// Empty version → assume worst case (match).
	findings := pe.Evaluate(parsers.Dependency{Name: "bad-pkg", Version: ""}, uuid.New(), time.Now())
	require.Len(t, findings, 1)
}

func TestPolicyEngine_NilEngine(t *testing.T) {
	var pe *PolicyEngine
	findings := pe.Evaluate(parsers.Dependency{Name: "express"}, uuid.New(), time.Now())
	assert.Empty(t, findings)
}

func TestPolicyEngine_InvalidRegexSkipped(t *testing.T) {
	pe := NewPolicyEngine(PolicyConfig{
		Mode: "blocklist_only",
		Blocklist: []BlocklistRule{
			{Name: "[invalid"}, // bad regex
			{Name: "^colors$"},
		},
	})

	// Only the valid rule should remain.
	findings := pe.Evaluate(parsers.Dependency{Name: "colors", Version: "1.0.0"}, uuid.New(), time.Now())
	require.Len(t, findings, 1)
}

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"2.14.1", "2.17.1", -1},
		{"2.17.1", "2.17.1", 0},
		{"2.21.0", "2.17.1", 1},
		{"1.2", "1.2.0", -1}, // "1.2" vs "1.2.0": missing part treated as empty → 0 vs 0
		{"10.0.0", "9.0.0", 1},
	}
	for _, tc := range tests {
		got := compareSemver(tc.a, tc.b)
		assert.Equal(t, tc.want, got, "compareSemver(%q, %q)", tc.a, tc.b)
	}
}

func TestVersionInRange(t *testing.T) {
	tests := []struct {
		version    string
		constraint string
		want       bool
	}{
		{"2.14.1", "<2.17.1", true},
		{"2.17.1", "<2.17.1", false},
		{"2.17.1", "<=2.17.1", true},
		{"2.21.0", "<2.17.1", false},
		{"3.0.0", ">=2.17.1", true},
		{"2.17.1", "=2.17.1", true},
		{"2.17.0", "=2.17.1", false},
		{"1.0.0", "1.0.0", true},  // no operator → exact match
		{"", "<2.0.0", true},       // empty version → assume match
	}
	for _, tc := range tests {
		got := versionInRange(tc.version, tc.constraint)
		assert.Equal(t, tc.want, got, "versionInRange(%q, %q)", tc.version, tc.constraint)
	}
}
