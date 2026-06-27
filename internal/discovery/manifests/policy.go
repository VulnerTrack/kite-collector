package manifests

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/manifests/parsers"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// PolicyConfig defines dependency approval rules.
type PolicyConfig struct {
	Mode      string // "blocklist_only" (default), "allowlist_only", "both"
	Blocklist []BlocklistRule
	Allowlist []AllowlistRule
}

// BlocklistRule defines a banned dependency pattern.
type BlocklistRule struct {
	Name        string // regex matched against dependency name (case-insensitive)
	Version     string // semver constraint (optional); empty = all versions
	Reason      string // human-readable reason
	Remediation string // suggested fix
}

// AllowlistRule defines an approved dependency pattern.
type AllowlistRule struct {
	Name string // regex matched against dependency name (case-insensitive)
}

// PolicyEngine evaluates dependencies against blocklist/allowlist rules.
type PolicyEngine struct {
	mode      string
	blocklist []*compiledBlock
	allowlist []*regexp.Regexp
}

type compiledBlock struct {
	pattern     *regexp.Regexp
	name        string // original pattern string for RuleID
	version     string // raw semver constraint
	reason      string
	remediation string
}

// NewPolicyEngine compiles policy rules. Invalid regexes are silently skipped.
func NewPolicyEngine(cfg PolicyConfig) *PolicyEngine {
	pe := &PolicyEngine{mode: cfg.Mode}
	if pe.mode == "" {
		pe.mode = "blocklist_only"
	}

	for _, rule := range cfg.Blocklist {
		re, err := regexp.Compile("(?i)" + rule.Name)
		if err != nil {
			continue
		}
		pe.blocklist = append(pe.blocklist, &compiledBlock{
			pattern:     re,
			name:        rule.Name,
			version:     rule.Version,
			reason:      rule.Reason,
			remediation: rule.Remediation,
		})
	}

	for _, rule := range cfg.Allowlist {
		re, err := regexp.Compile("(?i)" + rule.Name)
		if err != nil {
			continue
		}
		pe.allowlist = append(pe.allowlist, re)
	}

	return pe
}

// Evaluate checks a dependency against all policy rules and returns any violations.
func (pe *PolicyEngine) Evaluate(dep parsers.Dependency, assetID uuid.UUID, now time.Time) []model.ConfigFinding {
	if pe == nil {
		return nil
	}

	var findings []model.ConfigFinding

	if pe.mode == "blocklist_only" || pe.mode == "both" {
		for _, rule := range pe.blocklist {
			if !rule.pattern.MatchString(dep.Name) {
				continue
			}
			if rule.version != "" && !versionInRange(dep.Version, rule.version) {
				continue
			}
			findings = append(findings, model.ConfigFinding{
				ID:          newID(),
				AssetID:     assetID,
				Timestamp:   now,
				Auditor:     "manifest_scanner",
				CheckID:     "blocklist:" + rule.name,
				Title:       fmt.Sprintf("Blocklisted dependency: %s %s", dep.Name, dep.Version),
				Severity:    model.SeverityCritical,
				Evidence:    fmt.Sprintf("Matched blocklist pattern %q; reason: %s", rule.name, rule.reason),
				Remediation: rule.remediation,
			})
		}
	}

	if pe.mode == "allowlist_only" || pe.mode == "both" {
		if len(pe.allowlist) > 0 && !pe.isAllowed(dep.Name) {
			findings = append(findings, model.ConfigFinding{
				ID:          newID(),
				AssetID:     assetID,
				Timestamp:   now,
				Auditor:     "manifest_scanner",
				CheckID:     "allowlist:not_approved",
				Title:       fmt.Sprintf("Unapproved dependency: %s %s", dep.Name, dep.Version),
				Severity:    model.SeverityMedium,
				Evidence:    fmt.Sprintf("Dependency %q not in allowlist", dep.Name),
				Remediation: "Add to the approved dependency list or remove from the project.",
			})
		}
	}

	return findings
}

func (pe *PolicyEngine) isAllowed(name string) bool {
	for _, re := range pe.allowlist {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// versionInRange checks if depVersion satisfies a simple semver constraint.
// Supported operators: "<", "<=", ">", ">=", "=". No operator means exact match.
// An empty depVersion is treated as matching (worst-case assumption).
func versionInRange(depVersion, constraint string) bool {
	if depVersion == "" {
		return true
	}

	constraint = strings.TrimSpace(constraint)
	var op, target string

	for _, prefix := range []string{"<=", ">=", "<", ">", "="} {
		if strings.HasPrefix(constraint, prefix) {
			op = prefix
			target = strings.TrimSpace(constraint[len(prefix):])
			break
		}
	}
	if op == "" {
		op = "="
		target = constraint
	}

	cmp := compareSemver(depVersion, target)
	switch op {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "=":
		return cmp == 0
	}
	return false
}

// compareSemver compares two dotted version strings numerically.
// Returns -1, 0, or 1.
func compareSemver(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := range maxLen {
		var av, bv string
		if i < len(aParts) {
			av = aParts[i]
		}
		if i < len(bParts) {
			bv = bParts[i]
		}

		an, aErr := strconv.Atoi(av)
		bn, bErr := strconv.Atoi(bv)

		if aErr == nil && bErr == nil {
			if an < bn {
				return -1
			}
			if an > bn {
				return 1
			}
		} else {
			if av < bv {
				return -1
			}
			if av > bv {
				return 1
			}
		}
	}
	return 0
}
