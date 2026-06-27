// Package filefingerprint probes an HTTP origin for well-known and
// commonly-exposed file paths, classifying each hit as a Finding with
// a severity rating.
//
// This is the file-discovery complement to apifingerprint (REST
// endpoints), jsfingerprint (HTML/JS bodies), and tlsfingerprint
// (cert metadata). It exists because the most embarrassing leaks at
// the application boundary are not behind APIs at all — they are
// flat files left at canonical paths:
//
//   - VCS repositories: /.git/HEAD lets an attacker reconstruct the
//     full source tree via git clone over HTTP.
//   - Environment files: /.env almost always carries database
//     credentials, API tokens, and signing keys.
//   - Build artefacts: /package.json + /composer.json expose the
//     dependency tree which feeds CVE matching.
//   - Admin entry points: /phpmyadmin, /wp-admin let an attacker
//     pivot from "exposed" to "exploited".
//   - Well-known endpoints: /.well-known/security.txt,
//     /.well-known/openid-configuration are legitimately useful for
//     inventory.
//
// Each Probe carries a Severity (info/low/medium/high/critical) so
// downstream tooling can triage. Read-only: never POSTs, never
// follows redirects, body reads are capped at MaxBodyBytes.
package filefingerprint

import (
	"regexp"
	"sort"
	"strings"
)

// MaxBodyBytes caps each HTTP body read. Most fingerprint files
// (config dumps, manifests) sit well under 64 KiB; the cap exists as
// a hostile-server defence.
const MaxBodyBytes = 64 * 1024

// Severity rates how serious a hit is. Inventory consumers can
// filter on severity to surface only actionable items.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Category groups Probes by the kind of file they represent.
type Category string

const (
	CategoryVCS       Category = "vcs"
	CategorySecrets   Category = "secrets"
	CategoryConfig    Category = "config"
	CategoryManifest  Category = "manifest"
	CategoryBackup    Category = "backup"
	CategoryAdmin     Category = "admin"
	CategoryWellKnown Category = "well-known"
	CategoryDebug     Category = "debug"
	CategoryIDE       Category = "ide"
	CategoryDocs      Category = "docs"
	CategoryGeneric   Category = "generic"
)

// Probe is a single (path, expected response) check. A body matcher
// is recommended for paths that often return a generic 200 from a
// SPA's catch-all index handler — without it, a Probe would emit a
// false positive on every Next.js/Nuxt/Vite app.
type Probe struct {
	BodyRegex      *regexp.Regexp
	Path           string
	Description    string
	Category       Category
	Severity       Severity
	BodyContains   string
	MustNotContain string
	ExpectedStatus []int
}

// Finding is one matched Probe on one origin.
type Finding struct {
	Path        string   `json:"path"`
	URL         string   `json:"url"`
	Description string   `json:"description"`
	Category    Category `json:"category"`
	Severity    Severity `json:"severity"`
	Evidence    []string `json:"evidence,omitempty"`
	StatusCode  int      `json:"status_code"`
}

// Result bundles every Finding the Scanner emits for one origin.
type Result struct {
	Endpoint string    `json:"endpoint"`
	Findings []Finding `json:"findings"`
}

// SortFindings orders by descending severity, then path so the
// highest-impact items surface first in lists.
func SortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		if severityRank(fs[i].Severity) != severityRank(fs[j].Severity) {
			return severityRank(fs[i].Severity) > severityRank(fs[j].Severity)
		}
		return fs[i].Path < fs[j].Path
	})
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// MatchProbe reports whether p matches the supplied response, with
// evidence describing what tipped it over. Callers truncate body to
// MaxBodyBytes before calling.
func MatchProbe(p Probe, status int, body string) (bool, []string) {
	if !statusAllowed(status, p.ExpectedStatus) {
		return false, nil
	}
	matched := true
	matchedAny := false
	var ev []string
	if p.BodyContains != "" {
		if strings.Contains(body, p.BodyContains) {
			ev = append(ev, "body contains "+truncate(p.BodyContains, 64))
			matchedAny = true
		} else {
			matched = false
		}
	}
	if p.BodyRegex != nil {
		if p.BodyRegex.MatchString(body) {
			ev = append(ev, "body matches regex")
			matchedAny = true
		} else {
			matched = false
		}
	}
	if p.MustNotContain != "" && strings.Contains(body, p.MustNotContain) {
		matched = false
	}
	if p.BodyContains == "" && p.BodyRegex == nil {
		// status-only match — counts as a hit.
		matchedAny = true
	}
	if !matched || !matchedAny {
		return false, nil
	}
	return true, ev
}

func statusAllowed(got int, allow []int) bool {
	if len(allow) == 0 {
		return got >= 200 && got < 300
	}
	for _, want := range allow {
		if got == want {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
