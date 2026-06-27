// Package jsfingerprint identifies client-side SDKs and Backend-as-a-
// Service (BaaS) integrations by scanning fetched HTML pages and their
// linked JavaScript bundles for known signal patterns.
//
// This is the client-side complement to apifingerprint. Where
// apifingerprint hits well-known REST endpoints to identify a server
// product, jsfingerprint walks the body of a rendered page (and a
// bounded set of same-origin scripts referenced by it) to extract
// signals such as:
//
//   - SDK script-src CDNs (e.g. "supabase-js@2/dist", "firebase-app.js")
//   - global symbol names (e.g. "Stripe", "firebase", "supabase")
//   - configuration object literals (e.g. firebaseConfig = { apiKey })
//   - endpoint URL hostname patterns (e.g. "*.supabase.co/rest/v1")
//   - inlined env-var names (e.g. NEXT_PUBLIC_SUPABASE_URL)
//   - public-key prefixes (Stripe pk_live_, Clerk pk_test_, etc.)
//
// Each Signature lists one or more Patterns; the Detector emits a
// Fingerprint when any Pattern matches, with the strongest matching
// signal's confidence. Capture groups named "id" are extracted into
// Fingerprint.ProjectID so an inventory consumer can correlate which
// Supabase / Firebase / Sanity project the page is bound to.
//
// Read-only by intent: no JS is executed, no headers are sent that
// look like a real browser, no auth is attempted. Body reads are
// capped at MaxBodyBytes so a hostile origin can't OOM the scanner.
package jsfingerprint

import (
	"regexp"
	"sort"
	"strings"
)

// MaxBodyBytes bounds each HTTP response read. BaaS bundles are
// typically 200KB–2MB; 4MB covers the head we need (scripts are
// truncated at the end so we keep the first portion which contains
// config/init blocks).
const MaxBodyBytes = 4 * 1024 * 1024

// MaxLinkedScripts is the highest number of <script src> URLs that
// the Detector will fetch per page. Real apps reference 5–20; the cap
// stops a hostile page from steering the scanner through hundreds.
const MaxLinkedScripts = 12

// Category groups fingerprints so inventory consumers can filter.
type Category string

const (
	CategoryBaaS         Category = "baas"
	CategoryAuth         Category = "auth"
	CategoryAnalytics    Category = "analytics"
	CategoryPayments     Category = "payments"
	CategoryCMS          Category = "cms"
	CategorySearch       Category = "search"
	CategoryFeatureFlags Category = "feature-flags"
	CategoryMonitoring   Category = "monitoring"
	CategoryHeadlessUI   Category = "headless-ui"
	CategoryEdge         Category = "edge"
	CategorySecretLeak   Category = "secret-leak"
	CategoryGeneric      Category = "generic"
)

// SignalKind describes what kind of evidence a Pattern matches.
// Different kinds carry different default confidence:
//
//   - script-src + global-symbol + endpoint-url → high (specific URLs/IDs)
//   - config-literal + public-key → high (verbatim project markers)
//   - envvar-name → medium (env-var names leak from bundlers but are
//     generic enough to false-positive on inline JSON)
//   - global-symbol alone → low (variable names are noisy)
type SignalKind string

const (
	SignalScriptSrc     SignalKind = "script-src"
	SignalGlobalSymbol  SignalKind = "global-symbol"
	SignalConfigLiteral SignalKind = "config-literal"
	SignalEndpointURL   SignalKind = "endpoint-url"
	SignalEnvVarName    SignalKind = "envvar-name"
	SignalPublicKey     SignalKind = "public-key"
)

// Confidence ranks how certain a single Pattern match is.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Pattern is one regex-based detection rule. The regex is run over
// the truncated body; if a capture group named "id" exists and
// matches, the captured text is extracted as the project / tenant /
// app ID. Other named groups are ignored.
type Pattern struct {
	Name       string
	Regex      *regexp.Regexp
	Kind       SignalKind
	Confidence Confidence
}

// Signature is one product's detection rule set. Any one Pattern
// matching emits a Fingerprint; the Fingerprint inherits the strongest
// matched Pattern's Confidence.
type Signature struct {
	Vendor   string
	Product  string
	Category Category
	Patterns []Pattern
}

// Fingerprint is the read-only result of one matched Signature on
// one fetched URL.
type Fingerprint struct {
	Vendor     string     `json:"vendor"`
	Product    string     `json:"product"`
	Category   Category   `json:"category"`
	Endpoint   string     `json:"endpoint"`
	ProjectID  string     `json:"project_id,omitempty"`
	Evidence   []string   `json:"evidence"`
	Confidence Confidence `json:"confidence"`
}

// Result bundles every Fingerprint produced from one Scan() call.
type Result struct {
	Endpoint     string        `json:"endpoint"`
	Fingerprints []Fingerprint `json:"fingerprints"`
}

// confidenceRank turns a Confidence into a comparable integer so we
// can pick the strongest among several Pattern matches.
func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	}
	return 0
}

// stronger returns the higher-ranked of two confidences.
func stronger(a, b Confidence) Confidence {
	if confidenceRank(a) >= confidenceRank(b) {
		return a
	}
	return b
}

// SortFingerprints orders fingerprints deterministically for stable
// downstream output. Sort is by vendor, product, project ID.
func SortFingerprints(fps []Fingerprint) {
	sort.Slice(fps, func(i, j int) bool {
		if fps[i].Vendor != fps[j].Vendor {
			return fps[i].Vendor < fps[j].Vendor
		}
		if fps[i].Product != fps[j].Product {
			return fps[i].Product < fps[j].Product
		}
		return fps[i].ProjectID < fps[j].ProjectID
	})
}

// uniqueStrings returns a stable de-duplicated copy of in.
func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// MatchPattern runs p against body and returns (matched, evidence,
// projectID). The evidence string is short ("<kind>: <pattern name>"
// plus a hint of where in the body). projectID is the value of any
// regex capture group named "id".
func MatchPattern(p Pattern, body string) (bool, string, string) {
	if p.Regex == nil {
		return false, "", ""
	}
	m := p.Regex.FindStringSubmatchIndex(body)
	if m == nil {
		return false, "", ""
	}
	var projectID string
	for i, name := range p.Regex.SubexpNames() {
		if name == "id" && i*2+1 < len(m) && m[i*2] >= 0 {
			projectID = body[m[i*2]:m[i*2+1]]
			break
		}
	}
	// Evidence: kind + pattern name + snippet around the match,
	// trimmed and length-capped so it's safe to surface verbatim.
	snippetStart := m[0] - 16
	if snippetStart < 0 {
		snippetStart = 0
	}
	snippetEnd := m[1] + 16
	if snippetEnd > len(body) {
		snippetEnd = len(body)
	}
	snippet := strings.ReplaceAll(body[snippetStart:snippetEnd], "\n", " ")
	snippet = strings.TrimSpace(snippet)
	if len(snippet) > 80 {
		snippet = snippet[:77] + "..."
	}
	return true, string(p.Kind) + ":" + p.Name + " — " + snippet, projectID
}

// scriptSrcRegex pulls the URLs out of <script src="..."> tags so the
// Detector can follow them. Picks up both single- and double-quoted
// forms and supports protocol-relative URLs.
var scriptSrcRegex = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

// ExtractScriptSrcs returns the de-duplicated list of script src URLs
// referenced from the supplied HTML body. Protocol-relative URLs are
// returned as-is and the caller resolves them against the page URL.
func ExtractScriptSrcs(body string) []string {
	matches := scriptSrcRegex.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		s := strings.TrimSpace(m[1])
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
