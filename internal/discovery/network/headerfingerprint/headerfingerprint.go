// Package headerfingerprint identifies servers, frameworks, CDNs, and
// session-tracking technologies by examining HTTP response headers.
//
// This is the cheapest network fingerprinting mechanism: a single
// HTTP GET against the origin's root reveals a Server header,
// X-Powered-By, X-Vercel-Id, CF-Ray, and a Set-Cookie list whose
// names alone (PHPSESSID, JSESSIONID, connect.sid, laravel_session)
// reveal the runtime stack. It catches what apifingerprint misses —
// software without a distinctive REST path but with distinctive
// header behaviour.
//
// Read-only by intent: never authenticates, never POSTs, never
// follows redirects (a 302 to a CDN would otherwise mask the origin's
// own headers). Body is not consumed beyond the cap because the
// signal lives in the headers; the body cap is purely defensive
// against a hostile server that buffers the connection open.
package headerfingerprint

import (
	"regexp"
	"sort"
	"strings"
)

// MaxBodyBytes caps body drain so a slow-loris origin cannot pin the
// scanner. We do not match against the body — that's apifingerprint's
// job — but the body must be drained so the connection can close
// cleanly.
const MaxBodyBytes = 4 * 1024

// Category groups header fingerprints so consumers can filter.
type Category string

const (
	CategoryWebServer    Category = "web-server"
	CategoryAppRuntime   Category = "app-runtime"
	CategoryFramework    Category = "framework"
	CategoryCDN          Category = "cdn"
	CategoryEdgeHosting  Category = "edge-hosting"
	CategoryCMS          Category = "cms"
	CategoryAuth         Category = "auth"
	CategoryCache        Category = "cache"
	CategorySessionTrack Category = "session-tracking"
	CategorySecurity     Category = "security"
	CategoryGeneric      Category = "generic"
)

// Confidence ranks how certain a single hit is.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// SignalKind classifies which kind of header evidence produced the hit.
type SignalKind string

const (
	SignalHeaderName  SignalKind = "header-name"  // header presence alone
	SignalHeaderValue SignalKind = "header-value" // header value regex / substring
	SignalCookieName  SignalKind = "cookie-name"  // Set-Cookie name pattern
)

// Pattern is one matcher in a Signature. Exactly one of the matcher
// fields (HeaderName / CookieName) must drive the lookup; ValueRegex
// and ValueContains optionally narrow header-value matching.
type Pattern struct {
	Name string
	// HeaderName matches a response header (case-insensitive). When
	// only HeaderName is set, mere presence counts as a hit.
	HeaderName string
	// ValueRegex narrows a header-value match.
	ValueRegex *regexp.Regexp
	// ValueContains narrows a header-value match (substring).
	ValueContains string
	// CookieName matches the *name* of any Set-Cookie value. The
	// value is ignored (it's a session id).
	CookieName string
	Kind       SignalKind
	Confidence Confidence
}

// Signature is one product's detection rule set.
type Signature struct {
	Vendor   string
	Product  string
	Category Category
	Patterns []Pattern
}

// Fingerprint is one matched Signature on one origin.
type Fingerprint struct {
	Vendor     string     `json:"vendor"`
	Product    string     `json:"product"`
	Category   Category   `json:"category"`
	Endpoint   string     `json:"endpoint"`
	Confidence Confidence `json:"confidence"`
	Evidence   []string   `json:"evidence"`
}

// Result is the full output of one Probe() call.
type Result struct {
	Endpoint     string        `json:"endpoint"`
	Fingerprints []Fingerprint `json:"fingerprints"`
}

// SortFingerprints orders fingerprints deterministically.
func SortFingerprints(fps []Fingerprint) {
	sort.Slice(fps, func(i, j int) bool {
		if fps[i].Vendor != fps[j].Vendor {
			return fps[i].Vendor < fps[j].Vendor
		}
		return fps[i].Product < fps[j].Product
	})
}

// confRank converts a Confidence to a comparable int.
func confRank(c Confidence) int {
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
	if confRank(a) >= confRank(b) {
		return a
	}
	return b
}

// uniqueStrings — shared helper shape across packages.
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

// MatchPattern reports whether p matches the supplied header set and
// returns evidence. headers must be in canonical http.Header form
// (case-insensitive lookup via Get / Values); cookieNames is the
// extracted list of Set-Cookie names already parsed from the response.
func MatchPattern(p Pattern, headers Headers, cookieNames []string) (bool, string) {
	if p.CookieName != "" {
		want := strings.ToLower(p.CookieName)
		for _, name := range cookieNames {
			if strings.ToLower(name) == want {
				return true, "cookie:" + name
			}
		}
		return false, ""
	}
	if p.HeaderName != "" {
		vals := headers.Values(p.HeaderName)
		if len(vals) == 0 {
			return false, ""
		}
		if p.ValueRegex == nil && p.ValueContains == "" {
			return true, "header " + p.HeaderName + ": " + headers.Get(p.HeaderName)
		}
		for _, v := range vals {
			if p.ValueRegex != nil && p.ValueRegex.MatchString(v) {
				return true, "header " + p.HeaderName + " ~= /" + p.ValueRegex.String() + "/ (" + truncate(v, 60) + ")"
			}
			if p.ValueContains != "" && strings.Contains(v, p.ValueContains) {
				return true, "header " + p.HeaderName + " contains " + p.ValueContains + " (" + truncate(v, 60) + ")"
			}
		}
	}
	return false, ""
}

// Headers is the narrow contract MatchPattern needs from the response.
// We accept any type that exposes Get / Values so callers can use
// http.Header directly or a stub.
type Headers interface {
	Get(name string) string
	Values(name string) []string
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
