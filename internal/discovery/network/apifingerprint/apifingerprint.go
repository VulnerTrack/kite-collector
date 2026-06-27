// Package apifingerprint identifies REST APIs, GraphQL endpoints, and
// other HTTP-exposed services by sending a small set of well-known GET
// probes and matching their responses against a curated catalog.
//
// The detector is read-only: it never authenticates, never writes, and
// never follows redirects (a redirect to an attacker-controlled
// destination must not influence a fingerprint). Body reads are capped
// at MaxBodyBytes so a hostile server can't OOM the agent.
//
// The catalog is seeded from public, project-published health and
// version endpoints (Grafana /api/health, Prometheus /api/v1/status/
// buildinfo, Elasticsearch /, etc.) and is extended over time. Each
// Signature lists one or more Probes; a Signature emits a Fingerprint
// when at least one Probe matches, and Confidence rises with the count.
package apifingerprint

import (
	"regexp"
	"sort"
	"strings"
)

// MaxBodyBytes bounds how much of any HTTP response body the detector
// reads before deciding whether a Probe matched. Most fingerprints fit
// in well under a kilobyte; the cap exists purely as a hostile-server
// safety belt.
const MaxBodyBytes = 64 * 1024

// Category groups fingerprints by the kind of service they identify so
// downstream consumers can filter (e.g. "show only auth endpoints").
type Category string

const (
	CategoryObservability Category = "observability"
	CategoryDatabase      Category = "database"
	CategorySearch        Category = "search"
	CategoryAuth          Category = "auth"
	CategoryCICD          Category = "ci-cd"
	CategoryServiceMesh   Category = "service-mesh"
	CategoryRESTAPI       Category = "rest-api"
	CategoryGraphQL       Category = "graphql"
	CategoryKubernetes    Category = "kubernetes"
	CategoryStorage       Category = "storage"
	CategoryMessageQueue  Category = "message-queue"
	CategoryDataInfra     Category = "data-infrastructure"
	CategoryAPIGateway    Category = "api-gateway"
	CategoryCMS           Category = "cms"
	CategoryAIInference   Category = "ai-inference"
	CategoryVectorDB      Category = "vector-db"
	CategoryFediverse     Category = "fediverse"
	CategoryITSM          Category = "itsm"
	CategoryLowCode       Category = "low-code"
	CategoryHypervisor    Category = "hypervisor"
	CategoryDBAdmin       Category = "db-admin"
	CategoryStreaming     Category = "streaming"
	CategoryQueueUI       Category = "queue-ui"
	CategoryEcommerce     Category = "ecommerce"
	CategoryAPM           Category = "apm"
	CategoryMail          Category = "mail"
	CategoryRPA           Category = "rpa"
	CategoryNotebook      Category = "notebook"
	CategoryDocMgmt       Category = "doc-mgmt"
	CategoryMedia         Category = "media"
	CategoryGeo           Category = "geo"
	CategoryPKI           Category = "pki"
	CategoryGameAdmin     Category = "game-admin"
	CategoryERP           Category = "erp"
	CategoryWebFramework  Category = "web-framework"
	CategoryGeneric       Category = "generic"
)

// Confidence ranks how certain a single fingerprint match is.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Probe is a single HTTP GET against Path scored against a set of
// optional matchers. At least one of (BodyContains, BodyRegex,
// HeaderName) must be set for the probe to be useful — a probe with
// only ExpectedStatus is too weak on its own (every reverse proxy
// returns 200) and is rejected at catalog-load time.
type Probe struct {
	// Path is the URL path component, including any leading slash.
	Path string
	// ExpectedStatus is the set of HTTP status codes that count as a
	// hit; an empty slice means "any 2xx".
	ExpectedStatus []int
	// BodyContains is a literal substring match against the truncated
	// response body. Empty = no body-substring check.
	BodyContains string
	// BodyRegex is a compiled regex run against the truncated body.
	// nil = no regex check.
	BodyRegex *regexp.Regexp
	// HeaderName, HeaderRegex check a response header. HeaderRegex
	// may be nil to assert mere header presence.
	HeaderName  string
	HeaderRegex *regexp.Regexp
}

// HasMatcher reports whether the Probe has any non-status matcher set.
// Probes without one are catalog bugs.
func (p Probe) HasMatcher() bool {
	return p.BodyContains != "" || p.BodyRegex != nil || p.HeaderName != ""
}

// Signature is one product's detection rule set. All Probes share the
// same vendor/product attribution; the engine emits a single Fingerprint
// per Signature even if multiple Probes hit.
type Signature struct {
	Vendor   string
	Product  string
	Category Category
	Probes   []Probe
	// Confidence is the maximum confidence a perfect match can yield.
	// A partial match (some Probes hit, others missed) yields one
	// tier lower.
	Confidence Confidence
}

// Fingerprint is the read-only outcome of one matched Signature.
type Fingerprint struct {
	Vendor     string     `json:"vendor"`
	Product    string     `json:"product"`
	Category   Category   `json:"category"`
	Endpoint   string     `json:"endpoint"`
	Evidence   []string   `json:"evidence"`
	Confidence Confidence `json:"confidence"`
}

// Result is the full output of one Probe(host, port) sweep.
type Result struct {
	Endpoint     string        `json:"endpoint"`
	Fingerprints []Fingerprint `json:"fingerprints"`
}

// downgradeConfidence shifts a Confidence one tier toward Low. Used
// when a Signature's Probes only partially match.
func downgradeConfidence(c Confidence) Confidence {
	switch c {
	case ConfidenceHigh:
		return ConfidenceMedium
	case ConfidenceMedium:
		return ConfidenceLow
	default:
		return ConfidenceLow
	}
}

// SortFingerprints orders fingerprints deterministically — by vendor
// then product — so downstream JSON / hash output is stable.
func SortFingerprints(fps []Fingerprint) {
	sort.Slice(fps, func(i, j int) bool {
		if fps[i].Vendor != fps[j].Vendor {
			return fps[i].Vendor < fps[j].Vendor
		}
		return fps[i].Product < fps[j].Product
	})
}

// uniqueStrings de-duplicates and stably orders a slice of evidence
// strings. Used so a single Signature does not list the same hit twice
// when the body matches multiple matchers.
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
