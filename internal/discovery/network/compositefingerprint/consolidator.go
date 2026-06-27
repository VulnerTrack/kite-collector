package compositefingerprint

import (
	"strings"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/apifingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/headerfingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/jsfingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/tlsfingerprint"
)

// StackSummary is the per-endpoint synthesis produced by Summarise().
// Each non-nil field is the heuristic "best guess" for one
// architectural layer; the full CompositeResult is still authoritative
// when an operator needs every match across surfaces.
//
// Auth, Analytics, and DataLayer are slices because a real endpoint
// commonly stacks multiple SDKs (OneTrust + Cookiebot, GA4 + Hotjar,
// Supabase + Firebase). Single-value layers (Hosting, WebServer,
// Runtime, Framework) collapse to one Pick because "two web servers"
// or "two frameworks" rarely makes sense.
type StackSummary struct {
	Endpoint    string  `json:"endpoint"`
	Hosting     *Pick   `json:"hosting,omitempty"`
	WebServer   *Pick   `json:"web_server,omitempty"`
	Runtime     *Pick   `json:"runtime,omitempty"`
	Framework   *Pick   `json:"framework,omitempty"`
	Auth        []*Pick `json:"auth,omitempty"`
	Analytics   []*Pick `json:"analytics,omitempty"`
	DataLayer   []*Pick `json:"data_layer,omitempty"`
	SecretsLeak []*Pick `json:"secrets_leak,omitempty"`
}

// Pick is one selected vendor for one StackSummary layer. Sources
// carries the per-mechanism IDs that contributed to the choice
// ("tls", "header", "js", "api") so the operator can confirm the
// pick against the underlying CompositeResult.
type Pick struct {
	Vendor     string   `json:"vendor"`
	Product    string   `json:"product"`
	Confidence string   `json:"confidence"`
	Sources    []string `json:"sources"`
}

// confRank returns a numeric rank for a string-valued confidence so
// the consolidator can compare ranks across the five fingerprint
// packages, which each define their own Confidence type alias.
func confRank(c string) int {
	switch c {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// FilterByVendor returns a CompositeResult keeping only fingerprints
// whose Vendor contains the supplied substring (case-insensitive). An
// empty substring is passthrough. Useful when an operator wants to
// scope a sweep's output to one vendor — e.g. "show me only Vercel
// signals across the five surfaces".
func (r *CompositeResult) FilterByVendor(substr string) CompositeResult {
	if r == nil {
		return CompositeResult{}
	}
	out := *r
	out.Errors = append([]MechanismError(nil), r.Errors...)
	if substr == "" {
		return out
	}
	want := strings.ToLower(substr)
	keepStr := func(v string) bool {
		return strings.Contains(strings.ToLower(v), want)
	}
	if r.TLS != nil {
		c := *r.TLS
		c.Fingerprints = nil
		for _, fp := range r.TLS.Fingerprints {
			if keepStr(fp.Vendor) {
				c.Fingerprints = append(c.Fingerprints, fp)
			}
		}
		out.TLS = &c
	}
	if r.Header != nil {
		c := *r.Header
		c.Fingerprints = nil
		for _, fp := range r.Header.Fingerprints {
			if keepStr(fp.Vendor) {
				c.Fingerprints = append(c.Fingerprints, fp)
			}
		}
		out.Header = &c
	}
	if r.JS != nil {
		c := *r.JS
		c.Fingerprints = nil
		for _, fp := range r.JS.Fingerprints {
			if keepStr(fp.Vendor) {
				c.Fingerprints = append(c.Fingerprints, fp)
			}
		}
		out.JS = &c
	}
	if r.API != nil {
		c := *r.API
		c.Fingerprints = nil
		for _, fp := range r.API.Fingerprints {
			if keepStr(fp.Vendor) {
				c.Fingerprints = append(c.Fingerprints, fp)
			}
		}
		out.API = &c
	}
	return out
}

// FilterByCategory returns a CompositeResult keeping only fingerprints
// whose Category equals one of the supplied values (case-insensitive
// exact match). An empty or nil list is passthrough. Categories from
// different surface packages live in different string spaces (e.g.
// jsfingerprint's "auth" vs headerfingerprint's "auth") but
// fortunately their values overlap conceptually — a "web-framework"
// category in apifingerprint and "framework" in headerfingerprint are
// both passed when the operator asks for either name.
func (r *CompositeResult) FilterByCategory(categories []string) CompositeResult {
	if r == nil {
		return CompositeResult{}
	}
	out := *r
	out.Errors = append([]MechanismError(nil), r.Errors...)
	if len(categories) == 0 {
		return out
	}
	want := make(map[string]struct{}, len(categories))
	for _, c := range categories {
		want[strings.ToLower(strings.TrimSpace(c))] = struct{}{}
	}
	keepStr := func(c string) bool {
		_, ok := want[strings.ToLower(c)]
		return ok
	}
	if r.TLS != nil {
		c := *r.TLS
		c.Fingerprints = nil
		for _, fp := range r.TLS.Fingerprints {
			if keepStr(string(fp.Category)) {
				c.Fingerprints = append(c.Fingerprints, fp)
			}
		}
		out.TLS = &c
	}
	if r.Header != nil {
		c := *r.Header
		c.Fingerprints = nil
		for _, fp := range r.Header.Fingerprints {
			if keepStr(string(fp.Category)) {
				c.Fingerprints = append(c.Fingerprints, fp)
			}
		}
		out.Header = &c
	}
	if r.JS != nil {
		c := *r.JS
		c.Fingerprints = nil
		for _, fp := range r.JS.Fingerprints {
			if keepStr(string(fp.Category)) {
				c.Fingerprints = append(c.Fingerprints, fp)
			}
		}
		out.JS = &c
	}
	if r.API != nil {
		c := *r.API
		c.Fingerprints = nil
		for _, fp := range r.API.Fingerprints {
			if keepStr(string(fp.Category)) {
				c.Fingerprints = append(c.Fingerprints, fp)
			}
		}
		out.API = &c
	}
	return out
}

// FilterByConfidence returns a CompositeResult containing only
// fingerprints at or above the supplied min confidence band ("low",
// "medium", or "high"). An empty min returns the result unchanged.
// File findings are kept as-is because filefingerprint does not carry
// a confidence field — operators can suppress them with --skip file.
//
// Used to suppress noisy low-confidence matches before Summarise() or
// before serialisation to JSON. The original CompositeResult is not
// mutated.
func (r *CompositeResult) FilterByConfidence(min string) CompositeResult {
	if r == nil {
		return CompositeResult{}
	}
	out := *r
	out.Errors = append([]MechanismError(nil), r.Errors...)
	threshold := confRank(min)
	if threshold == 0 {
		return out
	}
	if r.TLS != nil {
		tlsCopy := *r.TLS
		tlsCopy.Fingerprints = nil
		for _, fp := range r.TLS.Fingerprints {
			if confRank(string(fp.Confidence)) >= threshold {
				tlsCopy.Fingerprints = append(tlsCopy.Fingerprints, fp)
			}
		}
		out.TLS = &tlsCopy
	}
	if r.Header != nil {
		hCopy := *r.Header
		hCopy.Fingerprints = nil
		for _, fp := range r.Header.Fingerprints {
			if confRank(string(fp.Confidence)) >= threshold {
				hCopy.Fingerprints = append(hCopy.Fingerprints, fp)
			}
		}
		out.Header = &hCopy
	}
	if r.JS != nil {
		jCopy := *r.JS
		jCopy.Fingerprints = nil
		for _, fp := range r.JS.Fingerprints {
			if confRank(string(fp.Confidence)) >= threshold {
				jCopy.Fingerprints = append(jCopy.Fingerprints, fp)
			}
		}
		out.JS = &jCopy
	}
	if r.API != nil {
		aCopy := *r.API
		aCopy.Fingerprints = nil
		for _, fp := range r.API.Fingerprints {
			if confRank(string(fp.Confidence)) >= threshold {
				aCopy.Fingerprints = append(aCopy.Fingerprints, fp)
			}
		}
		out.API = &aCopy
	}
	return out
}

// candidate is the consolidator's internal accumulator: one vendor/
// product pair under consideration, with a running best confidence
// and a de-duplicated source list.
type candidate struct {
	sources map[string]struct{}
	vendor  string
	product string
	conf    string
}

func (c *candidate) addSource(src, conf string) {
	if c.sources == nil {
		c.sources = make(map[string]struct{})
	}
	c.sources[src] = struct{}{}
	if confRank(conf) > confRank(c.conf) {
		c.conf = conf
	}
}

func (c *candidate) toPick() *Pick {
	if c == nil || c.vendor == "" {
		return nil
	}
	srcs := make([]string, 0, len(c.sources))
	for s := range c.sources {
		srcs = append(srcs, s)
	}
	// Canonical source order so output is stable.
	order := map[string]int{"tls": 0, "header": 1, "api": 2, "js": 3, "file": 4}
	sortSrcs(srcs, order)
	return &Pick{
		Vendor:     c.vendor,
		Product:    c.product,
		Sources:    srcs,
		Confidence: c.conf,
	}
}

func sortSrcs(s []string, order map[string]int) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && order[s[j-1]] > order[s[j]]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// Summarise reduces the CompositeResult to a StackSummary. The result
// is heuristic — it picks the highest-confidence match per layer and
// merges secondary surfaces that agree as supporting evidence. Use it
// when you want a one-line "what is this app" answer; fall back to
// the full CompositeResult when you need every attribution.
func (r *CompositeResult) Summarise() StackSummary {
	if r == nil {
		return StackSummary{}
	}
	s := StackSummary{Endpoint: r.Endpoint}
	s.Hosting = pickHosting(r)
	s.WebServer = pickWebServer(r)
	s.Runtime = pickRuntime(r)
	s.Framework = pickFramework(r)
	s.Auth = pickAuth(r)
	s.Analytics = pickAnalytics(r)
	s.DataLayer = pickDataLayer(r)
	s.SecretsLeak = pickSecretsLeak(r)
	return s
}

// pickBest reduces a vendor->candidate map to the single highest-
// confidence entry. Ties break in favour of more sources.
func pickBest(cands map[string]*candidate) *candidate {
	var best *candidate
	for _, c := range cands {
		if best == nil {
			best = c
			continue
		}
		if confRank(c.conf) > confRank(best.conf) {
			best = c
			continue
		}
		if confRank(c.conf) == confRank(best.conf) && len(c.sources) > len(best.sources) {
			best = c
		}
	}
	return best
}

// addFP merges one fingerprint into the candidate map keyed by
// vendor. Cross-surface agreement on the same vendor accumulates
// regardless of which sub-product each surface named — the picker
// keeps whichever Product had the highest single-surface confidence
// so the operator-facing label stays specific (e.g. "Next.js" wins
// over "Next.js (X-Powered-By)" when API saw both).
func addFP(cands map[string]*candidate, source, vendor, product, conf string) {
	if vendor == "" {
		return
	}
	c, ok := cands[vendor]
	if !ok {
		c = &candidate{vendor: vendor, product: product, conf: conf}
		cands[vendor] = c
	} else if confRank(conf) > confRank(c.conf) {
		c.product = product
	}
	c.addSource(source, conf)
}

func pickHosting(r *CompositeResult) *Pick {
	cands := make(map[string]*candidate)
	if r.TLS != nil {
		for _, fp := range r.TLS.Fingerprints {
			switch fp.Category {
			case tlsfingerprint.CategoryHosting,
				tlsfingerprint.CategoryServerless,
				tlsfingerprint.CategoryStaticHost,
				tlsfingerprint.CategoryCDN,
				tlsfingerprint.CategoryCloudCompute:
				addFP(cands, "tls", fp.Vendor, fp.Product, string(fp.Confidence))
			case tlsfingerprint.CategoryBaaS,
				tlsfingerprint.CategoryAuth,
				tlsfingerprint.CategoryStorage,
				tlsfingerprint.CategoryGeneric:
				// Not a hosting layer signal — handled by other pickers.
			}
		}
	}
	if r.Header != nil {
		for _, fp := range r.Header.Fingerprints {
			switch fp.Category {
			case headerfingerprint.CategoryEdgeHosting,
				headerfingerprint.CategoryCDN:
				addFP(cands, "header", fp.Vendor, fp.Product, string(fp.Confidence))
			case headerfingerprint.CategoryWebServer,
				headerfingerprint.CategoryAppRuntime,
				headerfingerprint.CategoryFramework,
				headerfingerprint.CategoryCMS,
				headerfingerprint.CategoryAuth,
				headerfingerprint.CategoryCache,
				headerfingerprint.CategorySessionTrack,
				headerfingerprint.CategorySecurity,
				headerfingerprint.CategoryGeneric:
				// Not a hosting layer signal — handled by other pickers.
			}
		}
	}
	return pickBest(cands).toPick()
}

func pickWebServer(r *CompositeResult) *Pick {
	cands := make(map[string]*candidate)
	if r.Header != nil {
		for _, fp := range r.Header.Fingerprints {
			if fp.Category == headerfingerprint.CategoryWebServer {
				addFP(cands, "header", fp.Vendor, fp.Product, string(fp.Confidence))
			}
		}
	}
	return pickBest(cands).toPick()
}

func pickRuntime(r *CompositeResult) *Pick {
	cands := make(map[string]*candidate)
	if r.Header != nil {
		for _, fp := range r.Header.Fingerprints {
			if fp.Category == headerfingerprint.CategoryAppRuntime {
				addFP(cands, "header", fp.Vendor, fp.Product, string(fp.Confidence))
			}
		}
	}
	return pickBest(cands).toPick()
}

func pickFramework(r *CompositeResult) *Pick {
	cands := make(map[string]*candidate)
	if r.API != nil {
		for _, fp := range r.API.Fingerprints {
			if fp.Category == apifingerprint.CategoryWebFramework {
				addFP(cands, "api", fp.Vendor, fp.Product, string(fp.Confidence))
			}
		}
	}
	if r.Header != nil {
		for _, fp := range r.Header.Fingerprints {
			if fp.Category == headerfingerprint.CategoryFramework {
				addFP(cands, "header", fp.Vendor, fp.Product, string(fp.Confidence))
			}
		}
	}
	return pickBest(cands).toPick()
}

func pickAuth(r *CompositeResult) []*Pick {
	cands := make(map[string]*candidate)
	if r.JS != nil {
		for _, fp := range r.JS.Fingerprints {
			if fp.Category == jsfingerprint.CategoryAuth {
				addFP(cands, "js", fp.Vendor, fp.Product, string(fp.Confidence))
			}
		}
	}
	if r.Header != nil {
		for _, fp := range r.Header.Fingerprints {
			if fp.Category == headerfingerprint.CategoryAuth ||
				fp.Category == headerfingerprint.CategorySessionTrack {
				addFP(cands, "header", fp.Vendor, fp.Product, string(fp.Confidence))
			}
		}
	}
	return allPicks(cands)
}

func pickAnalytics(r *CompositeResult) []*Pick {
	cands := make(map[string]*candidate)
	if r.JS != nil {
		for _, fp := range r.JS.Fingerprints {
			if fp.Category == jsfingerprint.CategoryAnalytics ||
				fp.Category == jsfingerprint.CategoryMonitoring {
				addFP(cands, "js", fp.Vendor, fp.Product, string(fp.Confidence))
			}
		}
	}
	return allPicks(cands)
}

// pickSecretsLeak surfaces every jsfingerprint match in the
// CategorySecretLeak bucket — exposed AWS/GitHub/Slack/Stripe/etc.
// tokens shipped in browser JS bundles. Each leak gets its own Pick
// so the operator can act on them individually rather than collapse
// them under one vendor.
func pickSecretsLeak(r *CompositeResult) []*Pick {
	cands := make(map[string]*candidate)
	if r.JS != nil {
		for _, fp := range r.JS.Fingerprints {
			if fp.Category == jsfingerprint.CategorySecretLeak {
				// Vendor alone is too coarse — two leaks at the same
				// vendor (e.g. two GitHub PATs in one bundle) should
				// both surface. Key by Vendor+Product instead.
				k := fp.Vendor + "\x00" + fp.Product
				c, ok := cands[k]
				if !ok {
					c = &candidate{vendor: fp.Vendor, product: fp.Product}
					cands[k] = c
				}
				c.addSource("js", string(fp.Confidence))
			}
		}
	}
	return allPicks(cands)
}

func pickDataLayer(r *CompositeResult) []*Pick {
	cands := make(map[string]*candidate)
	if r.JS != nil {
		for _, fp := range r.JS.Fingerprints {
			if fp.Category == jsfingerprint.CategoryBaaS ||
				fp.Category == jsfingerprint.CategoryCMS ||
				fp.Category == jsfingerprint.CategorySearch {
				addFP(cands, "js", fp.Vendor, fp.Product, string(fp.Confidence))
			}
		}
	}
	if r.TLS != nil {
		for _, fp := range r.TLS.Fingerprints {
			if fp.Category == tlsfingerprint.CategoryBaaS {
				addFP(cands, "tls", fp.Vendor, fp.Product, string(fp.Confidence))
			}
		}
	}
	return allPicks(cands)
}

// allPicks returns every candidate as a Pick, sorted by confidence
// descending then by vendor/product so the output is stable.
func allPicks(cands map[string]*candidate) []*Pick {
	if len(cands) == 0 {
		return nil
	}
	out := make([]*Pick, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.toPick())
	}
	// Insertion sort: small N, keeps zero deps.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			if confRank(a.Confidence) > confRank(b.Confidence) {
				break
			}
			if confRank(a.Confidence) == confRank(b.Confidence) {
				if a.Vendor < b.Vendor || (a.Vendor == b.Vendor && a.Product <= b.Product) {
					break
				}
			}
			out[j-1], out[j] = b, a
		}
	}
	return out
}
