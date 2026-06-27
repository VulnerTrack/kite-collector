package compositefingerprint

import (
	"testing"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/apifingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/headerfingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/jsfingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/tlsfingerprint"
)

// fixture builds a CompositeResult shaped like a real Vercel-hosted
// Next.js app: TLS shows Vercel SAN, header shows Vercel + Next.js +
// nginx, api detects Next.js framework, js detects NextAuth + GA4 +
// Supabase BaaS.
func fixtureVercelNextAuthSupabase() *CompositeResult {
	return &CompositeResult{
		Endpoint: "https://myapp.vercel.app:443",
		TLS: &tlsfingerprint.Result{
			Fingerprints: []tlsfingerprint.Fingerprint{
				{Vendor: "Vercel", Product: "Vercel",
					Category: tlsfingerprint.CategoryHosting, Confidence: tlsfingerprint.ConfidenceHigh},
			},
		},
		Header: &headerfingerprint.Result{
			Fingerprints: []headerfingerprint.Fingerprint{
				{Vendor: "Vercel", Product: "Vercel-hosted",
					Category: headerfingerprint.CategoryEdgeHosting, Confidence: headerfingerprint.ConfidenceHigh},
				{Vendor: "Vercel", Product: "Next.js (X-Powered-By)",
					Category: headerfingerprint.CategoryFramework, Confidence: headerfingerprint.ConfidenceHigh},
				{Vendor: "F5 NGINX", Product: "nginx",
					Category: headerfingerprint.CategoryWebServer, Confidence: headerfingerprint.ConfidenceHigh},
				{Vendor: "NextAuth.js", Product: "Auth.js / NextAuth (session)",
					Category: headerfingerprint.CategorySessionTrack, Confidence: headerfingerprint.ConfidenceHigh},
			},
		},
		API: &apifingerprint.Result{
			Fingerprints: []apifingerprint.Fingerprint{
				{Vendor: "Vercel", Product: "Next.js",
					Category: apifingerprint.CategoryWebFramework, Confidence: apifingerprint.ConfidenceHigh},
			},
		},
		JS: &jsfingerprint.Result{
			Fingerprints: []jsfingerprint.Fingerprint{
				{Vendor: "NextAuth.js", Product: "Auth.js / NextAuth",
					Category: jsfingerprint.CategoryAuth, Confidence: jsfingerprint.ConfidenceHigh},
				{Vendor: "Google", Product: "Google Analytics 4",
					Category: jsfingerprint.CategoryAnalytics, Confidence: jsfingerprint.ConfidenceHigh},
				{Vendor: "Vercel", Product: "Vercel Web Analytics",
					Category: jsfingerprint.CategoryAnalytics, Confidence: jsfingerprint.ConfidenceHigh},
				{Vendor: "Supabase", Product: "Supabase",
					Category: jsfingerprint.CategoryBaaS, Confidence: jsfingerprint.ConfidenceHigh},
			},
		},
	}
}

func TestSummarise_VercelNextAuthSupabaseStack(t *testing.T) {
	r := fixtureVercelNextAuthSupabase()
	s := r.Summarise()

	if s.Endpoint != r.Endpoint {
		t.Fatalf("endpoint: got %q want %q", s.Endpoint, r.Endpoint)
	}
	if s.Hosting == nil || s.Hosting.Vendor != "Vercel" {
		t.Fatalf("expected Vercel hosting, got %+v", s.Hosting)
	}
	// Hosting should reflect both TLS and Header sources.
	if !containsSource(s.Hosting.Sources, "tls") || !containsSource(s.Hosting.Sources, "header") {
		t.Errorf("expected hosting sources=[tls,header], got %v", s.Hosting.Sources)
	}
	if s.WebServer == nil || s.WebServer.Product != "nginx" {
		t.Fatalf("expected nginx web server, got %+v", s.WebServer)
	}
	if s.Framework == nil || s.Framework.Product != "Next.js" {
		t.Fatalf("expected Next.js framework, got %+v", s.Framework)
	}
	// Framework should appear in both api and header (different products
	// — "Next.js" vs "Next.js (X-Powered-By)" — so each is a distinct
	// candidate). The picker chooses one; check the surface comes from
	// the higher-priority API source.
	if !containsSource(s.Framework.Sources, "api") {
		t.Errorf("expected framework sources to include 'api', got %v", s.Framework.Sources)
	}
	if len(s.Auth) == 0 || s.Auth[0].Vendor != "NextAuth.js" {
		t.Fatalf("expected NextAuth in auth picks, got %+v", s.Auth)
	}
	// Analytics should list both GA4 and Vercel Web Analytics.
	if len(s.Analytics) < 2 {
		t.Fatalf("expected ≥2 analytics picks, got %+v", s.Analytics)
	}
	if len(s.DataLayer) == 0 || s.DataLayer[0].Vendor != "Supabase" {
		t.Fatalf("expected Supabase in data layer, got %+v", s.DataLayer)
	}
}

func TestSummarise_EmptyResultProducesEmptySummary(t *testing.T) {
	r := &CompositeResult{Endpoint: "https://nothing:443"}
	s := r.Summarise()
	if s.Endpoint != r.Endpoint {
		t.Fatalf("endpoint mismatch")
	}
	if s.Hosting != nil || s.WebServer != nil || s.Framework != nil {
		t.Fatalf("expected nil layer picks, got hosting=%+v webserver=%+v framework=%+v",
			s.Hosting, s.WebServer, s.Framework)
	}
}

func TestSummarise_SecretsLeakSurfacesEveryFinding(t *testing.T) {
	// Multiple distinct secret leaks (different vendor/product pairs)
	// should produce multiple Pick entries — operators need to act on
	// each one individually rather than have them collapse.
	r := &CompositeResult{
		Endpoint: "https://leaky:443",
		JS: &jsfingerprint.Result{
			Fingerprints: []jsfingerprint.Fingerprint{
				{Vendor: "Amazon (exposed)", Product: "AWS Access Key ID",
					Category: jsfingerprint.CategorySecretLeak, Confidence: jsfingerprint.ConfidenceHigh},
				{Vendor: "GitHub (exposed)", Product: "GitHub Personal Access Token",
					Category: jsfingerprint.CategorySecretLeak, Confidence: jsfingerprint.ConfidenceHigh},
				{Vendor: "Slack (exposed)", Product: "Slack incoming webhook URL",
					Category: jsfingerprint.CategorySecretLeak, Confidence: jsfingerprint.ConfidenceHigh},
				// Two of the same vendor (e.g. two GitHub PATs) must
				// not collapse — Vendor+Product key keeps them split.
				{Vendor: "GitHub (exposed)", Product: "GitHub fine-grained PAT",
					Category: jsfingerprint.CategorySecretLeak, Confidence: jsfingerprint.ConfidenceHigh},
			},
		},
	}
	s := r.Summarise()
	if len(s.SecretsLeak) != 4 {
		t.Fatalf("expected 4 SecretsLeak picks, got %d: %+v", len(s.SecretsLeak), s.SecretsLeak)
	}
	products := map[string]bool{}
	for _, p := range s.SecretsLeak {
		products[p.Product] = true
	}
	for _, want := range []string{"AWS Access Key ID", "GitHub Personal Access Token", "Slack incoming webhook URL", "GitHub fine-grained PAT"} {
		if !products[want] {
			t.Errorf("expected %q in SecretsLeak picks", want)
		}
	}
}

func TestSummarise_PicksHigherConfidenceCandidate(t *testing.T) {
	r := &CompositeResult{
		Endpoint: "https://x:443",
		Header: &headerfingerprint.Result{
			Fingerprints: []headerfingerprint.Fingerprint{
				{Vendor: "Apache Software Foundation", Product: "Apache httpd",
					Category: headerfingerprint.CategoryWebServer, Confidence: headerfingerprint.ConfidenceLow},
				{Vendor: "F5 NGINX", Product: "nginx",
					Category: headerfingerprint.CategoryWebServer, Confidence: headerfingerprint.ConfidenceHigh},
			},
		},
	}
	s := r.Summarise()
	if s.WebServer == nil || s.WebServer.Product != "nginx" {
		t.Fatalf("expected nginx (high) to win, got %+v", s.WebServer)
	}
}

func containsSource(srcs []string, s string) bool {
	for _, v := range srcs {
		if v == s {
			return true
		}
	}
	return false
}

func TestFilterByConfidence_DropsBelowThreshold(t *testing.T) {
	r := fixtureVercelNextAuthSupabaseWithNoise()
	filtered := r.FilterByConfidence("medium")

	// Original must be untouched.
	if len(r.JS.Fingerprints) == len(filtered.JS.Fingerprints) {
		// If filtering kept everything we filtered nothing — verify
		// fixture actually had low-confidence entries to drop.
		t.Fatalf("fixture had no low-confidence entries — test invariant broken")
	}
	for _, fp := range filtered.JS.Fingerprints {
		if confRank(string(fp.Confidence)) < confRank("medium") {
			t.Errorf("filtered JS section kept low-confidence %s/%s", fp.Vendor, fp.Product)
		}
	}
	for _, fp := range filtered.Header.Fingerprints {
		if confRank(string(fp.Confidence)) < confRank("medium") {
			t.Errorf("filtered Header section kept low-confidence %s/%s", fp.Vendor, fp.Product)
		}
	}
}

func TestFilterByConfidence_EmptyMinPassthrough(t *testing.T) {
	r := fixtureVercelNextAuthSupabaseWithNoise()
	filtered := r.FilterByConfidence("")
	if len(filtered.JS.Fingerprints) != len(r.JS.Fingerprints) {
		t.Errorf("empty min should be passthrough, dropped %d entries",
			len(r.JS.Fingerprints)-len(filtered.JS.Fingerprints))
	}
}

func TestFilterByConfidence_NilSafe(t *testing.T) {
	var r *CompositeResult
	out := r.FilterByConfidence("high")
	if out.TotalFingerprints() != 0 {
		t.Errorf("nil receiver should yield empty result")
	}
}

func TestFilterByVendor_SubstringCaseInsensitive(t *testing.T) {
	r := fixtureVercelNextAuthSupabase()
	filtered := r.FilterByVendor("vercel")
	// Each section should keep only Vercel-vendored fingerprints.
	for _, fp := range filtered.TLS.Fingerprints {
		if fp.Vendor != "Vercel" {
			t.Errorf("TLS section kept non-Vercel %q", fp.Vendor)
		}
	}
	for _, fp := range filtered.Header.Fingerprints {
		if fp.Vendor != "Vercel" {
			t.Errorf("Header section kept non-Vercel %q", fp.Vendor)
		}
	}
	// JS section's NextAuth/GA4/Supabase should all be dropped.
	if len(filtered.JS.Fingerprints) > 1 {
		t.Errorf("expected ≤1 JS fp (Vercel Web Analytics), got %d", len(filtered.JS.Fingerprints))
	}
}

func TestFilterByVendor_EmptyPassthrough(t *testing.T) {
	r := fixtureVercelNextAuthSupabase()
	filtered := r.FilterByVendor("")
	if filtered.TotalFingerprints() != r.TotalFingerprints() {
		t.Errorf("empty vendor filter dropped entries: was %d, now %d",
			r.TotalFingerprints(), filtered.TotalFingerprints())
	}
}

func TestFilterByCategory_KeepsListed(t *testing.T) {
	r := fixtureVercelNextAuthSupabase()
	filtered := r.FilterByCategory([]string{"auth", "session-tracking"})
	// JS section had Auth (NextAuth) and BaaS (Supabase); only auth should remain.
	for _, fp := range filtered.JS.Fingerprints {
		if string(fp.Category) != "auth" {
			t.Errorf("JS section kept non-auth category %q", fp.Category)
		}
	}
	// Header had session-tracking (NextAuth) — should remain.
	hasSession := false
	for _, fp := range filtered.Header.Fingerprints {
		if string(fp.Category) == "session-tracking" {
			hasSession = true
		}
	}
	if !hasSession {
		t.Errorf("expected session-tracking entry kept in Header")
	}
}

func TestFilterByCategory_EmptyPassthrough(t *testing.T) {
	r := fixtureVercelNextAuthSupabase()
	filtered := r.FilterByCategory(nil)
	if filtered.TotalFingerprints() != r.TotalFingerprints() {
		t.Errorf("empty category filter dropped entries")
	}
}

// fixtureVercelNextAuthSupabaseWithNoise extends the base fixture with
// a few low-confidence entries so the filter has something to drop.
func fixtureVercelNextAuthSupabaseWithNoise() *CompositeResult {
	r := fixtureVercelNextAuthSupabase()
	r.JS.Fingerprints = append(r.JS.Fingerprints, jsfingerprint.Fingerprint{
		Vendor: "Noisy", Product: "Maybe-X",
		Category: jsfingerprint.CategoryGeneric,
		Confidence: jsfingerprint.ConfidenceLow,
	})
	r.Header.Fingerprints = append(r.Header.Fingerprints, headerfingerprint.Fingerprint{
		Vendor: "GenericSig", Product: "Could-be-anything",
		Category: headerfingerprint.CategoryGeneric,
		Confidence: headerfingerprint.ConfidenceLow,
	})
	return r
}
