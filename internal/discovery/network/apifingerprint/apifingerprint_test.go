package apifingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// newDetectorAgainst spins up an httptest.Server with the supplied
// handler and returns a Detector pointed at it plus the base URL.
// All tests use this helper so we never hit the real network.
func newDetectorAgainst(t *testing.T, h http.HandlerFunc) (*Detector, *url.URL, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	base, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatalf("parse srv url: %v", err)
	}
	d := NewDetector(srv.Client(), DefaultCatalog())
	return d, base, srv.Close
}

func TestProbe_DetectsGrafana(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"commit":"abc","database":"ok","version":"10.4.0"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer stop()

	result, err := d.Probe(context.Background(), base)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if !hasProduct(result.Fingerprints, "Grafana") {
		t.Fatalf("expected Grafana fingerprint, got %+v", result.Fingerprints)
	}
	fp := getProduct(result.Fingerprints, "Grafana")
	if fp.Confidence != ConfidenceHigh {
		t.Fatalf("expected high confidence, got %s", fp.Confidence)
	}
	if fp.Category != CategoryObservability {
		t.Fatalf("expected observability category, got %s", fp.Category)
	}
}

func TestProbe_DetectsPrometheusAndGrafanaTogether(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/health":
			_, _ = w.Write([]byte(`{"database":"ok","version":"10.4.0"}`))
		case "/api/v1/status/buildinfo":
			_, _ = w.Write([]byte(`{"status":"success","data":{"version":"2.45"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer stop()

	result, err := d.Probe(context.Background(), base)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if !hasProduct(result.Fingerprints, "Grafana") || !hasProduct(result.Fingerprints, "Prometheus Server") {
		t.Fatalf("expected Grafana + Prometheus, got %+v", result.Fingerprints)
	}
}

func TestProbe_NoMatchOnPlain404Server(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer stop()

	result, err := d.Probe(context.Background(), base)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if len(result.Fingerprints) != 0 {
		t.Fatalf("expected no fingerprints from 404-only server, got %+v", result.Fingerprints)
	}
}

func TestProbe_DetectsKubernetesAPIBehindAuth(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"major":"1","minor":"29","gitVersion":"v1.29.3"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer stop()

	result, _ := d.Probe(context.Background(), base)
	if !hasProduct(result.Fingerprints, "Kubernetes API Server") {
		t.Fatalf("expected Kubernetes fingerprint despite 401, got %+v", result.Fingerprints)
	}
}

func TestProbe_DetectsHasuraWithBothProbes(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			w.Header().Set("X-Hasura-Query-Plan-Cache-Hit", "false")
			_, _ = w.Write([]byte("OK"))
		case "/v1/version":
			_, _ = w.Write([]byte(`{"version":"v2.36.0","server_type":"ce"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer stop()

	result, _ := d.Probe(context.Background(), base)
	fp := getProduct(result.Fingerprints, "Hasura GraphQL Engine")
	if fp.Vendor == "" {
		t.Fatalf("expected Hasura fingerprint, got %+v", result.Fingerprints)
	}
	if fp.Confidence != ConfidenceHigh {
		t.Fatalf("expected high confidence with both probes matching, got %s", fp.Confidence)
	}
	if fp.Category != CategoryGraphQL {
		t.Fatalf("expected GraphQL category, got %s", fp.Category)
	}
}

func TestProbe_PartialMatchDowngradesConfidence(t *testing.T) {
	// Only Hasura's /healthz probe matches; /v1/version is missing.
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Header().Set("X-Hasura-Query-Plan-Cache-Hit", "false")
			_, _ = w.Write([]byte("OK"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer stop()

	result, _ := d.Probe(context.Background(), base)
	fp := getProduct(result.Fingerprints, "Hasura GraphQL Engine")
	if fp.Vendor == "" {
		t.Fatalf("expected Hasura partial fingerprint, got %+v", result.Fingerprints)
	}
	if fp.Confidence != ConfidenceMedium {
		t.Fatalf("expected medium confidence on partial Hasura match, got %s", fp.Confidence)
	}
}

func TestProbe_DetectsGenericGraphQL(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":[{"message":"Must provide query string."}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer stop()

	result, _ := d.Probe(context.Background(), base)
	if !hasProduct(result.Fingerprints, "Generic GraphQL endpoint") {
		t.Fatalf("expected generic GraphQL detection, got %+v", result.Fingerprints)
	}
}

func TestProbe_DetectsOpenAPI(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(`{"openapi":"3.0.3","info":{"title":"x"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer stop()

	result, _ := d.Probe(context.Background(), base)
	if !hasProduct(result.Fingerprints, "OpenAPI document") {
		t.Fatalf("expected OpenAPI fingerprint, got %+v", result.Fingerprints)
	}
}

func TestProbe_HoneysJenkinsHeader(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/json" {
			w.Header().Set("X-Jenkins", "2.440.3")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer stop()

	result, _ := d.Probe(context.Background(), base)
	if !hasProduct(result.Fingerprints, "Jenkins") {
		t.Fatalf("expected Jenkins fingerprint via X-Jenkins header, got %+v", result.Fingerprints)
	}
}

func TestProbe_BodyCapPreventsRunawayResponses(t *testing.T) {
	// Server emits a huge first chunk that fails the matcher; the
	// match string only appears AFTER the cap. Cap must hold.
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			padding := strings.Repeat("x", MaxBodyBytes+100)
			_, _ = w.Write([]byte(padding + `{"database":"ok","version":"10.4.0"}`))
		}
	})
	defer stop()

	result, _ := d.Probe(context.Background(), base)
	if hasProduct(result.Fingerprints, "Grafana") {
		t.Fatalf("body cap should have prevented Grafana detection, got %+v", result.Fingerprints)
	}
}

func TestProbe_ContextCancellationStopsEarly(t *testing.T) {
	d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer stop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Probe(ctx, base); err == nil {
		t.Fatalf("expected cancellation error")
	}
}

func TestStatusAllowed(t *testing.T) {
	cases := []struct {
		got   int
		allow []int
		want  bool
	}{
		{200, nil, true},
		{204, nil, true},
		{301, nil, false},
		{401, []int{200, 401}, true},
		{500, []int{200, 401}, false},
	}
	for _, c := range cases {
		if got := statusAllowed(c.got, c.allow); got != c.want {
			t.Errorf("statusAllowed(%d, %v) = %v, want %v", c.got, c.allow, got, c.want)
		}
	}
}

func TestMatchProbe_RequiresAllConfiguredMatchers(t *testing.T) {
	// Probe wants both a body regex and a header — only the body
	// matches. Result: no match.
	p := Probe{
		Path:           "/x",
		ExpectedStatus: []int{200},
		BodyRegex:      regexp.MustCompile(`"version"`),
		HeaderName:     "X-Hasura-Query-Plan-Cache-Hit",
	}
	h := http.Header{}
	ok, _ := matchProbe(p, 200, `{"version":"1"}`, h)
	if ok {
		t.Fatalf("expected no match when header missing")
	}
}

func TestDefaultCatalog_AllProbesHaveMatchers(t *testing.T) {
	for _, sig := range DefaultCatalog() {
		for i, p := range sig.Probes {
			if !p.HasMatcher() {
				t.Errorf("%s/%s probe[%d] (%s) has no matcher — catalog bug",
					sig.Vendor, sig.Product, i, p.Path)
			}
			if p.Path == "" || p.Path[0] != '/' {
				t.Errorf("%s/%s probe[%d] path %q must start with /",
					sig.Vendor, sig.Product, i, p.Path)
			}
		}
		if sig.Vendor == "" || sig.Product == "" {
			t.Errorf("signature with empty vendor/product: %+v", sig)
		}
	}
}

func hasProduct(fps []Fingerprint, product string) bool {
	for _, f := range fps {
		if f.Product == product {
			return true
		}
	}
	return false
}

func getProduct(fps []Fingerprint, product string) Fingerprint {
	for _, f := range fps {
		if f.Product == product {
			return f
		}
	}
	return Fingerprint{}
}

// jsFrameworkCase pairs a target product with a server response that
// should trigger its Signature. The responses are minimal but
// realistic — copied from each framework's stock SSR output.
type jsFrameworkCase struct {
	product  string
	path     string
	status   int
	header   http.Header
	body     string
	category Category
}

func TestProbe_DetectsJSWebFrameworks(t *testing.T) {
	cases := []jsFrameworkCase{
		{
			product: "Next.js", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><head><script src="/_next/static/chunks/main.js"></script></head><body><script id="__NEXT_DATA__" type="application/json">{"props":{}}</script></body></html>`,
		},
		{
			product: "Nuxt", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><div id="__nuxt"></div><script>window.__NUXT__=function(){return {data:[]}}()</script></body></html>`,
		},
		{
			product: "Remix", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><div id="root"></div><script>window.__remixContext = {state:{}};window.__remixManifest = {};</script></body></html>`,
		},
		{
			product: "Astro", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><head><meta name="generator" content="Astro v4.5.0"></head><body><astro-island uid="abc"></astro-island></body></html>`,
		},
		{
			product: "SvelteKit", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body data-sveltekit-preload-data="hover"><script type="module" src="/_app/immutable/entry/start.abc.js"></script></body></html>`,
		},
		{
			product: "Gatsby", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><head><meta name="generator" content="Gatsby 5.13.1"></head><body><div id="___gatsby"></div></body></html>`,
		},
		{
			product: "Fresh", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><script id="__FRSH_STATE" type="application/json">{}</script></body></html>`,
		},
		{
			product: "Qwik", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html q:container="paused" q:base="/build/" q:version="1.5.0"><body></body></html>`,
		},
		{
			product: "Angular", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><app-root ng-version="17.3.0" _nghost-ng-c123></app-root></body></html>`,
		},
		{
			product: "Vue", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><div id="app" data-v-app><span data-v-7ba5bd90>x</span></div></body></html>`,
		},
		{
			product: "Vite (dev server)", path: "/@vite/client", status: 200, category: CategoryWebFramework,
			body: `import { ErrorOverlay } from "/@vite/...";\nif (import.meta.hot) { /* ... */ }`,
		},
		{
			product: "Express", path: "/", status: 200, category: CategoryWebFramework,
			header: http.Header{"X-Powered-By": []string{"Express"}},
			body:   `Hello, world.`,
		},
		{
			product: "hapi", path: "/", status: 200, category: CategoryWebFramework,
			header: http.Header{"Server": []string{"hapi"}},
			body:   `{}`,
		},
		{
			product: "Deno (runtime)", path: "/", status: 200, category: CategoryWebFramework,
			header: http.Header{"Server": []string{"deno/1.45.5"}},
			body:   `{}`,
		},
		{
			product: "htmx", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><button hx-get="/api/click" hx-swap="outerHTML">Go</button></body></html>`,
		},
		{
			product: "Alpine.js", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><div x-data="{open: false}" x-show="open">Hi</div></body></html>`,
		},
		{
			product: "Stimulus", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><div data-controller="hello" data-action="click->hello#greet">x</div></body></html>`,
		},
		{
			product: "Inertia.js", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><div id="app" data-page="{&quot;component&quot;:&quot;Dashboard&quot;,&quot;props&quot;:{},&quot;url&quot;:&quot;/&quot;,&quot;version&quot;:&quot;abc123&quot;}"></div></body></html>`,
		},
		{
			product: "Ember.js", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><head><meta name="my-app/config/environment" content="%7B%7D"></head><body class="ember-application"></body></html>`,
		},
		{
			product: "Quasar", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><div id="q-app"><router-view/></div><link rel="stylesheet" href="/quasar.umd.min.css"></body></html>`,
		},
		{
			product: "Marko", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body>Hi<!--M_$--><script>window.$initComponents=[]</script></body></html>`,
		},
		{
			product: "Phoenix LiveView", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><main data-phx-main="true" data-phx-session="abc" phx-static="def" phx-session="ghi"></main></body></html>`,
		},
		{
			product: "Eleventy", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><head><meta name="generator" content="Eleventy v2.0.1"></head><body></body></html>`,
		},
		{
			product: "Blazor WebAssembly", path: "/_framework/blazor.boot.json", status: 200, category: CategoryWebFramework,
			body: `{"cacheBootResources":true,"config":[],"icuDataMode":0,"mainAssemblyName":"MyApp","resources":{"assembly":{"MyApp.dll":"sha256-abc"}}}`,
		},
		{
			product: "Preact", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><div id="app"></div><script src="https://unpkg.com/preact@10/dist/preact.min.js"></script></body></html>`,
		},
		{
			product: "Stencil", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><script type="module" src="/build/p-deadbeef12.esm.js"></script></body></html>`,
		},
		{
			product: "Riot.js", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><script src="https://unpkg.com/riot@7/riot+compiler.min.js"></script><script>riot.mount('app')</script></body></html>`,
		},
		{
			product: "Storybook", path: "/iframe.html", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><head><title>Storybook</title></head><body><div id="storybook-root"></div><script>window.__STORYBOOK_PREVIEW__={}</script></body></html>`,
		},
		{
			product: "Flutter Web", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><head><meta name="flutter-web-renderer" content="canvaskit"></head><body><script src="main.dart.js"></script></body></html>`,
		},
		{
			product: "Decap CMS / Netlify CMS", path: "/admin/config.yml", status: 200, category: CategoryWebFramework,
			body: "backend:\n  name: git-gateway\ncollections:\n  - name: posts\n    label: Posts\nmedia_folder: static/img\n",
		},
		{
			product: "VitePress", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><head><meta name="generator" content="VitePress 1.3.4"></head><body><div id="VPContent"></div></body></html>`,
		},
		{
			product: "Docusaurus", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><head><meta name="generator" content="Docusaurus v3.5.2"></head><body><div id="__docusaurus"></div></body></html>`,
		},
		{
			product: "Mintlify", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><head><meta name="generator" content="Mintlify"></head><body><img src="https://cdn.mintlify.com/logo.svg"></body></html>`,
		},
		{
			product: "GitBook", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><head><meta name="generator" content="GitBook"><link rel="icon" href="https://assets.gitbook.com/favicon.ico"></head><body></body></html>`,
		},
		{
			product: "Slidev", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><head><title>My Deck - Slidev</title></head><body><div data-slidev-id="0"></div></body></html>`,
		},
		{
			product: "Capacitor", path: "/capacitor.js", status: 200, category: CategoryWebFramework,
			body: `(function(){window.Capacitor=Capacitor||{};Capacitor.Plugins={};})()`,
		},
		{
			product: "Payload CMS", path: "/api/access", status: 200, category: CategoryWebFramework,
			body: `{"canAccessAdmin":true,"collections":{"posts":{"create":true,"read":true}}}`,
		},
		{
			product: "Sanity Studio", path: "/studio/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><head><title>Sanity Studio</title><script src="/static/sanity-loader.js"></script></head><body><div id="sanity"></div></body></html>`,
		},
		{
			product: "Prismic CMS", path: "/api/v2", status: 200, category: CategoryWebFramework,
			body: `{"refs":[{"id":"master","ref":"abc123def456789012345","label":"Master","isMasterRef":true}],"types":{"page":"Page"}}`,
		},
		{
			product: "MeiliSearch", path: "/health", status: 200, category: CategorySearch,
			body: `{"status":"available"}`,
		},
		{
			product: "GraphQL endpoint (introspection-on)", path: "/graphql", status: 200, category: CategoryGraphQL,
			body: `<!DOCTYPE html><html><head><title>Apollo Sandbox</title></head><body><script src="https://embeddable-sandbox.cdn.apollographql.com/_latest/embeddable-sandbox.umd.production.min.js"></script></body></html>`,
		},
		{
			product: "Workbox (PWA Service Worker)", path: "/sw.js", status: 200, category: CategoryWebFramework,
			body: `importScripts('https://storage.googleapis.com/workbox-cdn/releases/6.5.4/workbox-sw.js');workbox.routing.registerRoute(/.*/, new workbox.strategies.NetworkFirst())`,
		},
		{
			product: "TanStack Start", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><script>window.__TSR_ROUTE_MANIFEST__={routes:[]}</script></body></html>`,
		},
		{
			product: "Million.js", path: "/", status: 200, category: CategoryWebFramework,
			body: `<!DOCTYPE html><html><body><million-block>fast</million-block><script src="https://unpkg.com/million@3/dist/million.min.js"></script></body></html>`,
		},
		{
			product: "OpenID Connect Discovery", path: "/.well-known/openid-configuration", status: 200, category: CategoryAuth,
			body: `{"issuer":"https://idp.example.com","authorization_endpoint":"https://idp.example.com/oauth/authorize","token_endpoint":"https://idp.example.com/oauth/token"}`,
		},
		{
			product: "OAuth2 Authorization Server Metadata (RFC 8414)", path: "/.well-known/oauth-authorization-server", status: 200, category: CategoryAuth,
			body: `{"issuer":"https://auth.example.com","authorization_endpoint":"https://auth.example.com/oauth/authorize","grant_types_supported":["authorization_code","refresh_token"]}`,
		},
		{
			product: "security.txt (RFC 9116)", path: "/.well-known/security.txt", status: 200, category: CategoryGeneric,
			body: "Contact: mailto:security@example.com\nExpires: 2026-12-31T23:59:59Z\nPolicy: https://example.com/security-policy\n",
		},
		{
			product: "OpenAPI 3.1 document", path: "/openapi.json", status: 200, category: CategoryRESTAPI,
			body: `{"openapi":"3.1.0","info":{"title":"My API","version":"1.0.0"},"paths":{}}`,
		},
		{
			product: "Web App Manifest (PWA)", path: "/manifest.webmanifest", status: 200, category: CategoryGeneric,
			body: `{"name":"My PWA","short_name":"PWA","start_url":"/","display":"standalone","theme_color":"#000","icons":[{"src":"/icon.png","sizes":"192x192","type":"image/png"}]}`,
		},
		{
			product: "SBOM document (CycloneDX/SPDX)", path: "/.well-known/sbom", status: 200, category: CategoryGeneric,
			body: `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"name":"openssl","version":"3.2.0"}]}`,
		},
		{
			product: "WebFinger / host-meta (RFC 7033 / 6415)", path: "/.well-known/host-meta", status: 200, category: CategoryFediverse,
			body: `<?xml version="1.0"?><XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0"><Link rel="lrdd" template="https://example.com/.well-known/webfinger?resource={uri}"/></XRD>`,
		},
		{
			product: "RFC 9728 OAuth Protected Resource Metadata", path: "/.well-known/oauth-protected-resource", status: 200, category: CategoryAuth,
			body: `{"resource":"https://api.example.com","authorization_servers":["https://auth.example.com"],"bearer_methods_supported":["header"]}`,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.product, func(t *testing.T) {
			d, base, stop := newDetectorAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				for k, vs := range tc.header {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			defer stop()

			result, err := d.Probe(context.Background(), base)
			if err != nil {
				t.Fatalf("Probe error: %v", err)
			}
			if !hasProduct(result.Fingerprints, tc.product) {
				t.Fatalf("expected %s fingerprint, got %+v", tc.product, result.Fingerprints)
			}
			fp := getProduct(result.Fingerprints, tc.product)
			if fp.Category != tc.category {
				t.Fatalf("expected category %s, got %s", tc.category, fp.Category)
			}
		})
	}
}
