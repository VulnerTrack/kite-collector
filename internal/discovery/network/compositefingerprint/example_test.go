package compositefingerprint_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"time"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/compositefingerprint"
)

// Example_orchestrator shows the canonical usage pattern: build one
// composite Scanner, call Scan against each (scheme, host, port)
// target, then walk the five per-mechanism sections.
//
// In production an orchestrator builds (scheme, host, port) tuples
// from the TCP scanner's open-port output (port 443 → https, 80 → http,
// ambiguous → try both). For inventory the composite scanner is then
// invoked once per target; results land in the operator's pipeline
// (SQLite store, OTLP emit, or a custom sink).
//
// This example uses an httptest.Server stand-in so it runs without
// touching the network.
func Example_orchestrator() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("CF-Ray", "7d0f8c5b6e3c1a2b-LAX")
		switch r.URL.Path {
		case "/api/health":
			_, _ = w.Write([]byte(`{"database":"ok","version":"10.4.0"}`))
		case "/":
			_, _ = w.Write([]byte(`<html><body><script>
createClient('https://abcdefghijklmnopqrstuvwx.supabase.co', 'k')
</script></body></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())

	scanner := compositefingerprint.NewScannerWithClient(srv.Client())
	res, err := scanner.Scan(context.Background(), "http", u.Hostname(), port,
		compositefingerprint.Options{
			// Default timeout per mechanism is 15s — override for a
			// tight scan budget.
			PerMechanismTimeout: 5 * time.Second,
		})
	if err != nil {
		fmt.Println("scan error:", err)
		return
	}

	// Header section: nginx + Cloudflare via CF-Ray.
	if res.Header != nil {
		for _, fp := range res.Header.Fingerprints {
			fmt.Printf("header: %s/%s\n", fp.Vendor, fp.Product)
		}
	}
	// API section: Grafana via /api/health.
	if res.API != nil {
		for _, fp := range res.API.Fingerprints {
			fmt.Printf("api: %s/%s\n", fp.Vendor, fp.Product)
		}
	}
	// JS section: Supabase project bound to this page.
	if res.JS != nil {
		for _, fp := range res.JS.Fingerprints {
			fmt.Printf("js: %s/%s project=%s\n", fp.Vendor, fp.Product, fp.ProjectID)
		}
	}
	// File section is silent because no leaks are exposed.
	// TLS section is nil because scheme=http.
	// Any per-mechanism failures land in res.Errors.

	fmt.Println("total:", res.TotalFingerprints(), "errors:", len(res.Errors))
}
