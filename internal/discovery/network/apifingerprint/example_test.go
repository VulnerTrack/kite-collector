package apifingerprint_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/apifingerprint"
)

// Example_orchestrator shows how an orchestrator (or a `kite-collector
// fingerprint-apis` CLI command) wires the TCP scanner's output into
// apifingerprint without either side knowing about the other.
//
// The bridge is deliberately tiny — three lines — so the apifingerprint
// package stays dependency-free from the network/scanner.go side, and
// the scanner stays unaware of HTTP fingerprinting. Tests exercise both
// pieces independently and the orchestrator wires them at the seam.
func Example_orchestrator() {
	// Stand-in for a real TCP-scan result. In production this comes from
	// `network.Scanner.Discover`'s persisted OpenPort rows, grouped by IP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			_, _ = w.Write([]byte(`{"database":"ok","version":"10.4.0"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())

	// One detector reused across all hosts; safe for concurrent use.
	detector := apifingerprint.NewDetector(srv.Client(), apifingerprint.DefaultCatalog())

	// Build Targets from (host, [port]) — GuessSchemes picks http/https
	// per port based on the well-known TLS/cleartext convention.
	targets := apifingerprint.TargetsFromHostPorts(host, []int{port})

	// Fan out, bounded at 4 concurrent endpoints by default.
	results, err := apifingerprint.ScanTargets(context.Background(), detector,
		targets, apifingerprint.ScanOptions{MaxConcurrent: 4})
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	for _, r := range results {
		for _, fp := range r.Fingerprints {
			// In production: persist to SQLite, emit OTLP, surface to dashboard.
			fmt.Printf("%s = %s/%s (%s)\n",
				r.Endpoint, fp.Vendor, fp.Product, fp.Confidence)
		}
	}
	// One Grafana fingerprint at high confidence is the only output.
}
