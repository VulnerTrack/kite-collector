package apifingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// stripScheme returns "host:port" from a base URL string.
func stripScheme(t *testing.T, base string) (string, int) {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	host := u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return host, port
}

func TestTargetURL(t *testing.T) {
	cases := []struct {
		target  Target
		want    string
		wantErr bool
	}{
		{Target{Host: "1.2.3.4", Port: 443, Scheme: "https"}, "https://1.2.3.4:443", false},
		{Target{Host: "host", Port: 80}, "http://host:80", false}, // default scheme
		{Target{Host: "", Port: 80}, "", true},
		{Target{Host: "x", Port: 0}, "", true},
		{Target{Host: "x", Port: 70000}, "", true},
		{Target{Host: "x", Port: 80, Scheme: "ftp"}, "", true},
	}
	for _, c := range cases {
		u, err := c.target.URL()
		if c.wantErr {
			if err == nil {
				t.Errorf("Target%+v: want error, got nil", c.target)
			}
			continue
		}
		if err != nil {
			t.Errorf("Target%+v: unexpected error %v", c.target, err)
			continue
		}
		if u.String() != c.want {
			t.Errorf("Target%+v: got %q want %q", c.target, u.String(), c.want)
		}
	}
}

func TestGuessSchemes(t *testing.T) {
	cases := []struct {
		port int
		want []string
	}{
		{443, []string{"https"}},
		{8443, []string{"https"}},
		{80, []string{"http"}},
		{8080, []string{"http"}},
		{9090, []string{"http"}},
		{8123, []string{"http", "https"}}, // unknown port
		{9092, []string{"http", "https"}}, // Kafka — typically not HTTP at all but be lenient
	}
	for _, c := range cases {
		got := GuessSchemes(c.port)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("GuessSchemes(%d): got %v want %v", c.port, got, c.want)
		}
	}
}

func TestTargetsFromHostPorts(t *testing.T) {
	got := TargetsFromHostPorts("h", []int{80, 443, 8123})
	want := []Target{
		{Host: "h", Port: 80, Scheme: "http"},
		{Host: "h", Port: 443, Scheme: "https"},
		{Host: "h", Port: 8123, Scheme: "http"},
		{Host: "h", Port: 8123, Scheme: "https"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if TargetsFromHostPorts("", []int{80}) != nil {
		t.Fatalf("empty host should return nil")
	}
	if TargetsFromHostPorts("h", nil) != nil {
		t.Fatalf("empty ports should return nil")
	}
}

func TestScanTargets_SingleHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			_, _ = w.Write([]byte(`{"database":"ok","version":"10.4.0"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	host, port := stripScheme(t, srv.URL)
	d := NewDetector(srv.Client(), DefaultCatalog())

	results, err := ScanTargets(context.Background(), d,
		[]Target{{Host: host, Port: port, Scheme: "http"}},
		ScanOptions{})
	if err != nil {
		t.Fatalf("ScanTargets error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !hasProduct(results[0].Fingerprints, "Grafana") {
		t.Fatalf("expected Grafana, got %+v", results[0].Fingerprints)
	}
}

func TestScanTargets_MultiHostOrdering(t *testing.T) {
	// Three servers, all the same content; results must come back sorted
	// by endpoint string regardless of completion order.
	makeSrv := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/health" {
				_, _ = w.Write([]byte(`{"database":"ok","version":"10.4.0"}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
	}
	s1, s2, s3 := makeSrv(), makeSrv(), makeSrv()
	defer s1.Close()
	defer s2.Close()
	defer s3.Close()
	d := NewDetector(s1.Client(), DefaultCatalog())

	var targets []Target
	for _, srv := range []*httptest.Server{s1, s2, s3} {
		host, port := stripScheme(t, srv.URL)
		targets = append(targets, Target{Host: host, Port: port, Scheme: "http"})
	}

	results, err := ScanTargets(context.Background(), d, targets, ScanOptions{MaxConcurrent: 3})
	if err != nil {
		t.Fatalf("ScanTargets error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	// Verify sorted by endpoint.
	for i := 1; i < len(results); i++ {
		if results[i-1].Endpoint >= results[i].Endpoint {
			t.Fatalf("results out of order: %s vs %s", results[i-1].Endpoint, results[i].Endpoint)
		}
	}
}

func TestScanTargets_BoundsConcurrency(t *testing.T) {
	// Server blocks briefly; with MaxConcurrent=1, observed peak
	// in-flight must be 1. Uses a single-Signature catalog so each
	// Target only issues one HTTP round-trip — keeps the test under
	// a second instead of fanning out across the full catalog.
	var inFlight int32
	var maxInFlight int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt32(&inFlight, 1)
		defer atomic.AddInt32(&inFlight, -1)
		for {
			peak := atomic.LoadInt32(&maxInFlight)
			if cur <= peak || atomic.CompareAndSwapInt32(&maxInFlight, peak, cur) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	host, port := stripScheme(t, srv.URL)
	// Single-signature catalog so each Target = one HTTP call.
	d := NewDetector(srv.Client(), []Signature{{
		Vendor: "Test", Product: "Test", Category: CategoryGeneric, Confidence: ConfidenceLow,
		Probes: []Probe{{Path: "/", ExpectedStatus: []int{200}, BodyContains: "x"}},
	}})

	var targets []Target
	for i := 0; i < 4; i++ {
		targets = append(targets, Target{Host: host, Port: port, Scheme: "http"})
	}

	_, err := ScanTargets(context.Background(), d, targets, ScanOptions{MaxConcurrent: 1})
	if err != nil {
		t.Fatalf("ScanTargets error: %v", err)
	}
	if maxInFlight > 1 {
		t.Fatalf("MaxConcurrent=1 violated; saw %d in-flight", maxInFlight)
	}
}

func TestScanTargets_NilDetectorErrors(t *testing.T) {
	_, err := ScanTargets(context.Background(), nil, []Target{{Host: "x", Port: 80}}, ScanOptions{})
	if err == nil {
		t.Fatalf("expected error on nil detector")
	}
}

func TestScanTargets_EmptyTargetsReturnsNil(t *testing.T) {
	results, err := ScanTargets(context.Background(), NewDetector(nil, nil), nil, ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Fatalf("expected nil results, got %+v", results)
	}
}

func TestScanTargets_InvalidTargetSurfacesError(t *testing.T) {
	d := NewDetector(nil, nil)
	_, err := ScanTargets(context.Background(), d,
		[]Target{{Host: "x", Port: 0}}, ScanOptions{})
	if err == nil {
		t.Fatalf("expected error from invalid target")
	}
}
