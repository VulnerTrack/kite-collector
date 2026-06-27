package apifingerprint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultPerRequestTimeout is the per-HTTP-call deadline. Probes are
// expected to be cheap; a slow endpoint is not interesting.
const DefaultPerRequestTimeout = 5 * time.Second

// Detector probes a single endpoint against a Signature catalog.
// Reusing one Detector across many endpoints is safe — the embedded
// http.Client is goroutine-safe.
type Detector struct {
	client     *http.Client
	signatures []Signature
}

// NewDetector returns a Detector with the supplied client and catalog.
// Pass nil for client to get a sensible default (no redirects, 5s
// per-request timeout, system root CAs). Pass nil for signatures to
// use DefaultCatalog().
func NewDetector(client *http.Client, signatures []Signature) *Detector {
	if client == nil {
		client = defaultClient()
	}
	if signatures == nil {
		signatures = DefaultCatalog()
	}
	return &Detector{client: client, signatures: signatures}
}

// defaultClient returns an http.Client configured for safe scanning:
// redirects are refused (we want each endpoint's own response, not a
// redirect target's), and per-request work is bounded by a deadline
// the caller cannot accidentally remove.
func defaultClient() *http.Client {
	return &http.Client{
		Timeout: DefaultPerRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// httpEntry is the memoised response triple cached per-path during a
// single Probe sweep.
type httpEntry struct {
	headers http.Header
	body    string
	status  int
}

// Probe sweeps base against every Signature in the catalog and returns
// the matching Fingerprints. base must include scheme and host; path
// is overwritten per Probe.
//
// HTTP errors per Signature are silent — a server that refuses one
// path can still be fingerprinted by another. ctx errors short-circuit
// the loop.
func (d *Detector) Probe(ctx context.Context, base *url.URL) (Result, error) {
	if base == nil {
		return Result{}, errors.New("apifingerprint: nil base url")
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return Result{}, fmt.Errorf("apifingerprint: unsupported scheme %q", base.Scheme)
	}
	result := Result{Endpoint: trimURL(base)}

	// Cache GET responses by path so signatures sharing a Path only
	// trigger one HTTP round-trip.
	pathCache := make(map[string]httpEntry)
	pathFailed := make(map[string]bool)

	fetch := func(path string) (httpEntry, bool) {
		if pathFailed[path] {
			return httpEntry{}, false
		}
		if v, ok := pathCache[path]; ok {
			return v, true
		}
		u := *base
		u.Path = path
		u.RawQuery = ""
		body, status, headers, err := d.do(ctx, u.String())
		if err != nil {
			pathFailed[path] = true
			return httpEntry{}, false
		}
		entry := httpEntry{status: status, body: body, headers: headers}
		pathCache[path] = entry
		return entry, true
	}

	for _, sig := range d.signatures {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("apifingerprint: context cancelled: %w", err)
		}
		fp, ok := d.evaluate(sig, base, fetch)
		if ok {
			result.Fingerprints = append(result.Fingerprints, fp)
		}
	}
	SortFingerprints(result.Fingerprints)
	return result, nil
}

// evaluate runs every Probe of a Signature against the path cache and
// emits a Fingerprint when at least one Probe matches.
func (d *Detector) evaluate(sig Signature, base *url.URL, fetch func(string) (httpEntry, bool)) (Fingerprint, bool) {
	var evidence []string
	hits := 0
	considered := 0
	for _, p := range sig.Probes {
		if !p.HasMatcher() {
			// Catalog bug: ignore the probe rather than crash.
			continue
		}
		considered++
		got, ok := fetch(p.Path)
		if !ok {
			continue
		}
		ok, ev := matchProbe(p, got.status, got.body, got.headers)
		if ok {
			hits++
			evidence = append(evidence, ev...)
		}
	}
	if hits == 0 {
		return Fingerprint{}, false
	}
	conf := sig.Confidence
	if hits < considered {
		conf = downgradeConfidence(conf)
	}
	endpoint := trimURL(base)
	return Fingerprint{
		Vendor:     sig.Vendor,
		Product:    sig.Product,
		Category:   sig.Category,
		Endpoint:   endpoint,
		Evidence:   uniqueStrings(evidence),
		Confidence: conf,
	}, true
}

// matchProbe evaluates one Probe against a response triple and returns
// (matched, evidence). Evidence is a list of short human-readable
// strings describing exactly what hit so an operator can diagnose
// false positives.
func matchProbe(p Probe, status int, body string, headers http.Header) (bool, []string) {
	if !statusAllowed(status, p.ExpectedStatus) {
		return false, nil
	}
	var ev []string
	matched := true
	matchedAny := false
	if p.BodyContains != "" {
		if strings.Contains(body, p.BodyContains) {
			ev = append(ev, fmt.Sprintf("body contains %q at %s", p.BodyContains, p.Path))
			matchedAny = true
		} else {
			matched = false
		}
	}
	if p.BodyRegex != nil {
		if p.BodyRegex.MatchString(body) {
			ev = append(ev, fmt.Sprintf("body matches regex at %s", p.Path))
			matchedAny = true
		} else {
			matched = false
		}
	}
	if p.HeaderName != "" {
		v := headers.Get(p.HeaderName)
		if v == "" {
			matched = false
		} else if p.HeaderRegex != nil && !p.HeaderRegex.MatchString(v) {
			matched = false
		} else {
			ev = append(ev, fmt.Sprintf("header %s=%q at %s", p.HeaderName, v, p.Path))
			matchedAny = true
		}
	}
	if !matched || !matchedAny {
		return false, nil
	}
	return true, ev
}

// statusAllowed reports whether the observed status is in the allow
// list. An empty allow list accepts any 2xx response.
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

// do issues the HTTP GET and returns (body, status, headers, err).
// The body is truncated at MaxBodyBytes; the connection is always
// drained and closed.
func (d *Detector) do(ctx context.Context, target string) (string, int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", 0, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "kite-collector/apifingerprint")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	resp, err := d.client.Do(req)
	if err != nil {
		return "", 0, nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return "", resp.StatusCode, resp.Header, fmt.Errorf("read body: %w", err)
	}
	return string(body), resp.StatusCode, resp.Header, nil
}

// trimURL returns scheme://host[:port] with no path or trailing slash —
// the canonical form used in Fingerprint.Endpoint so identical base
// URLs cluster cleanly in downstream consumers.
func trimURL(u *url.URL) string {
	c := *u
	c.Path = ""
	c.RawQuery = ""
	c.Fragment = ""
	return strings.TrimRight(c.String(), "/")
}
