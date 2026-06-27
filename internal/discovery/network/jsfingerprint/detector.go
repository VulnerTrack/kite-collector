package jsfingerprint

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

// DefaultPerRequestTimeout is the per-HTTP-call deadline. Page +
// linked-script fetches all share this budget.
const DefaultPerRequestTimeout = 8 * time.Second

// Detector scans one page URL at a time. Concurrent calls share the
// embedded http.Client (which is goroutine-safe), so reusing one
// Detector across hosts is preferred.
type Detector struct {
	client     *http.Client
	signatures []Signature
}

// NewDetector returns a Detector wired with the supplied client and
// catalog. Pass nil for client to get a safe default (no redirects,
// 8s timeout); pass nil for signatures to use DefaultCatalog().
func NewDetector(client *http.Client, signatures []Signature) *Detector {
	if client == nil {
		client = defaultClient()
	}
	if signatures == nil {
		signatures = DefaultCatalog()
	}
	return &Detector{client: client, signatures: signatures}
}

// defaultClient returns an http.Client configured for safe scanning.
// Redirects are refused — we want the page's own response, not the
// upstream — and per-request work is bounded by a deadline.
func defaultClient() *http.Client {
	return &http.Client{
		Timeout: DefaultPerRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Scan fetches pageURL, extracts <script src> targets, fetches the
// same-origin subset (bounded by MaxLinkedScripts), and matches every
// catalog Signature against the concatenated body. Cross-origin
// scripts (Stripe.js, Algolia, etc.) are kept as evidence in the
// linked-URL list but not fetched — their presence is already a
// strong fingerprint via the script-src pattern, and following them
// would expand the request surface beyond the scanned origin.
func (d *Detector) Scan(ctx context.Context, pageURL *url.URL) (Result, error) {
	if pageURL == nil {
		return Result{}, errors.New("jsfingerprint: nil page url")
	}
	if pageURL.Scheme != "http" && pageURL.Scheme != "https" {
		return Result{}, fmt.Errorf("jsfingerprint: unsupported scheme %q", pageURL.Scheme)
	}
	result := Result{Endpoint: trimURL(pageURL)}

	pageBody, _, _, err := d.fetch(ctx, pageURL.String())
	if err != nil {
		return result, fmt.Errorf("fetch page: %w", err)
	}

	// Build the corpus we run patterns against: the page body plus the
	// scriptSrcRegex-extracted URLs (so script-src patterns hit) plus
	// the bodies of every same-origin script we follow.
	corpus := new(strings.Builder)
	corpus.WriteString(pageBody)

	scripts := ExtractScriptSrcs(pageBody)
	corpus.WriteString("\n")
	for _, s := range scripts {
		// Surface every script URL verbatim into the corpus so
		// script-src patterns can match host/path without us having
		// to fetch the script body.
		corpus.WriteString(s)
		corpus.WriteString("\n")
	}

	sameOriginScripts := filterSameOrigin(pageURL, scripts)
	if len(sameOriginScripts) > MaxLinkedScripts {
		sameOriginScripts = sameOriginScripts[:MaxLinkedScripts]
	}

	for _, raw := range sameOriginScripts {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("ctx cancelled mid-scan: %w", err)
		}
		abs, err := resolveURL(pageURL, raw)
		if err != nil {
			continue
		}
		body, _, _, ferr := d.fetch(ctx, abs)
		if ferr != nil {
			continue
		}
		corpus.WriteString("\n")
		corpus.WriteString(body)
	}

	body := corpus.String()
	endpoint := trimURL(pageURL)

	for _, sig := range d.signatures {
		fp, ok := matchSignature(sig, body, endpoint)
		if ok {
			result.Fingerprints = append(result.Fingerprints, fp)
		}
	}
	SortFingerprints(result.Fingerprints)
	return result, nil
}

// matchSignature applies every Pattern in sig to body and emits one
// Fingerprint per signature. Evidence is the union of every matched
// Pattern's evidence string; ProjectID is the first non-empty capture.
func matchSignature(sig Signature, body, endpoint string) (Fingerprint, bool) {
	var evidence []string
	var projectID string
	var best Confidence
	hit := false
	for _, p := range sig.Patterns {
		matched, ev, id := MatchPattern(p, body)
		if !matched {
			continue
		}
		hit = true
		evidence = append(evidence, ev)
		if projectID == "" && id != "" {
			projectID = id
		}
		best = stronger(best, p.Confidence)
	}
	if !hit {
		return Fingerprint{}, false
	}
	return Fingerprint{
		Vendor:     sig.Vendor,
		Product:    sig.Product,
		Category:   sig.Category,
		Endpoint:   endpoint,
		ProjectID:  projectID,
		Evidence:   uniqueStrings(evidence),
		Confidence: best,
	}, true
}

// fetch issues an HTTP GET with a browser-ish Accept header (it asks
// for HTML and JS but identifies as the scanner so server logs are
// honest). Body is truncated at MaxBodyBytes.
func (d *Detector) fetch(ctx context.Context, target string) (string, int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", 0, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "kite-collector/jsfingerprint")
	req.Header.Set("Accept", "text/html,application/javascript,application/json,*/*;q=0.1")
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

// resolveURL turns a script-src reference into an absolute URL,
// resolving against the page URL for relative or protocol-relative
// forms. Returns an error if the result isn't HTTP(S).
func resolveURL(pageURL *url.URL, ref string) (string, error) {
	if strings.HasPrefix(ref, "//") {
		return pageURL.Scheme + ":" + ref, nil
	}
	u, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	abs := pageURL.ResolveReference(u)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return "", fmt.Errorf("non-http scheme %q", abs.Scheme)
	}
	return abs.String(), nil
}

// filterSameOrigin returns the subset of refs that resolve to the same
// host as pageURL — used to bound which scripts we follow.
func filterSameOrigin(pageURL *url.URL, refs []string) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		abs, err := resolveURL(pageURL, ref)
		if err != nil {
			continue
		}
		u, err := url.Parse(abs)
		if err != nil {
			continue
		}
		if u.Host == pageURL.Host {
			out = append(out, ref)
		}
	}
	return out
}

// trimURL returns scheme://host[:port] with no path. Used as the
// canonical Endpoint field on every emitted Fingerprint so multiple
// hits on the same origin cluster cleanly downstream.
func trimURL(u *url.URL) string {
	c := *u
	c.Path = ""
	c.RawQuery = ""
	c.Fragment = ""
	return strings.TrimRight(c.String(), "/")
}
