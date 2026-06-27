package headerfingerprint

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

// DefaultPerRequestTimeout caps the single GET we issue per origin.
const DefaultPerRequestTimeout = 5 * time.Second

// Detector probes one origin per Probe() call.
type Detector struct {
	client     *http.Client
	signatures []Signature
}

// NewDetector returns a Detector. Pass nil for client to get a safe
// default (no redirects, 5s timeout); pass nil for signatures to use
// DefaultCatalog().
func NewDetector(client *http.Client, signatures []Signature) *Detector {
	if client == nil {
		client = defaultClient()
	}
	if signatures == nil {
		signatures = DefaultCatalog()
	}
	return &Detector{client: client, signatures: signatures}
}

func defaultClient() *http.Client {
	return &http.Client{
		Timeout: DefaultPerRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// Refuse redirects — origin → CDN edge → varnish chain
			// would muddle the origin's own headers.
			return http.ErrUseLastResponse
		},
	}
}

// Probe issues one GET against base, extracts response headers + the
// names of every Set-Cookie, and emits one Fingerprint per matched
// Signature. The body is drained (capped) to free the connection but
// is never inspected — header signals only.
func (d *Detector) Probe(ctx context.Context, base *url.URL) (Result, error) {
	if base == nil {
		return Result{}, errors.New("headerfingerprint: nil base url")
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return Result{}, fmt.Errorf("headerfingerprint: unsupported scheme %q", base.Scheme)
	}
	endpoint := trimURL(base)
	result := Result{Endpoint: endpoint}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return result, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "kite-collector/headerfingerprint")
	req.Header.Set("Accept", "*/*")
	resp, err := d.client.Do(req)
	if err != nil {
		return result, fmt.Errorf("do request: %w", err)
	}
	defer func() {
		// Drain at most MaxBodyBytes so the connection can be reused.
		_, _ = io.CopyN(io.Discard, resp.Body, int64(MaxBodyBytes))
		_ = resp.Body.Close()
	}()

	// Pre-extract Set-Cookie names so the matcher doesn't reparse
	// per Pattern.
	cookieNames := ExtractCookieNames(resp.Header.Values("Set-Cookie"))

	headers := canonicalHeaders(resp.Header)

	for _, sig := range d.signatures {
		fp, ok := evaluateSignature(sig, headers, cookieNames, endpoint)
		if ok {
			result.Fingerprints = append(result.Fingerprints, fp)
		}
	}
	SortFingerprints(result.Fingerprints)
	return result, nil
}

// evaluateSignature matches every Pattern of sig against headers/cookies
// and emits a Fingerprint when at least one hits.
func evaluateSignature(sig Signature, headers Headers, cookieNames []string, endpoint string) (Fingerprint, bool) {
	var evidence []string
	var best Confidence
	hit := false
	for _, p := range sig.Patterns {
		ok, ev := MatchPattern(p, headers, cookieNames)
		if !ok {
			continue
		}
		hit = true
		evidence = append(evidence, ev)
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
		Evidence:   uniqueStrings(evidence),
		Confidence: best,
	}, true
}

// canonicalHeaders adapts http.Header to the Headers interface. It is
// a tiny wrapper that also exposes Values() for multi-valued headers.
type canonicalHeaders http.Header

func (h canonicalHeaders) Get(name string) string {
	return http.Header(h).Get(name)
}

func (h canonicalHeaders) Values(name string) []string {
	return http.Header(h).Values(name)
}

// ExtractCookieNames pulls the cookie *name* (the bit before the
// first '=') from each raw Set-Cookie line. Order is preserved and
// duplicates are kept — they're cheap and the matcher already does
// case-folded comparison.
func ExtractCookieNames(setCookieValues []string) []string {
	if len(setCookieValues) == 0 {
		return nil
	}
	out := make([]string, 0, len(setCookieValues))
	for _, v := range setCookieValues {
		// "<name>=<value>; Path=/; ..." — split on first '='.
		idx := strings.IndexByte(v, '=')
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(v[:idx])
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}

func trimURL(u *url.URL) string {
	c := *u
	c.Path = ""
	c.RawQuery = ""
	c.Fragment = ""
	return strings.TrimRight(c.String(), "/")
}
