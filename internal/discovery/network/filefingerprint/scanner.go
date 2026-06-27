package filefingerprint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultPerRequestTimeout caps each HTTP GET.
const DefaultPerRequestTimeout = 5 * time.Second

// DefaultMaxConcurrent is the default concurrent-fetch ceiling per
// origin. Eight overlaps RTTs without hammering a single server.
const DefaultMaxConcurrent = 8

// Scanner probes a single HTTP origin for every Probe in its catalog.
// Concurrent across catalog entries, but never across origins from a
// single Scan() call. The embedded http.Client is goroutine-safe so
// reusing one Scanner across hosts is preferred.
type Scanner struct {
	client *http.Client
	probes []Probe
	maxC   int
}

// NewScanner returns a Scanner. Pass nil for client to get safe
// defaults (no redirects, 5s timeout); pass nil for probes to use
// DefaultCatalog().
func NewScanner(client *http.Client, probes []Probe) *Scanner {
	if client == nil {
		client = defaultClient()
	}
	if probes == nil {
		probes = DefaultCatalog()
	}
	return &Scanner{client: client, probes: probes, maxC: DefaultMaxConcurrent}
}

// SetMaxConcurrent overrides the per-Scan concurrent-fetch ceiling.
func (s *Scanner) SetMaxConcurrent(n int) {
	if n <= 0 {
		n = DefaultMaxConcurrent
	}
	s.maxC = n
}

func defaultClient() *http.Client {
	return &http.Client{
		Timeout: DefaultPerRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// Refuse redirects — a 302 from /.env to /index.html
			// would otherwise mask the file-not-present case.
			return http.ErrUseLastResponse
		},
	}
}

// Scan probes base against every catalog Probe in parallel (bounded
// at maxC) and returns one Finding per matching Probe. Path-level
// fetch errors are silent; ctx cancellation aborts the sweep.
func (s *Scanner) Scan(ctx context.Context, base *url.URL) (Result, error) {
	if base == nil {
		return Result{}, errors.New("filefingerprint: nil base url")
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return Result{}, fmt.Errorf("filefingerprint: unsupported scheme %q", base.Scheme)
	}
	endpoint := trimURL(base)
	result := Result{Endpoint: endpoint}

	maxC := s.maxC
	if maxC <= 0 {
		maxC = DefaultMaxConcurrent
	}
	if maxC > len(s.probes) {
		maxC = len(s.probes)
	}

	type out struct {
		f  *Finding
		ok bool
	}
	results := make([]out, len(s.probes))
	sem := make(chan struct{}, maxC)
	var wg sync.WaitGroup

	for i, p := range s.probes {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("ctx cancelled: %w", err)
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, p Probe) {
			defer wg.Done()
			defer func() { <-sem }()
			u := *base
			u.Path = p.Path
			u.RawQuery = ""
			body, status, err := s.fetch(ctx, u.String())
			if err != nil {
				return
			}
			ok, ev := MatchProbe(p, status, body)
			if !ok {
				return
			}
			results[idx] = out{
				f: &Finding{
					Path:        p.Path,
					URL:         endpoint + p.Path,
					Description: p.Description,
					Category:    p.Category,
					Severity:    p.Severity,
					StatusCode:  status,
					Evidence:    ev,
				},
				ok: true,
			}
		}(i, p)
	}
	wg.Wait()

	for _, r := range results {
		if r.ok {
			result.Findings = append(result.Findings, *r.f)
		}
	}
	SortFindings(result.Findings)
	return result, nil
}

func (s *Scanner) fetch(ctx context.Context, target string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "kite-collector/filefingerprint")
	req.Header.Set("Accept", "*/*")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("http get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("read body: %w", err)
	}
	return string(body), resp.StatusCode, nil
}

func trimURL(u *url.URL) string {
	c := *u
	c.Path = ""
	c.RawQuery = ""
	c.Fragment = ""
	return strings.TrimRight(c.String(), "/")
}
