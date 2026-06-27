package storage

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// ExtractScriptSrcs walks the HTML in r, returning every <script src="...">
// value resolved against base. Inline scripts (no src attribute) are
// skipped. Empty / data: / javascript: URIs are dropped so callers can pass
// the result straight to an HTTP probe without re-validating.
//
// The function never returns an error from the tokenizer — the html package
// recovers from malformed input by treating it as an EOF; the worst that
// can happen is we return a shorter slice than a strict parser would.
func ExtractScriptSrcs(r io.Reader, base *url.URL) []string {
	z := html.NewTokenizer(r)
	var out []string
	seen := make(map[string]struct{})
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return out
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := z.TagName()
		if string(name) != "script" || !hasAttr {
			continue
		}
		for {
			key, val, more := z.TagAttr()
			if string(key) == "src" {
				resolved := resolveScriptSrc(string(val), base)
				if resolved != "" {
					if _, ok := seen[resolved]; !ok {
						seen[resolved] = struct{}{}
						out = append(out, resolved)
					}
				}
			}
			if !more {
				break
			}
		}
	}
}

// resolveScriptSrc joins a raw src attribute with the page base URL.
// Returns "" when the resulting URL has no scheme/host we can probe over
// HTTP — this filters out data:, javascript:, blob:, and bare fragments.
func resolveScriptSrc(raw string, base *url.URL) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return ""
	}
	if u.Host == "" {
		return ""
	}
	return u.String()
}

// AnalyzePage fetches pageURL, extracts every <script src=...>, and runs the
// detector against each one in turn. The returned slice has one entry per
// script (success or error captured per item — see PageAnalyzeResult.Err).
// The page fetch itself is returned as a non-nil error only on a network
// or parse failure; partial per-script failures do not abort the crawl.
func (a *Analyzer) AnalyzePage(ctx context.Context, pageURL string) ([]PageAnalyzeResult, error) {
	parsed, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("parse page URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build page request: %w", err)
	}
	if a.userAgent != "" {
		req.Header.Set("User-Agent", a.userAgent)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch page %s: %w", pageURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	srcs := ExtractScriptSrcs(io.LimitReader(resp.Body, a.maxBodyBytes), parsed)

	out := make([]PageAnalyzeResult, 0, len(srcs))
	for _, src := range srcs {
		if err := ctx.Err(); err != nil {
			out = append(out, PageAnalyzeResult{Target: src, Err: err})
			break
		}
		res, err := a.Analyze(ctx, src)
		if err != nil {
			out = append(out, PageAnalyzeResult{Target: src, Err: err})
			continue
		}
		out = append(out, PageAnalyzeResult{Target: src, Result: res})
	}
	return out, nil
}

// PageAnalyzeResult is one row of the AnalyzePage output. Err is populated
// when the probe failed; Result is zero-valued in that case so callers can
// unconditionally read Target.
type PageAnalyzeResult struct {
	Err    error
	Target string
	Result AnalyzeResult
}
