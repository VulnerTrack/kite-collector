package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}

func TestExtractScriptSrcs_ResolvesAndDedupes(t *testing.T) {
	body := `
		<!doctype html>
		<html>
		<head>
			<script src='/static/app.min.js'></script>
			<script src="https://cdn.example.net/aws-sdk.min.js"></script>
			<script src="//cdn.other.com/lib.js" defer></script>
			<script>console.log("inline; should be skipped")</script>
			<script src="data:text/javascript,foo"></script>
			<script src="javascript:void(0)"></script>
			<script src=""></script>
			<script src="/static/app.min.js"></script>  <!-- dup -->
		</head>
		</html>`

	base := mustParseURL(t, "https://app.example.com/path/")
	srcs := ExtractScriptSrcs(strings.NewReader(body), base)

	want := []string{
		"https://app.example.com/static/app.min.js",
		"https://cdn.example.net/aws-sdk.min.js",
		"https://cdn.other.com/lib.js",
	}
	if len(srcs) != len(want) {
		t.Fatalf("expected %d srcs, got %d: %v", len(want), len(srcs), srcs)
	}
	for i, w := range want {
		if srcs[i] != w {
			t.Errorf("srcs[%d]=%q want %q", i, srcs[i], w)
		}
	}
}

func TestExtractScriptSrcs_NoBase_DropsRelatives(t *testing.T) {
	// Without a base URL, relative paths cannot be probed. They should be
	// silently dropped rather than producing scheme-less garbage.
	body := `<script src="/static/app.js"></script><script src="https://x.example/abs.js"></script>`
	srcs := ExtractScriptSrcs(strings.NewReader(body), nil)
	if len(srcs) != 1 || srcs[0] != "https://x.example/abs.js" {
		t.Fatalf("expected only the absolute URL, got %v", srcs)
	}
}

func TestAnalyzePage_FansOutToScripts(t *testing.T) {
	// Mux: one HTML page that references two JS bundles served by the
	// same test server. The page is served at /index.html.
	mux := http.NewServeMux()
	mux.HandleFunc("/index.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`
			<html><head>
				<script src="/static/app.js"></script>
				<script src="/static/vendor.js"></script>
			</head></html>`))
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`import { S3Client } from "@aws-sdk/client-s3";`))
	})
	mux.HandleFunc("/static/vendor.js", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`import { createClient } from "@supabase/supabase-js";`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	a := NewAnalyzer(AnalyzerOptions{HTTPClient: srv.Client(), Timeout: 2 * time.Second})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	results, err := a.AnalyzePage(ctx, srv.URL+"/index.html")
	if err != nil {
		t.Fatalf("AnalyzePage: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 fan-out results, got %d", len(results))
	}

	// Collect detected providers across both scripts.
	seen := map[Provider]bool{}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("unexpected per-script error for %s: %v", r.Target, r.Err)
			continue
		}
		for _, m := range r.Result.Matches {
			if m.Signal == SignalFile {
				seen[m.Provider] = true
			}
		}
	}
	if !seen[ProviderAWSS3] {
		t.Errorf("AnalyzePage did not surface AWS S3 from /static/app.js: %+v", results)
	}
	if !seen[ProviderSupabaseStorage] {
		t.Errorf("AnalyzePage did not surface Supabase from /static/vendor.js: %+v", results)
	}
}

func TestAnalyzePage_PerScriptErrorDoesNotAbort(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/index.html", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`
			<script src="/static/good.js"></script>
			<script src="http://127.0.0.1:1/unreachable.js"></script>`))
	})
	mux.HandleFunc("/static/good.js", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`@aws-sdk/client-s3`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	a := NewAnalyzer(AnalyzerOptions{HTTPClient: srv.Client(), Timeout: 500 * time.Millisecond})

	results, err := a.AnalyzePage(context.Background(), srv.URL+"/index.html")
	if err != nil {
		t.Fatalf("AnalyzePage should not return error on partial failure: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	var goodCount, errCount int
	for _, r := range results {
		if r.Err != nil {
			errCount++
		} else {
			goodCount++
		}
	}
	if goodCount != 1 || errCount != 1 {
		t.Errorf("expected exactly 1 good + 1 error result, got good=%d err=%d", goodCount, errCount)
	}
}

func TestAnalyzePage_BadPageURL(t *testing.T) {
	a := NewAnalyzer(AnalyzerOptions{Timeout: 100 * time.Millisecond})
	_, err := a.AnalyzePage(context.Background(), "http://127.0.0.1:1/missing")
	if err == nil {
		t.Fatalf("expected error for unreachable page URL")
	}
}
