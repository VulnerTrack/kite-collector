package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stubServer spins up an httptest server that mimics an S3-style API: the
// handler echoes a response header (e.g. X-Amz-Request-Id) and a JS-looking
// body so the Analyzer pipeline exercises file + API signal paths together.
func stubServer(t *testing.T, headerName, headerVal, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/asset.js", func(w http.ResponseWriter, r *http.Request) {
		if headerName != "" {
			w.Header().Set(headerName, headerVal)
		}
		_, _ = w.Write([]byte(body))
	})
	return httptest.NewServer(mux)
}

func TestAnalyzer_HitsAPIAndFileSignals(t *testing.T) {
	srv := stubServer(
		t,
		"X-Amz-Request-Id", "test-abc",
		`(function(){ import { S3Client } from "@aws-sdk/client-s3"; })();`,
	)
	defer srv.Close()

	a := NewAnalyzer(AnalyzerOptions{HTTPClient: srv.Client(), Timeout: 2 * time.Second})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := a.Analyze(ctx, srv.URL+"/asset.js")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	if !hasMatch(res.Matches, ProviderAWSS3, SignalAPI) {
		t.Errorf("expected AWS API match from X-Amz-Request-Id header, got %+v", res.Matches)
	}
	if !hasMatch(res.Matches, ProviderAWSS3, SignalFile) {
		t.Errorf("expected AWS file match from JS body, got %+v", res.Matches)
	}
}

func TestAnalyzer_BodyTruncation(t *testing.T) {
	// 256 KiB of harmless data followed by an aws-sdk reference at the
	// very end. With MaxBodyBytes=1024 the analyser should not see the
	// trailing marker.
	tail := `@aws-sdk/client-s3`
	body := strings.Repeat("x", 256*1024) + tail
	srv := stubServer(t, "", "", body)
	defer srv.Close()

	a := NewAnalyzer(AnalyzerOptions{
		HTTPClient:   srv.Client(),
		MaxBodyBytes: 1024,
		Timeout:      2 * time.Second,
	})

	res, err := a.Analyze(context.Background(), srv.URL+"/asset.js")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if strings.Contains(res.Evidence.JS, tail) {
		t.Fatalf("expected body to be truncated below trailing marker, got len=%d", len(res.Evidence.JS))
	}
	if hasMatch(res.Matches, ProviderAWSS3, SignalFile) {
		t.Errorf("file match should not fire on truncated body: %+v", res.Matches)
	}
}

func TestAnalyzer_PopulatesTLSAndBucketHost(t *testing.T) {
	// httptest.NewTLSServer presents a self-signed cert whose DNSNames
	// include 'example.com'; we just check that the analyser surfaces SAN
	// and SNI rather than asserting on the certificate's exact contents.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Goog-Generation", "1")
		_, _ = w.Write([]byte("// firebase/storage"))
	}))
	defer srv.Close()

	a := NewAnalyzer(AnalyzerOptions{HTTPClient: srv.Client(), Timeout: 2 * time.Second})
	res, err := a.Analyze(context.Background(), srv.URL+"/v0/b/demo/o/file")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	if res.Evidence.TLSServerName == "" && len(res.Evidence.TLSSANs) == 0 {
		t.Errorf("expected TLS metadata to be populated, got %+v", res.Evidence)
	}
	if res.Evidence.BucketHost == "" {
		t.Errorf("expected BucketHost extracted from URL, got %+v", res.Evidence)
	}
	// The X-Goog-Generation header should still produce a GCS API match
	// even though the server's TLS cert won't match the GCS hostname.
	if !hasMatch(res.Matches, ProviderGCS, SignalAPI) {
		t.Errorf("expected GCS API match from x-goog-generation header, got %+v", res.Matches)
	}
}

func TestAnalyzer_RespectsCallerDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // hang until caller cancels
	}))
	defer srv.Close()

	a := NewAnalyzer(AnalyzerOptions{HTTPClient: srv.Client(), Timeout: 5 * time.Second})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := a.Analyze(ctx, srv.URL+"/asset.js")
	if err == nil {
		t.Fatalf("expected context-deadline error, got nil")
	}
}
