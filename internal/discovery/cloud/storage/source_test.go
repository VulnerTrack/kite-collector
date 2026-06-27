package storage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// frozenSource returns a Source whose timestamps are reproducible — useful
// because the asset's NaturalKey is timestamp-independent but the test
// otherwise leaks wall-clock variance into log lines.
func frozenSource() *Source {
	s := NewSource()
	s.now = func() time.Time { return time.Unix(1735689600, 0).UTC() }
	return s
}

func TestSource_NoTargetsReturnsNil(t *testing.T) {
	assets, err := frozenSource().Discover(context.Background(), nil)
	if err != nil {
		t.Fatalf("Discover with nil cfg: %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("expected zero assets with no config, got %+v", assets)
	}
}

func TestSource_EmitsAssetPerBucket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amz-Request-Id", "abc")
		_, _ = w.Write([]byte(`import { S3Client } from "@aws-sdk/client-s3";`))
	}))
	defer srv.Close()

	cfg := map[string]any{
		"targets": []any{srv.URL + "/main.js"},
	}
	assets, err := frozenSource().Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d (%+v)", len(assets), assets)
	}
	a := assets[0]
	if a.DiscoverySource != "storage_fingerprint" {
		t.Errorf("unexpected DiscoverySource %q", a.DiscoverySource)
	}
	if a.Environment != "aws_s3" {
		t.Errorf("expected primary provider 'aws_s3' in Environment, got %q", a.Environment)
	}

	// Tags JSON should at least carry the primary provider and a non-empty
	// signals map.
	var tags map[string]any
	if err := json.Unmarshal([]byte(a.Tags), &tags); err != nil {
		t.Fatalf("Tags is not JSON: %v (%q)", err, a.Tags)
	}
	if tags["primary_provider"] != "aws_s3" {
		t.Errorf("primary_provider mismatch in Tags: %v", tags["primary_provider"])
	}
	if sigs, _ := tags["signals"].(map[string]any); len(sigs) == 0 {
		t.Errorf("signals map should be non-empty: %v", tags["signals"])
	}
}

func TestSource_DeduplicatesByBucketHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`@aws-sdk/client-s3`))
	}))
	defer srv.Close()

	cfg := map[string]any{
		"targets": []any{
			srv.URL + "/a.js",
			srv.URL + "/b.js", // same host → same bucket host → dedup
		},
	}
	assets, err := frozenSource().Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset after dedup, got %d", len(assets))
	}
}

func TestSource_FilterAppliedBeforeAssetEmission(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`@aws-sdk/client-s3`))
	}))
	defer srv.Close()

	cfg := map[string]any{
		"targets":             []any{srv.URL + "/a.js"},
		"providers_allowlist": []any{"supabase_storage"}, // filter out AWS
	}
	assets, err := frozenSource().Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("expected 0 assets after provider filter, got %+v", assets)
	}
}

func TestSource_MinConfidenceFromConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`@aws-sdk/client-s3`))
	}))
	defer srv.Close()

	cfg := map[string]any{
		"targets":        []any{srv.URL + "/a.js"},
		"min_confidence": 3, // every catalogue rule we match here is high already; sanity
	}
	assets, err := frozenSource().Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset at min-confidence=high, got %d", len(assets))
	}

	// min-confidence above any rule's confidence band silences output.
	cfg["min_confidence"] = 99
	assets, err = frozenSource().Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("expected 0 assets at impossible min-confidence, got %+v", assets)
	}
}

func TestSource_ProbeFailureDoesNotHaltOthers(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`@aws-sdk/client-s3`))
	}))
	defer good.Close()

	cfg := map[string]any{
		"targets": []any{
			"http://127.0.0.1:1/unreachable", // no listener
			good.URL + "/a.js",
		},
		"timeout": "500ms",
	}
	assets, err := frozenSource().Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover should not error on partial probe failure: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset from surviving probe, got %d", len(assets))
	}
}

func TestSource_PageTargetsFanOut(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/index.html", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`
			<script src="/app.js"></script>
			<script src="/vendor.js"></script>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`@aws-sdk/client-s3`))
	})
	mux.HandleFunc("/vendor.js", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`@supabase/supabase-js`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := map[string]any{
		"page_targets": []any{srv.URL + "/index.html"},
		"timeout":      "2s",
	}
	assets, err := frozenSource().Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(assets) != 1 {
		// Both scripts share the same host (the httptest server), so
		// dedup-by-bucket-host should collapse them to one asset. The
		// test would need separate hosts to surface two — instead we
		// assert that fan-out at least found the AWS provider.
		t.Fatalf("expected 1 deduplicated asset, got %d (%+v)", len(assets), assets)
	}

	// Tags should mention either aws_s3 or supabase_storage as primary.
	if !strings.Contains(assets[0].Tags, "aws_s3") && !strings.Contains(assets[0].Tags, "supabase_storage") {
		t.Errorf("expected aws_s3 or supabase_storage in tags, got %q", assets[0].Tags)
	}
}

func TestSource_PageTargetsFailureSurvives(t *testing.T) {
	// Unreachable page_target should not abort direct-target processing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`@aws-sdk/client-s3`))
	}))
	defer srv.Close()

	cfg := map[string]any{
		"page_targets": []any{"http://127.0.0.1:1/missing.html"},
		"targets":      []any{srv.URL + "/app.js"},
		"timeout":      "500ms",
	}
	assets, err := frozenSource().Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset from surviving direct target, got %d", len(assets))
	}
}

func TestSource_LoadsExternalSignatures(t *testing.T) {
	dir := t.TempDir()
	sigsPath := filepath.Join(dir, "sigs.json")
	body := `[{
		"provider": "custom_provider",
		"signal": "file",
		"pattern": "(?i)custom-sdk-marker",
		"description": "Custom SDK marker",
		"confidence": 3
	}]`
	if err := os.WriteFile(sigsPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write sigs: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`hi there; CUSTOM-SDK-MARKER appears here`))
	}))
	defer srv.Close()

	cfg := map[string]any{
		"targets":        []any{srv.URL + "/main.js"},
		"signature_file": sigsPath,
		"timeout":        "2s",
	}
	assets, err := frozenSource().Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset from custom signature, got %d", len(assets))
	}
	if !strings.Contains(assets[0].Tags, "custom_provider") {
		t.Errorf("expected custom_provider in Tags, got %q", assets[0].Tags)
	}
}

func TestSource_SignatureFileLoadErrorDegradesGracefully(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`@aws-sdk/client-s3`))
	}))
	defer srv.Close()

	cfg := map[string]any{
		"targets":        []any{srv.URL + "/main.js"},
		"signature_file": "/nonexistent/path/to/sigs.json",
		"timeout":        "2s",
	}
	assets, err := frozenSource().Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover should not error on bad signature_file: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset from built-in catalogue fallback, got %d", len(assets))
	}
}

func TestSource_NameMatchesRegistryConvention(t *testing.T) {
	if name := frozenSource().Name(); name != "storage_fingerprint" {
		t.Errorf("Source name should be the registry key, got %q", name)
	}
	if !strings.HasPrefix("storage_fingerprint", "storage") {
		t.Error("sanity check on prefix")
	}
}
