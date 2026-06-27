package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// captureStdout swaps os.Stdout for a pipe while fn runs and returns
// whatever fn wrote. This lets the test verify the JSON shape without
// extracting a writer from the cobra command (the subcommand prints
// directly to os.Stdout to match the project's existing style).
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()

	fn()

	_ = w.Close()
	<-done
	os.Stdout = orig
	return buf.String()
}

// writeFixture drops a temporary JS file containing the supplied body so
// the runner can exercise the --file code path without depending on the
// package-private testdata fixtures (those live under internal/, which
// this command package can not reach without imports we want to avoid).
func writeFixture(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestRunStorageFingerprint_FileJSON(t *testing.T) {
	path := writeFixture(t, "app.js", `import { S3Client } from "@aws-sdk/client-s3";`)

	out := captureStdout(t, func() {
		err := runStorageFingerprint(storageFingerprintOpts{
			file:   path,
			output: "json",
		})
		if err != nil {
			t.Fatalf("runStorageFingerprint: %v", err)
		}
	})

	var payload struct {
		Matches []map[string]any `json:"matches"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("json output not parseable: %v\nraw=%s", err, out)
	}

	foundAWS := false
	for _, m := range payload.Matches {
		if m["provider"] == "aws_s3" && m["signal"] == "file" {
			foundAWS = true
			break
		}
	}
	if !foundAWS {
		t.Fatalf("expected aws_s3/file match in JSON output, got %v", payload.Matches)
	}
}

func TestRunStorageFingerprint_FilterAppliedToFile(t *testing.T) {
	path := writeFixture(t, "app.js", `import { S3Client } from "@aws-sdk/client-s3";`)

	out := captureStdout(t, func() {
		err := runStorageFingerprint(storageFingerprintOpts{
			file:      path,
			output:    "table",
			providers: []string{"gcs"}, // filter out the AWS match
		})
		if err != nil {
			t.Fatalf("runStorageFingerprint: %v", err)
		}
	})

	if !strings.Contains(out, "No matches.") {
		t.Errorf("expected filter to suppress all matches, got %q", out)
	}
}

func TestRunStorageFingerprint_RejectsConflictingFlags(t *testing.T) {
	err := runStorageFingerprint(storageFingerprintOpts{target: "x", file: "y"})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually-exclusive error, got %v", err)
	}

	err = runStorageFingerprint(storageFingerprintOpts{})
	if err == nil {
		t.Fatalf("expected error when neither --url nor --file is set")
	}
}

func TestRunStorageFingerprint_RejectsBadConfidence(t *testing.T) {
	err := runStorageFingerprint(storageFingerprintOpts{file: "/tmp/x.js", minConf: 9})
	if err == nil || !strings.Contains(err.Error(), "min-confidence") {
		t.Fatalf("expected min-confidence validation error, got %v", err)
	}
}

func TestReadScanList_SkipsBlanksAndComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	body := strings.Join([]string{
		"# comment",
		"https://example.com/a.js",
		"   ",
		"",
		"https://example.com/b.js",
		"  # leading-space comment",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write list: %v", err)
	}
	got, err := readScanList(path)
	if err != nil {
		t.Fatalf("readScanList: %v", err)
	}
	want := []string{"https://example.com/a.js", "https://example.com/b.js"}
	if !equalStringSlice(got, want) {
		t.Fatalf("readScanList got %v want %v", got, want)
	}
}

func TestRunStorageFingerprint_BatchEmitsSummary(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "list.txt")
	// Use an unreachable target so the probe fails fast and we exercise
	// the error path without needing an httptest server.
	body := "http://127.0.0.1:1/unreachable.js"
	if err := os.WriteFile(listPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write list: %v", err)
	}

	out := captureStdout(t, func() {
		err := runStorageFingerprint(storageFingerprintOpts{
			scanList: listPath,
			output:   "json",
			timeout:  500 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("runStorageFingerprint batch: %v", err)
		}
	})

	var batch []map[string]any
	if err := json.Unmarshal([]byte(out), &batch); err != nil {
		t.Fatalf("batch JSON unparseable: %v\nraw=%s", err, out)
	}
	if len(batch) != 1 {
		t.Fatalf("expected 1 batch entry, got %d (%v)", len(batch), batch)
	}
	if batch[0]["error"] == nil {
		t.Errorf("expected error field for unreachable target, got %v", batch[0])
	}
}

func TestRunStorageFingerprint_RejectsMultipleModes(t *testing.T) {
	err := runStorageFingerprint(storageFingerprintOpts{target: "u", scanList: "s"})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually-exclusive error, got %v", err)
	}
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
