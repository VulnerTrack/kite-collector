package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestPrintBrandBanner_NoColorPlainText verifies that with NO_COLOR set the
// banner contains no ANSI escape sequences and prints the wordmark plainly.
func TestPrintBrandBanner_NoColorPlainText(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	var buf bytes.Buffer
	printBrandBanner(&buf, "1.2.3", "abcdef0")

	got := buf.String()
	if strings.Contains(got, "\x1b[") {
		t.Fatalf("expected no ANSI escapes when NO_COLOR is set, got: %q", got)
	}
	if !strings.Contains(got, "Powered by Vulnertrack") {
		t.Fatalf("expected plain 'Powered by Vulnertrack' line, got: %q", got)
	}
	if !strings.Contains(got, "kite-collector v1.2.3 (abcdef0)") {
		t.Fatalf("expected version+commit line, got: %q", got)
	}
}

// TestPrintBrandBanner_ContainsPoweredByVulnertrack verifies the banner
// always advertises the brand, regardless of color mode. We pass a
// bytes.Buffer (non-TTY) so this is the plain-text path even without
// NO_COLOR — the assertion is on textual content, not styling.
func TestPrintBrandBanner_ContainsPoweredByVulnertrack(t *testing.T) {
	var buf bytes.Buffer
	printBrandBanner(&buf, "9.9.9", "deadbee")

	got := buf.String()
	if !strings.Contains(got, "Powered by") {
		t.Fatalf("expected 'Powered by' in banner, got: %q", got)
	}
	if !strings.Contains(got, "Vulnertrack") {
		t.Fatalf("expected 'Vulnertrack' in banner, got: %q", got)
	}
	if !strings.Contains(got, "https://vulnertrack.com") {
		t.Fatalf("expected brand URL in banner, got: %q", got)
	}
}
