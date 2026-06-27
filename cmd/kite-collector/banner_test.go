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

// TestPrintBrandBanner_TTY_UsesRedANSI pins the brand-red truecolor escape
// in the colored render path.
//
// We can't easily fake a TTY through `printBrandBanner` (the helper inspects
// a real *os.File and os.Stderr), so we assert directly on the brandANSI
// constant — which is exactly what the colored path emits. The substring
// `48;2;255;49;49` is the 24-bit background SGR for the brand primary
// (#FF3131); `38;2;245;245;245` is the foreground for the brand
// contrastText (#F5F5F5). Either drifting from those RGB triples means the
// banner no longer matches the design-system palette in
// internal/dashboard/static/style.css.
func TestPrintBrandBanner_TTY_UsesRedANSI(t *testing.T) {
	const wantBg = "48;2;255;49;49"
	const wantFg = "38;2;245;245;245"
	if !strings.Contains(brandANSI, wantBg) {
		t.Fatalf("expected brand-red bg %q in brandANSI, got: %q", wantBg, brandANSI)
	}
	if !strings.Contains(brandANSI, wantFg) {
		t.Fatalf("expected contrast-text fg %q in brandANSI, got: %q", wantFg, brandANSI)
	}
	if !strings.Contains(brandANSI, "Vulnertrack") {
		t.Fatalf("expected wordmark in brandANSI, got: %q", brandANSI)
	}
	// Bold attribute (SGR 1) and reset (SGR 0) should bracket the wordmark.
	if !strings.HasPrefix(brandANSI, "\x1b[1;") {
		t.Fatalf("expected brandANSI to start with bold SGR, got: %q", brandANSI)
	}
	if !strings.HasSuffix(brandANSI, "\x1b[0m") {
		t.Fatalf("expected brandANSI to end with SGR reset, got: %q", brandANSI)
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
