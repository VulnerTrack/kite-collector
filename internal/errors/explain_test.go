package errors

import (
	stderrors "errors"
	"fmt"
	"strings"
	"testing"
)

// TestExplain_ThroughWrappedChain guards the realistic CLI path: command RunE
// functions typically wrap errors with %w before returning (e.g.
// `return fmt.Errorf("run scan: %w", err)`), so Explain must still surface the
// catalogued remediation through the extra layers via errors.As. Without this,
// the iteration-26 CLI feature would silently miss remediation for any command
// that annotates its error.
func TestExplain_ThroughWrappedChain(t *testing.T) {
	base := Wrap(stderrors.New("bad yaml"), CodeConfigInvalid, "Configuration file invalid")
	wrapped := fmt.Errorf("start dashboard: %w", fmt.Errorf("load config: %w", base))

	out := Explain(wrapped)

	// Outer context is preserved...
	if !strings.Contains(out, "start dashboard") {
		t.Errorf("expected outer wrap context, got %q", out)
	}
	// ...and the catalogued remediation is still found and appended.
	if !strings.Contains(out, "KITE-E007") || !strings.Contains(out, "YAML syntax") {
		t.Errorf("remediation not surfaced through the wrapped chain: %q", out)
	}
}

// TestExplain_CataloguedErrorAppendsRemediation verifies that a failed command
// carrying a catalog code shows the fix inline: both the error message and the
// catalogued remediation (code, cause, OS-specific fix) appear.
func TestExplain_CataloguedErrorAppendsRemediation(t *testing.T) {
	err := Wrap(stderrors.New("bad yaml"), CodeConfigInvalid, "Configuration file invalid")

	out := Explain(err)

	if !strings.Contains(out, "Configuration file invalid") {
		t.Errorf("expected the error message, got %q", out)
	}
	if !strings.Contains(out, "KITE-E007") {
		t.Errorf("expected the catalog code from Format(), got %q", out)
	}
	if !strings.Contains(out, "YAML syntax") {
		t.Errorf("expected the catalogued remediation text, got %q", out)
	}
	if !strings.Contains(out, "bad yaml") {
		t.Errorf("expected the underlying cause, got %q", out)
	}
}

// TestExplain_PlainErrorIsJustMessage guards that a non-catalogued error is not
// decorated with catalog noise.
func TestExplain_PlainErrorIsJustMessage(t *testing.T) {
	out := Explain(stderrors.New("something broke"))
	if out != "something broke" {
		t.Errorf("Explain(plain) = %q, want the bare message", out)
	}
}

// TestExplain_UnknownCodeFallsBackToMessage ensures a structured error whose
// code is not in the catalog degrades to the message (no panic, no empty
// Format block).
func TestExplain_UnknownCodeFallsBackToMessage(t *testing.T) {
	err := New("KITE-E999", "made-up error")
	out := Explain(err)
	if out != "made-up error" {
		t.Errorf("Explain(unknown code) = %q, want the bare message", out)
	}
}

func TestExplain_NilIsEmpty(t *testing.T) {
	if got := Explain(nil); got != "" {
		t.Errorf("Explain(nil) = %q, want empty", got)
	}
}
