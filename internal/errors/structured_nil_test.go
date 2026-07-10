package errors

import (
	"log/slog"
	"strings"
	"testing"
)

// TestError_NilReceiverIsSafe guards the classic Go typed-nil footgun: a
// nil-valued *Error returned as an error must never panic when its methods
// run in a logging or error-inspection path.
func TestError_NilReceiverIsSafe(t *testing.T) {
	var e *Error // typed nil

	if got := e.Error(); got != "<nil>" {
		t.Errorf("nil Error() = %q, want %q", got, "<nil>")
	}
	if e.Unwrap() != nil {
		t.Error("nil Unwrap() should return nil")
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("LogValue panicked on nil receiver: %v", r)
			}
		}()
		_ = e.LogValue()
	}()
}

// TestAttrs_TypedNilDoesNotPanic ensures Attrs handles a typed-nil *Error
// (which is != nil at the interface level) without panicking, still emitting
// all four stable envelope keys.
func TestAttrs_TypedNilDoesNotPanic(t *testing.T) {
	var typedNil error = (*Error)(nil)

	var attrs []slog.Attr
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Attrs panicked on typed-nil *Error: %v", r)
			}
		}()
		attrs = Attrs(typedNil)
	}()

	got := make(map[string]bool, len(attrs))
	for _, a := range attrs {
		got[a.Key] = true
	}
	for _, k := range []string{"error_code", "error_message", "hint", "error_context"} {
		if !got[k] {
			t.Errorf("envelope missing top-level key %q", k)
		}
	}
}

// TestLogValue_TypedNilThroughJSONHandler drives a typed-nil *Error through a
// real slog JSON handler via slog.Any (which resolves LogValuer), asserting no
// panic and a well-formed envelope.
func TestLogValue_TypedNilThroughJSONHandler(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("logging a typed-nil *Error panicked: %v", r)
		}
	}()
	logger.Error("boom", slog.Any("error", (*Error)(nil)))

	if !strings.Contains(buf.String(), "error_message") {
		t.Errorf("expected error_message in log output, got %q", buf.String())
	}
}
