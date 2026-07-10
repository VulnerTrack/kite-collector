package errors

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"log/slog"
	"strings"
	"testing"
)

func TestAttrsRenderEnvelopeAsTopLevelFields(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	err := Wrap(stderrors.New("connection refused"), "KITE-E002", "Wazuh authentication failed").
		WithHint("check KITE_WAZUH_USERNAME and KITE_WAZUH_PASSWORD").
		With("status", 401).
		With("endpoint", "https://localhost:55000")

	logger.LogAttrs(context.Background(), slog.LevelError, "token exchange failed", Attrs(err)...)

	var rec map[string]any
	if e := json.Unmarshal([]byte(buf.String()), &rec); e != nil {
		t.Fatalf("log line is not valid JSON: %v\n%s", e, buf.String())
	}

	if got := rec["error_code"]; got != "KITE-E002" {
		t.Errorf("error_code = %v, want KITE-E002", got)
	}
	if got := rec["error_message"]; got != "Wazuh authentication failed: connection refused" {
		t.Errorf("error_message = %v", got)
	}
	if got := rec["hint"]; got != "check KITE_WAZUH_USERNAME and KITE_WAZUH_PASSWORD" {
		t.Errorf("hint = %v", got)
	}
	ctx, ok := rec["error_context"].(map[string]any)
	if !ok {
		t.Fatalf("error_context is not an object: %v", rec["error_context"])
	}
	if ctx["status"] != float64(401) || ctx["endpoint"] != "https://localhost:55000" {
		t.Errorf("error_context = %v", ctx)
	}
}

func TestAttrsPlainErrorFallback(t *testing.T) {
	attrs := Attrs(stderrors.New("boom"))
	got := map[string]slog.Value{}
	for _, a := range attrs {
		got[a.Key] = a.Value
	}
	if got["error_code"].String() != "" {
		t.Errorf("plain error should have empty code, got %q", got["error_code"].String())
	}
	if got["error_message"].String() != "boom" {
		t.Errorf("error_message = %q", got["error_message"].String())
	}
	if _, ok := got["error_context"]; !ok {
		t.Error("error_context should always be present")
	}
}

func TestUnwrapAndAsTraverseChain(t *testing.T) {
	sentinel := stderrors.New("sentinel")
	err := Wrap(sentinel, "KITE-E010", "migration failed")

	if !stderrors.Is(err, sentinel) {
		t.Error("errors.Is should find the wrapped sentinel")
	}
	// errors.As should recover the *Error even when wrapped again downstream.
	wrapped := Wrap(err, "KITE-E011", "outer") //nolint:errcheck
	_ = wrapped
	var e *Error
	if !stderrors.As(err, &e) || e.Code != "KITE-E010" {
		t.Errorf("errors.As failed to recover *Error, got %+v", e)
	}
}

func TestFromCatalogPullsMessageAndHint(t *testing.T) {
	err := FromCatalog("KITE-E001", stderrors.New("dial tcp: no route"))
	if err.Message != "Docker not accessible" {
		t.Errorf("Message = %q, want catalogue message", err.Message)
	}
	if err.Hint == "" {
		t.Error("Hint should be populated from catalogue remediation")
	}
	if !strings.Contains(err.Error(), "no route") {
		t.Errorf("Error() should include cause, got %q", err.Error())
	}
}
