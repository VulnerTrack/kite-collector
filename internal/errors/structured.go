package errors

import (
	stderrors "errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
)

// WrapFileError classifies a filesystem error from operation op. A permission
// failure is surfaced as the catalogued KITE-E008 (check ownership/permissions,
// run as admin) with the cause preserved so errors.Is(err, os.ErrPermission)
// still matches; any other error is annotated with op and returned unchanged in
// shape; a nil error stays nil. This is the canonical way to produce E008 from
// a file operation, shared by the identity and enrollment key/cert stores.
func WrapFileError(op string, err error) error {
	if err == nil {
		return nil
	}
	if stderrors.Is(err, os.ErrPermission) {
		return FromCatalog(CodePermissionDenied, fmt.Errorf("%s: %w", op, err))
	}
	return fmt.Errorf("%s: %w", op, err)
}

// Error is a runtime error instance that renders as a structured envelope in
// slog JSON logs:
//
//	{"error_code": "", "error_message": "", "hint": "", "error_context": {}}
//
// It pairs a stable Code (for alerting/runbook pivots, like LogCode) with the
// underlying cause, an operator-facing Hint, and arbitrary Context key/values.
// It implements error and Unwrap, so errors.Is / errors.As keep working, and
// slog.LogValuer, so `slog.Any("error", err)` emits the envelope as a group.
// Use Attrs to emit the envelope as top-level log fields instead.
//
// Fields ordered pointer-first to minimise the GC pointer bitmap
// (govet fieldalignment), mirroring KiteError.
type Error struct {
	// Context holds structured key/values describing where/why the error
	// occurred (status codes, IDs, URLs). Rendered under "error_context".
	Context map[string]any
	// cause is the wrapped underlying error, exposed via Unwrap.
	cause error
	// Code is the stable identifier, e.g. "KITE-E002" or a dotted LogCode.
	Code string
	// Message is a short human-readable summary.
	Message string
	// Hint is operator-facing remediation guidance.
	Hint string
}

// New builds a structured error with no underlying cause.
func New(code, message string) *Error {
	return &Error{Code: code, Message: message}
}

// Wrap builds a structured error around an underlying cause.
func Wrap(cause error, code, message string) *Error {
	return &Error{Code: code, Message: message, cause: cause}
}

// FromCatalog builds a structured error from a catalogued KiteError, pulling
// the Message and OS-specific remediation Hint from the Catalog. Unknown codes
// yield an error carrying just the code.
func FromCatalog(code string, cause error) *Error {
	e := &Error{Code: code, cause: cause}
	if entry := Lookup(code); entry != nil {
		e.Message = entry.Message
		e.Hint = entry.RemediationFor(runtime.GOOS)
	}
	return e
}

// WithHint sets operator-facing remediation guidance and returns the error for
// chaining.
func (e *Error) WithHint(hint string) *Error {
	e.Hint = hint
	return e
}

// With adds a single key/value to the error context and returns the error for
// chaining.
func (e *Error) With(key string, value any) *Error {
	if e.Context == nil {
		e.Context = make(map[string]any, 4)
	}
	e.Context[key] = value
	return e
}

// WithContext merges the given key/values into the error context and returns
// the error for chaining.
func (e *Error) WithContext(ctx map[string]any) *Error {
	if len(ctx) == 0 {
		return e
	}
	if e.Context == nil {
		e.Context = make(map[string]any, len(ctx))
	}
	for k, v := range ctx {
		e.Context[k] = v
	}
	return e
}

// Error implements the error interface. The rendered string is cause-inclusive
// but code-free so it stays clean when surfaced to callers (e.g. HTTP bodies);
// the code travels in the structured fields.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	switch {
	case e.Message != "" && e.cause != nil:
		return e.Message + ": " + e.cause.Error()
	case e.Message != "":
		return e.Message
	case e.cause != nil:
		return e.cause.Error()
	default:
		return e.Code
	}
}

// Unwrap exposes the underlying cause so errors.Is / errors.As traverse it.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// LogValue implements slog.LogValuer so `slog.Any("error", err)` renders the
// envelope as a nested group. Use Attrs for top-level fields instead.
func (e *Error) LogValue() slog.Value {
	return slog.GroupValue(e.attrs()...)
}

// attrs returns the envelope as ordered slog attributes.
func (e *Error) attrs() []slog.Attr {
	// A typed-nil *Error (the classic Go footgun: returning a nil-valued
	// concrete pointer as an error) must not panic in the logging path.
	if e == nil {
		return fallbackAttrs("<nil>")
	}
	ctx := e.Context
	if ctx == nil {
		// Emit an explicit empty object rather than letting slog elide a
		// zero-attr group, so the envelope shape is stable in production.
		ctx = map[string]any{}
	}
	return []slog.Attr{
		slog.String("error_code", e.Code),
		slog.String("error_message", e.Error()),
		slog.String("hint", e.Hint),
		slog.Any("error_context", ctx),
	}
}

// fallbackAttrs builds the envelope for an error that carries no structured
// code/hint/context — a plain error or a nil *Error — keeping the four
// top-level fields stable so downstream log queries never see a missing key.
func fallbackAttrs(msg string) []slog.Attr {
	return []slog.Attr{
		slog.String("error_code", ""),
		slog.String("error_message", msg),
		slog.String("hint", ""),
		slog.Any("error_context", map[string]any{}),
	}
}

// Attrs returns the structured envelope for any error as top-level slog
// attributes, ready to spread into slog.Logger.LogAttrs:
//
//	logger.LogAttrs(ctx, slog.LevelError, "token exchange failed",
//		errors.Attrs(err)...)
//
// If err (or anything it wraps) is a *Error, its code/hint/context are used;
// otherwise a plain error yields an empty code/hint and its message. A nil err
// yields no attributes.
func Attrs(err error) []slog.Attr {
	if err == nil {
		return nil
	}
	var e *Error
	if stderrors.As(err, &e) && e != nil {
		return e.attrs()
	}
	// Plain error, or a typed-nil *Error in the chain — fall back to the bare
	// envelope. err.Error() is safe here: a nil *Error's Error() is guarded.
	return fallbackAttrs(err.Error())
}

// Explain renders err for an operator (e.g. a failed CLI command). When err
// carries a catalog code, the catalogued remediation (KiteError.Format) is
// appended so the fix is shown inline instead of requiring a separate
// `kite-collector error <code>` lookup; a plain error yields just its message,
// and nil yields "".
func Explain(err error) string {
	if err == nil {
		return ""
	}
	var e *Error
	if stderrors.As(err, &e) && e != nil {
		if entry := Lookup(e.Code); entry != nil {
			return err.Error() + "\n\n" + entry.Format()
		}
	}
	return err.Error()
}
