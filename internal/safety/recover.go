// Package safety provides panic recovery wrappers and runtime safety
// utilities for kite-collector goroutines, HTTP handlers, and gRPC
// interceptors.
package safety

import (
	"fmt"
	"log/slog"
	"runtime/debug"

	"github.com/prometheus/client_golang/prometheus"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
)

// Recover catches a panic in a deferred call, logs it with a stack trace,
// and increments the supplied Prometheus counter. If retErr is non-nil, it
// is set to an error describing the panic.
//
// Usage:
//
//	defer safety.Recover("discovery.docker", counter, &err)
func Recover(component string, counter *prometheus.CounterVec, retErr *error) {
	r := recover()
	if r == nil {
		return
	}
	stack := string(debug.Stack())

	// Build the catalogued KITE-E011 error once so the log line and the error
	// surfaced to the caller share the same code and remediation hint. The
	// "panic in <component>: <value>" detail is preserved as the cause, so
	// errors.Is/As and existing substring checks keep working.
	panicErr := kiteerrors.FromCatalog(kiteerrors.CodePanicRecovered,
		fmt.Errorf("panic in %s: %v", component, r)).With("component", component)

	slog.Error(
		"panic recovered in goroutine; converted to error and surfaced to caller",
		"code", string(LogCodeSafetyPanicRecovered),
		"component", component,
		"error", fmt.Sprint(r),
		"stack_trace", stack,
		"recover_wrapper", "Recover",
		"hint", panicErr.Hint,
	)
	if counter != nil {
		counter.With(prometheus.Labels{"component": component}).Inc()
	}
	if retErr != nil {
		*retErr = panicErr
	}
}

// LogPanic logs a recovered panic and increments the counter. Use this
// helper when the caller handles recover() itself (e.g., when additional
// cleanup such as a channel send is needed in the same defer).
func LogPanic(component string, panicVal any, stack string, counter *prometheus.CounterVec) {
	slog.Error(
		"panic recovered by caller-driven helper; caller will perform cleanup",
		"code", string(LogCodeSafetyPanicRecovered),
		"component", component,
		"error", fmt.Sprint(panicVal),
		"stack_trace", stack,
		"recover_wrapper", "LogPanic",
	)
	if counter != nil {
		counter.With(prometheus.Labels{"component": component}).Inc()
	}
}
