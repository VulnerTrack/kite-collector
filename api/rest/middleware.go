package rest

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/prometheus/client_golang/prometheus"
)

// RecoveryMiddleware wraps an http.Handler with panic recovery. Panics are
// caught, logged with a stack trace, counted via the supplied Prometheus
// counter, and the client receives an HTTP 500 with a structured JSON body.
func RecoveryMiddleware(counter *prometheus.CounterVec, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				stack := string(debug.Stack())
				slog.Error("panic recovered in REST handler",
					"component", "rest",
					"method", r.Method,
					"path", r.URL.Path,
					"error", fmt.Sprint(rec),
					"stack_trace", stack,
				)
				if counter != nil {
					counter.With(prometheus.Labels{"component": "rest"}).Inc()
				}
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// MaxBytesMiddleware limits the size of incoming request bodies using
// http.MaxBytesReader. If a handler reads beyond maxBytes, the read returns
// an error. When maxBytes is <= 0 the middleware is a no-op pass-through.
func MaxBytesMiddleware(maxBytes int64, next http.Handler) http.Handler {
	if maxBytes <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}

// boundedResponseWriter wraps an http.ResponseWriter and silently stops
// writing after maxBytes have been flushed. This is a safety net to prevent
// runaway responses from exhausting server memory; normal pagination limits
// should keep responses well under the cap.
type boundedResponseWriter struct {
	http.ResponseWriter
	maxBytes  int64
	written   int64
	truncated bool
	counter   prometheus.Counter
}

func (w *boundedResponseWriter) Write(p []byte) (int, error) {
	if w.truncated {
		return len(p), nil
	}
	remaining := w.maxBytes - w.written
	if remaining <= 0 {
		w.truncated = true
		if w.counter != nil {
			w.counter.Inc()
		}
		slog.Warn("response truncated: size limit exceeded",
			"max_bytes", w.maxBytes, "written", w.written)
		return len(p), nil
	}
	truncating := int64(len(p)) > remaining
	if truncating {
		p = p[:remaining]
	}
	n, err := w.ResponseWriter.Write(p)
	w.written += int64(n)
	if truncating {
		w.truncated = true
		if w.counter != nil {
			w.counter.Inc()
		}
		slog.Warn("response truncated: size limit exceeded",
			"max_bytes", w.maxBytes, "written", w.written)
	}
	return n, err
}

// ResponseBoundingMiddleware limits the total bytes written to the HTTP
// response body. When maxBytes is <= 0 the middleware is a no-op.
func ResponseBoundingMiddleware(maxBytes int64, counter prometheus.Counter, next http.Handler) http.Handler {
	if maxBytes <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bw := &boundedResponseWriter{
			ResponseWriter: w,
			maxBytes:       maxBytes,
			counter:        counter,
		}
		next.ServeHTTP(bw, r)
	})
}
