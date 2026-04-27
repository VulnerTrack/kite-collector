package dashboard

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/scan"
	"github.com/vulnertrack/kite-collector/internal/store"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

// Options bundles the optional dependencies a dashboard server can wire in.
// When Coordinator and BaseConfig are both non-nil, the "Run Scan" button
// actually starts a scan through the coordinator; otherwise the button
// renders a read-only placeholder.
//
// StreamController, when non-nil, enables the RFC-0112 streaming toggle
// buttons on /onboarding. A nil controller causes the onboarding page to
// render the streaming card as disabled (read-only banner).
// AppVersion / Commit are surfaced in /api/v1/support-bundle; empty values
// are rendered as the literal string "dev".
type Options struct {
	Coordinator      *scan.Coordinator
	BaseConfig       *config.Config
	StreamController StreamController
	AppVersion       string
	Commit           string
	// PlatformEndpoint is the collector's OTLP destination (sourced from
	// cfg.Streaming.OTLP.Endpoint). The onboarding Enroll form shows this as
	// read-only text and the connection-check probes dial this host. The
	// value is NOT persisted in enrolled_identity — see RFC-0112.
	PlatformEndpoint string
}

// Serve creates and returns an HTTP server for the dashboard.
// The caller is responsible for calling ListenAndServe.
//
// When opts.Coordinator is nil the dashboard runs in read-only mode:
// fragments still render, but POST /api/v1/scan returns a "not available"
// badge instead of starting a scan. This matches the `vie dashboard`
// standalone inspector mode where no engine is wired up.
func Serve(addr string, st store.Store, rc ReportContext, logger *slog.Logger, opts Options) *http.Server {
	if logger == nil {
		logger = slog.Default()
	}

	mux := http.NewServeMux()

	// Serve static files (embedded or from disk in dev mode).
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		logger.Error("dashboard: failed to create sub filesystem", "error", err)
	} else {
		mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
	}

	// Dashboard root — serves the main HTML page.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		indexContent, readErr := fs.ReadFile(staticFS, "static/index.html")
		if readErr != nil {
			http.Error(w, "index.html not found", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(indexContent)
	})

	// renderFragment renders a template to a buffer first, then writes to
	// the response. This prevents "superfluous WriteHeader" when a template
	// error occurs after partial output has already been sent.
	renderFragment := func(w http.ResponseWriter, name string, render func(io.Writer) error) {
		var buf bytes.Buffer
		if renderErr := render(&buf); renderErr != nil {
			logger.Error("dashboard: render "+name, "error", renderErr)
			http.Error(w, renderErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(buf.Bytes())
	}

	// HTMX fragment endpoints — return HTML snippets for dynamic loading.
	mux.HandleFunc("GET /fragments/assets", func(w http.ResponseWriter, r *http.Request) {
		renderFragment(w, "assets", func(buf io.Writer) error {
			return renderAssetsFragment(buf, r.Context(), st, rc)
		})
	})

	mux.HandleFunc("GET /fragments/software", func(w http.ResponseWriter, r *http.Request) {
		renderFragment(w, "software", func(buf io.Writer) error {
			return renderSoftwareFragment(buf, r.Context(), st, rc)
		})
	})

	mux.HandleFunc("GET /fragments/findings", func(w http.ResponseWriter, r *http.Request) {
		renderFragment(w, "findings", func(buf io.Writer) error {
			return renderFindingsFragment(buf, r.Context(), st, rc)
		})
	})

	mux.HandleFunc("GET /fragments/scans", func(w http.ResponseWriter, r *http.Request) {
		renderFragment(w, "scans", func(buf io.Writer) error {
			return renderScansFragment(buf, r.Context(), st, rc)
		})
	})

	// CSV export endpoints.
	mux.HandleFunc("GET /api/v1/assets/export.csv", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=assets_%s.csv", rc.ReportID[:8]))
		if exportErr := exportAssetsCSV(w, r.Context(), st, rc); exportErr != nil {
			logger.Error("dashboard: export assets csv", "error", exportErr)
		}
	})

	mux.HandleFunc("GET /api/v1/software/export.csv", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=software_%s.csv", rc.ReportID[:8]))
		if exportErr := exportSoftwareCSV(w, r.Context(), st, rc); exportErr != nil {
			logger.Error("dashboard: export software csv", "error", exportErr)
		}
	})

	mux.HandleFunc("GET /api/v1/findings/export.csv", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=findings_%s.csv", rc.ReportID[:8]))
		if exportErr := exportFindingsCSV(w, r.Context(), st, rc); exportErr != nil {
			logger.Error("dashboard: export findings csv", "error", exportErr)
		}
	})

	// Scan status fragment — the #scan-status div re-fetches this every 3s
	// via HTMX, so the "Run Scan" button transitions through its
	// queued → running → completed states without a manual page reload.
	mux.HandleFunc("GET /fragments/scan-status", func(w http.ResponseWriter, r *http.Request) {
		renderFragment(w, "scan-status", func(buf io.Writer) error {
			return renderScanStatusFragment(buf, r.Context(), st, opts.Coordinator)
		})
	})

	// Scan controls fragment — renders the "Run Scan" button enabled or
	// disabled-with-tooltip depending on whether a coordinator is wired.
	// The index loads this once on page load.
	mux.HandleFunc("GET /fragments/scan-controls", func(w http.ResponseWriter, _ *http.Request) {
		renderFragment(w, "scan-controls", func(buf io.Writer) error {
			return renderScanControlsFragment(buf, opts.Coordinator != nil && opts.BaseConfig != nil)
		})
	})

	// Scan trigger endpoint. Delegates to the coordinator when one is
	// wired in; otherwise returns a read-only placeholder so the button
	// surfaces the right affordance.
	mux.HandleFunc("POST /api/v1/scan", func(w http.ResponseWriter, r *http.Request) {
		if opts.Coordinator == nil || opts.BaseConfig == nil {
			renderFragment(w, "scan-trigger-unavailable", func(buf io.Writer) error {
				return renderScanStatusFragment(buf, r.Context(), st, nil)
			})
			return
		}
		_, startErr := opts.Coordinator.Start(r.Context(), scan.StartRequest{
			Config:        opts.BaseConfig,
			TriggerSource: "api",
			TriggeredBy:   "dashboard",
		})
		if startErr != nil {
			// AlreadyRunningError is expected when the operator double-
			// clicks; fall through to the status fragment either way since
			// it will show "Scan running" for the in-flight scan.
			var already *scan.AlreadyRunningError
			if !errors.As(startErr, &already) {
				logger.Error("dashboard: scan trigger failed", "error", startErr)
			}
		} else {
			logger.Info("dashboard: scan triggered via UI")
		}
		renderFragment(w, "scan-status", func(buf io.Writer) error {
			return renderScanStatusFragment(buf, r.Context(), st, opts.Coordinator)
		})
	})

	// Tables browser — Datasette-style introspection.
	mux.HandleFunc("GET /fragments/tables", func(w http.ResponseWriter, r *http.Request) {
		renderFragment(w, "tables", func(buf io.Writer) error {
			return renderTablesFragment(buf, r.Context(), st, rc)
		})
	})

	mux.HandleFunc("GET /fragments/tables/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		limit, offset := parsePaging(r)
		renderFragment(w, "table", func(buf io.Writer) error {
			return renderTableFragment(buf, r.Context(), st, rc, name, limit, offset)
		})
	})

	mux.HandleFunc("GET /fragments/tables/{name}/row", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		pk := extractPKQuery(r)
		renderFragment(w, "row", func(buf io.Writer) error {
			return renderRowReportFragment(buf, r.Context(), st, name, pk)
		})
	})

	mux.HandleFunc("GET /api/v1/tables/{name}/export.csv", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_%s.csv", name, rc.ReportID[:8]))
		if exportErr := exportTableCSV(w, r.Context(), st, rc, name); exportErr != nil {
			logger.Error("dashboard: export table csv", "table", name, "error", exportErr)
			if errors.Is(exportErr, store.ErrUnknownTable) {
				http.Error(w, "unknown table", http.StatusNotFound)
			}
		}
	})

	// RFC-0112 onboarding surface: enroll -> check -> stream. The SQLite-
	// typed identity store is required; non-SQLite stores (a theoretical
	// future alternative) skip registration with a warning so the rest of
	// the dashboard keeps working.
	if sqliteStore, ok := st.(*sqlite.SQLiteStore); ok {
		wrapKey, keyErr := newOnboardingWrapKey()
		if keyErr != nil {
			logger.Warn("dashboard: onboarding disabled — no wrap key", "error", keyErr)
		} else {
			registerOnboardingRoutes(mux, onboardingDeps{
				Store:            sqliteStore,
				StreamCtrl:       opts.StreamController,
				Logger:           logger,
				WrapKey:          wrapKey,
				AppVersion:       opts.AppVersion,
				Commit:           opts.Commit,
				PlatformEndpoint: opts.PlatformEndpoint,
				ProbeDuration:    onboardingProbeDurationHistogram(),
			})
		}
	} else {
		logger.Warn("dashboard: onboarding disabled — store is not sqlite-backed")
	}

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// OpenBrowser attempts to open the given URL in the default browser.
// It uses platform-specific commands and silently ignores errors.
func OpenBrowser(url string) {
	openBrowser(url)
}

// parsePaging extracts limit/offset query parameters, clamping to the
// introspection row cap and defaulting to store.IntrospectionDefaultPageSize.
func parsePaging(r *http.Request) (limit, offset int) {
	limit = store.IntrospectionDefaultPageSize
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
			if limit > store.IntrospectionRowLimit {
				limit = store.IntrospectionRowLimit
			}
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

// extractPKQuery reads query parameters prefixed with "pk." and returns them
// as a primary-key map. A row URL is shaped as ?pk.id=...&pk.version=...
func extractPKQuery(r *http.Request) map[string]string {
	pk := map[string]string{}
	for k, vs := range r.URL.Query() {
		if strings.HasPrefix(k, "pk.") && len(vs) > 0 {
			pk[strings.TrimPrefix(k, "pk.")] = vs[0]
		}
	}
	return pk
}
