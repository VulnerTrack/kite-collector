package dashboard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

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
	// Installer, when non-nil, enables POST /api/v1/agent/install to run a
	// real install from the dashboard. nil → the endpoint returns 503 with
	// a CLI hint, which is the safer production default for non-elevated
	// dashboards.
	Installer  Installer
	AppVersion string
	Commit     string
	// PlatformEndpoint is the collector's OTLP destination (sourced from
	// cfg.Streaming.OTLP.Endpoint). The onboarding Enroll form shows this as
	// read-only text and the connection-check probes dial this host. The
	// value is NOT persisted in enrolled_identity — see RFC-0112.
	PlatformEndpoint string
	// OAuth configures the first-party Supabase OAuth flow used by /kite-login.
	OAuth OAuthOptions
	// CertsDir is the PKI credential store populated after OAuth sign-in and
	// used by onboarding probes for mTLS.
	CertsDir string
	// FleetTokenIssuer mints per-computer, single-use PKI credentials for mass
	// deployment. nil uses the production PKI HTTP client.
	FleetTokenIssuer FleetEnrollmentTokenIssuer
	// FleetOperatorToken supplies the current operator OAuth credential. It is
	// injectable for non-browser embedding and tests; normal dashboards derive
	// it from the encrypted enrolled identity.
	FleetOperatorToken func(context.Context) (string, error)
	// TableSources are additional read-only table backends (e.g. a live
	// osqueryd) merged into the table catalog behind the durable store. The
	// dashboard's generic table machinery renders them identically to store
	// tables — it neither knows nor cares where a table comes from. On a
	// name collision the store wins.
	TableSources []store.TableSource
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
	// All table browsing goes through one source-agnostic catalog: the
	// durable store first, then any additional backends.
	tableSources := store.NewCompositeTableSource(
		append([]store.TableSource{st}, opts.TableSources...)...)
	fleetDiscovery := newFleetDiscoveryController()
	fleetPackages := &fleetPackageService{
		issuer: opts.FleetTokenIssuer, operatorToken: opts.FleetOperatorToken,
	}

	// Serve static files (embedded or from disk in dev mode).
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		logger.Error("dashboard: failed to create sub filesystem",
			"code", string(LogCodeServeStaticSubFS),
			"error", err)
	} else {
		mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
		// Browsers request /favicon.ico unprompted (address-bar,
		// bookmarks, non-HTML responses) — serve the VT mark there
		// too instead of a 404. The <link rel="icon"> tags in the
		// page heads point at the PNG variants under /static/img/.
		mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFileFS(w, r, staticSub, "img/favicon.ico")
		})
	}

	mux.HandleFunc("GET /kite-login", func(w http.ResponseWriter, r *http.Request) {
		serveKiteLoginPage(w, r, opts.OAuth, opts.AppVersion)
	})
	mux.HandleFunc("GET /kite-success", func(w http.ResponseWriter, r *http.Request) {
		serveKiteSuccessPage(w, r, opts.OAuth, opts.AppVersion)
	})
	mux.HandleFunc("GET /api/v1/enrollment/wait/{id}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, logger, http.StatusOK, map[string]bool{
			"complete": kiteOAuthWaitComplete(r.PathValue("id")),
		})
	})
	kiteOAuthEnrollment := kiteOAuthEnrollmentOptions{
		Logger:           logger,
		PlatformEndpoint: opts.PlatformEndpoint,
		CertsDir:         opts.CertsDir,
	}
	mux.HandleFunc("GET /oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		serveKiteOAuthCallbackPage(w, r, opts.OAuth, kiteOAuthEnrollment, opts.AppVersion)
	})

	// Dashboard root — context-aware redirect. Fresh hosts (no enrolled
	// identity) land on /onboarding so the operator sees the install/enroll
	// flow immediately instead of an empty /machines page. Once enrollment is
	// done the redirect flips to /machines, which is the steady-state home.
	// 307 preserves the request method on the off chance a non-GET client
	// hits "/".
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("code") || r.URL.Query().Has("state") {
			serveKiteOAuthCallbackPage(w, r, opts.OAuth, kiteOAuthEnrollment, opts.AppVersion)
			return
		}

		target := "/machines"
		if sqliteStore, ok := st.(*sqlite.SQLiteStore); ok {
			if _, err := sqliteStore.GetEnrolledIdentity(r.Context()); err != nil {
				// Any error (including ErrNoIdentity) → assume not yet onboarded
				// and surface the onboarding flow.
				target = "/onboarding"
			}
		}
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	})

	// renderFragment renders a template to a buffer first, then writes to
	// the response. This prevents "superfluous WriteHeader" when a template
	// error occurs after partial output has already been sent.
	renderFragment := func(w http.ResponseWriter, name string, render func(io.Writer) error) {
		var buf bytes.Buffer
		if renderErr := render(&buf); renderErr != nil {
			logger.Error("dashboard: render "+name,
				"code", string(LogCodeServeFragmentRender),
				"error", renderErr)
			http.Error(w, renderErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(buf.Bytes())
	}

	// serveTabRoute serves a top-level tab URL with two modes:
	//
	//   - HX-Request: true   → fragment-only (HTMX swaps it into #content)
	//   - bare GET           → full page shell with the fragment pre-
	//                          rendered into #content and the matching nav
	//                          link marked .active
	//
	// On a render error we still write a 500 — but the renderIndexPage
	// helper buffers the fragment first, so we never leak partial HTML.
	serveTabRoute := func(activeTab string, render func(io.Writer, context.Context) error) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("HX-Request") == "true" {
				renderFragment(w, activeTab, func(buf io.Writer) error {
					return render(buf, r.Context())
				})
				return
			}
			var buf bytes.Buffer
			if renderErr := renderIndexPage(&buf, activeTab, func(fragBuf io.Writer) error {
				return render(fragBuf, r.Context())
			}); renderErr != nil {
				logger.Error("dashboard: render page "+activeTab,
					"code", string(LogCodeServeTabPageRender),
					"error", renderErr)
				http.Error(w, renderErr.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(buf.Bytes())
		}
	}

	// Top-level pretty-URL routes. Each is the canonical URL for the
	// matching tab and is what nav links push into history. The existing
	// /fragments/* routes are kept (used by polling status divs and CSV
	// exports' Back-button paths).
	mux.HandleFunc("GET /machines", serveTabRoute("machines", func(w io.Writer, ctx context.Context) error {
		return renderMachinesFragment(w, ctx, st, rc)
	}))

	// Machine resource page — a machine is a page, not a drawer. ?tab picks
	// the related-resource tab; the ActiveTab stays "machines" so the nav
	// highlight is right when drilling in.
	mux.HandleFunc("GET /machines/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, parseErr := uuid.Parse(r.PathValue("id"))
		if parseErr != nil {
			http.NotFound(w, r)
			return
		}
		tab := r.URL.Query().Get("tab")
		render := func(buf io.Writer, ctx context.Context) error {
			return renderMachinePageFragment(buf, ctx, st, id, tab)
		}
		writeResult := func(renderErr error) bool {
			if renderErr == nil {
				return false
			}
			if errors.Is(renderErr, store.ErrNotFound) {
				http.NotFound(w, r)
				return true
			}
			logger.Error("dashboard: render machine page",
				"code", string(LogCodeServeTabPageRender),
				"machine_id", id.String(),
				"error", renderErr)
			http.Error(w, renderErr.Error(), http.StatusInternalServerError)
			return true
		}
		if r.Header.Get("HX-Request") == "true" {
			var buf bytes.Buffer
			if writeResult(render(&buf, r.Context())) {
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(buf.Bytes())
			return
		}
		var buf bytes.Buffer
		if writeResult(renderIndexPage(&buf, "machines", func(fragBuf io.Writer) error {
			return render(fragBuf, r.Context())
		})) {
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(buf.Bytes())
	})
	mux.HandleFunc("GET /software", serveTabRoute("software", func(w io.Writer, ctx context.Context) error {
		return renderSoftwareFragment(w, ctx, st, rc)
	}))
	mux.HandleFunc("GET /findings", serveTabRoute("findings", func(w io.Writer, ctx context.Context) error {
		return renderFindingsFragment(w, ctx, st, rc)
	}))
	mux.HandleFunc("GET /scans", serveTabRoute("scans", func(w io.Writer, ctx context.Context) error {
		return renderScansFragment(w, ctx, st, rc)
	}))
	mux.HandleFunc("GET /tables", serveTabRoute("tables", func(w io.Writer, ctx context.Context) error {
		return renderTablesFragment(w, ctx, tableSources, rc)
	}))
	mux.HandleFunc("GET /fleet", serveTabRoute("fleet", func(w io.Writer, ctx context.Context) error {
		return renderFleetDeploymentFragment(w, ctx, st, opts, fleetDiscovery)
	}))

	// Views — saved joins rendered as ordinary grids, plus the builder.
	mux.HandleFunc("GET /views/{slug}", func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		limit, offset := parsePaging(r)
		render := func(buf io.Writer, ctx context.Context) error {
			return renderViewFragment(buf, ctx, st, slug, limit, offset)
		}
		writeResult := func(renderErr error, buf *bytes.Buffer) bool {
			if renderErr == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(buf.Bytes())
				return true
			}
			if errors.Is(renderErr, store.ErrNotFound) {
				http.NotFound(w, r)
				return true
			}
			logger.Error("dashboard: render view page",
				"code", string(LogCodeServeTabPageRender),
				"view_slug", slug,
				"error", renderErr)
			http.Error(w, renderErr.Error(), http.StatusInternalServerError)
			return true
		}
		var buf bytes.Buffer
		if r.Header.Get("HX-Request") == "true" {
			writeResult(render(&buf, r.Context()), &buf)
			return
		}
		writeResult(renderIndexPage(&buf, "views:"+slug, func(fragBuf io.Writer) error {
			return render(fragBuf, r.Context())
		}), &buf)
	})

	mux.HandleFunc("GET /views/new", func(w http.ResponseWriter, r *http.Request) {
		render := func(buf io.Writer) error {
			return renderViewBuilderFragment(buf, r.Context(), st, builderSelection{}, "")
		}
		if r.Header.Get("HX-Request") == "true" {
			renderFragment(w, "view-builder", render)
			return
		}
		var buf bytes.Buffer
		if renderErr := renderIndexPage(&buf, "views-new", render); renderErr != nil {
			logger.Error("dashboard: render view builder page",
				"code", string(LogCodeServeTabPageRender),
				"error", renderErr)
			http.Error(w, renderErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(buf.Bytes())
	})

	// Builder re-render on every form change (server-driven form).
	mux.HandleFunc("POST /fragments/views/builder", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		sel := parseBuilderForm(r.PostForm)
		renderFragment(w, "view-builder", func(buf io.Writer) error {
			return renderViewBuilderFragment(buf, r.Context(), st, sel, "")
		})
	})

	// Save a builder selection as a named view. Success redirects (via
	// HX-Redirect for HTMX callers) to the new view; validation problems
	// re-render the builder inline with the error.
	mux.HandleFunc("POST /api/v1/views", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		sel := parseBuilderForm(r.PostForm)
		slug, saveErr := saveViewFromSelection(r.Context(), st, sel)
		if saveErr == nil {
			// slug comes from slugifyViewName, so it is [a-z0-9-] only; the
			// escape keeps the redirect target a single trusted path segment.
			target := "/views/" + url.PathEscape(slug)
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Redirect", target)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			http.Redirect(w, r, target, http.StatusSeeOther) // #nosec G710 -- server-generated slug, path-escaped, site-relative target
			return
		}
		message := saveErr.Error()
		if !errors.Is(saveErr, errViewValidation) {
			if sqlite.ErrIsUniqueViolation(saveErr) {
				message = "a view with that name already exists"
			} else {
				logger.Error("dashboard: save view",
					"code", string(LogCodeServeFragmentRender),
					"error", saveErr)
				message = "could not save the view"
			}
		}
		renderFragment(w, "view-builder", func(buf io.Writer) error {
			return renderViewBuilderFragment(buf, r.Context(), st, sel, message)
		})
	})

	// Docs — copy-paste snippets that hand an external AI agent (or any
	// script) read-only access to kite's data. Registered outside
	// serveTabRoute because the curl examples embed the request's Host so
	// they work as pasted.
	mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
		render := func(buf io.Writer) error { return renderDocsFragment(buf, r.Host) }
		if r.Header.Get("HX-Request") == "true" {
			renderFragment(w, "docs", render)
			return
		}
		var buf bytes.Buffer
		if renderErr := renderIndexPage(&buf, "docs", render); renderErr != nil {
			logger.Error("dashboard: render page docs",
				"code", string(LogCodeServeTabPageRender),
				"error", renderErr)
			http.Error(w, renderErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(buf.Bytes())
	})

	// Containers page — live Docker/compose observability. The engine host
	// honors the docker discovery source's configured host when one is set;
	// otherwise the controller autodetects (KITE_DOCKER_HOST → sockets).
	dockerHost := ""
	if opts.BaseConfig != nil {
		if src, ok := opts.BaseConfig.Discovery.Sources["docker"]; ok {
			dockerHost = src.Host
		}
	}
	registerContainerRoutes(mux, newContainersController(dockerHost, logger), logger)
	mux.HandleFunc("POST /api/v1/fleet/discover", func(w http.ResponseWriter, r *http.Request) {
		handleFleetDiscovery(w, r, st, logger, fleetDiscovery)
	})
	mux.HandleFunc("GET /api/v1/fleet/discover", func(w http.ResponseWriter, r *http.Request) {
		handleFleetDiscoveryResults(w, r, st, fleetDiscovery)
	})
	mux.HandleFunc("POST /api/v1/fleet/package", func(w http.ResponseWriter, r *http.Request) {
		handleFleetPackage(w, r, logger, opts, fleetPackages)
	})

	// /tables/{name} mirrors the per-tab pattern. Same HX-Request branch
	// (fragment-only) vs. plain GET (full shell) split, with ActiveTab
	// pinned to "tables" so the nav highlight stays correct when the user
	// drills into a specific table.
	mux.HandleFunc("GET /tables/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		limit, offset := parsePaging(r)
		filterCol, filterVal, filtered := parseFacetFilter(r)
		render := func(buf io.Writer, ctx context.Context) error {
			return renderTableFragment(buf, ctx, tableSources, rc, name, limit, offset, filterCol, filterVal, filtered)
		}
		if r.Header.Get("HX-Request") == "true" {
			renderFragment(w, "table", func(buf io.Writer) error {
				return render(buf, r.Context())
			})
			return
		}
		var buf bytes.Buffer
		if renderErr := renderIndexPage(&buf, "tables", func(fragBuf io.Writer) error {
			return render(fragBuf, r.Context())
		}); renderErr != nil {
			logger.Error("dashboard: render page tables/"+name,
				"code", string(LogCodeServeTablePageRender),
				"error", renderErr)
			http.Error(w, renderErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(buf.Bytes())
	})

	// HTMX fragment endpoints — return HTML snippets for dynamic loading.
	mux.HandleFunc("GET /fragments/machines", func(w http.ResponseWriter, r *http.Request) {
		renderFragment(w, "machines", func(buf io.Writer) error {
			return renderMachinesFragment(buf, r.Context(), st, rc)
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
	mux.HandleFunc("GET /api/v1/machines/export.csv", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=machines_%s.csv", rc.ReportID[:8]))
		if exportErr := exportMachinesCSV(w, r.Context(), st, rc); exportErr != nil {
			logger.Error("dashboard: export machines csv",
				"code", string(LogCodeExportMachinesCSV),
				"error", exportErr)
		}
	})

	mux.HandleFunc("GET /api/v1/software/export.csv", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=software_%s.csv", rc.ReportID[:8]))
		if exportErr := exportSoftwareCSV(w, r.Context(), st, rc); exportErr != nil {
			logger.Error("dashboard: export software csv",
				"code", string(LogCodeExportSoftwareCSV),
				"error", exportErr)
		}
	})

	mux.HandleFunc("GET /api/v1/findings/export.csv", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=findings_%s.csv", rc.ReportID[:8]))
		if exportErr := exportFindingsCSV(w, r.Context(), st, rc); exportErr != nil {
			logger.Error("dashboard: export findings csv",
				"code", string(LogCodeExportFindingsCSV),
				"error", exportErr)
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
				logger.Error("dashboard: scan trigger failed",
					"code", string(LogCodeScanTrigger),
					"error", startErr)
			}
		} else {
			logger.Info("dashboard: scan triggered via UI")
		}
		renderFragment(w, "scan-status", func(buf io.Writer) error {
			return renderScanStatusFragment(buf, r.Context(), st, opts.Coordinator)
		})
	})

	// Sidebar resource tree — the counted variant HTMX swaps in over the
	// static tree baked into the shell. Loaded lazily so the shell renders
	// fast and counts reflect whatever the most recent scan inserted.
	// ?active carries the shell's ActiveTab so the swap keeps the right
	// link highlighted.
	mux.HandleFunc("GET /fragments/sidebar-tree", func(w http.ResponseWriter, r *http.Request) {
		active := r.URL.Query().Get("active")
		renderFragment(w, "sidebar-tree", func(buf io.Writer) error {
			return renderSidebarTreeFragment(buf, r.Context(), st, tableSources, active)
		})
	})

	// Tables browser — Datasette-style introspection.
	mux.HandleFunc("GET /fragments/tables", func(w http.ResponseWriter, r *http.Request) {
		renderFragment(w, "tables", func(buf io.Writer) error {
			return renderTablesFragment(buf, r.Context(), tableSources, rc)
		})
	})

	mux.HandleFunc("GET /fragments/tables/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		limit, offset := parsePaging(r)
		filterCol, filterVal, filtered := parseFacetFilter(r)
		renderFragment(w, "table", func(buf io.Writer) error {
			return renderTableFragment(buf, r.Context(), tableSources, rc, name, limit, offset, filterCol, filterVal, filtered)
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
		if exportErr := exportTableCSV(w, r.Context(), tableSources, rc, name); exportErr != nil {
			logger.Error("dashboard: export table csv",
				"code", string(LogCodeExportTableCSV),
				"table", name, "error", exportErr)
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
			logger.Warn("dashboard: onboarding disabled — no wrap key",
				"code", string(LogCodeOnboardingDisabledNoWrapKey),
				"error", keyErr)
		} else {
			operatorToken := fleetPackages.operatorToken
			if operatorToken == nil {
				operatorToken = func(ctx context.Context) (string, error) {
					identity, identityErr := sqliteStore.GetEnrolledIdentity(ctx)
					if identityErr != nil {
						return "", fmt.Errorf("sign in to VulnerTrack before loading PKI data")
					}
					plaintext, unwrapErr := sqlite.AEADUnwrap(wrapKey, identity.ApiKeyWrapped)
					if unwrapErr != nil {
						return "", fmt.Errorf("VulnerTrack session is unavailable; sign in again")
					}
					token := strings.TrimSpace(string(plaintext))
					if token == "" {
						return "", fmt.Errorf("VulnerTrack session is unavailable; sign in again")
					}
					return token, nil
				}
				fleetPackages.operatorToken = operatorToken
			}
			var tlsCfg config.TLSConfig
			if opts.BaseConfig != nil {
				tlsCfg = opts.BaseConfig.Streaming.OTLP.TLS
			}
			registerOnboardingRoutes(mux, onboardingDeps{
				Store:            sqliteStore,
				StreamCtrl:       opts.StreamController,
				Logger:           logger,
				WrapKey:          wrapKey,
				AppVersion:       opts.AppVersion,
				Commit:           opts.Commit,
				PlatformEndpoint: opts.PlatformEndpoint,
				CertsDir:         opts.CertsDir,
				ProbeDuration:    onboardingProbeDurationHistogram(),
				PKIReader:        newPKIHTTPCertificateReader(),
				PKIOperatorToken: operatorToken,
				Installer:        opts.Installer,
				ScanEnabled:      opts.Coordinator != nil && opts.BaseConfig != nil,
				TLSConfig:        tlsCfg,
				OAuth:            opts.OAuth,
				PKIEndpoint:      resolveFleetPKIEndpoint(),
			})
			kiteOAuthEnrollment.Store = sqliteStore
			kiteOAuthEnrollment.WrapKey = wrapKey
		}
	} else {
		logger.Warn("dashboard: onboarding disabled — store is not sqlite-backed",
			"code", string(LogCodeOnboardingDisabledNoSQLite))
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
// parseFacetFilter reads the facet filter from the query string. fcol names
// the column; fval is the value ("" selects the NULL-or-empty bucket). The
// filter is active whenever fcol is present, so an empty fval still filters.
func parseFacetFilter(r *http.Request) (col, val string, filtered bool) {
	q := r.URL.Query()
	if !q.Has("fcol") {
		return "", "", false
	}
	col = q.Get("fcol")
	if col == "" {
		return "", "", false
	}
	return col, q.Get("fval"), true
}

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
