package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// dashboardLaunchInfo bundles everything the orientation banner needs to
// surface to the operator before the browser opens. Kept as a struct so
// the calling code reads as one assignment rather than a long arg list.
//
// State carries the probed install state so the banner can adapt its
// content: first-time operators see "will install at <paths>"; repeat
// operators see "installed at <path>, service running" — same real estate,
// different value per situation. Tests inject State directly; production
// callers populate it via installer.Probe.
type dashboardLaunchInfo struct {
	Addr          string
	DB            string
	CertsDir      string
	State         installer.State
	EnableInstall bool
	WithAgent     bool
	NoBrowser     bool
}

// printDashboardLaunchBanner writes the orientation banner the dashboard
// subcommand prints right after the brand banner. The content adapts to
// the operator's actual install state:
//
//   - First-time operator (binary not present) → orientation: shows where
//     install would write so they know what the install button will do.
//   - Repeat operator (binary present) → status report: shows that
//     everything is already installed and where, plus service state. They
//     came back to check on an existing install, not to onboard from
//     scratch.
//
// Printed to the supplied writer (stderr in the caller) so it doesn't
// interleave with structured JSON logs on stdout.
func printDashboardLaunchBanner(w io.Writer, info dashboardLaunchInfo) {
	d := installer.DetectDefaults()
	mode := "inspector (read-only)"
	switch {
	case info.WithAgent:
		mode = "agent (full stack: scan + OTLP + install)"
	case info.EnableInstall:
		mode = "inspector + install (advisory + writable install API)"
	}

	border := strings.Repeat("─", 64)
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, border)
	_, _ = fmt.Fprintln(w, "  Kite Collector Dashboard")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "  → Open in browser:  http://%s\n", info.Addr)
	if info.NoBrowser {
		_, _ = fmt.Fprintln(w, "    (browser auto-open disabled by --no-browser)")
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "  Mode:               %s\n", mode)
	_, _ = fmt.Fprintf(w, "  Detected host:      %s/%s%s\n",
		d.Detected.OS, d.Detected.Arch, privilegeSuffix(d.Detected.Privileged))

	// State-adaptive section: first-run gets orientation copy ("will install
	// at..."), repeat-run gets a status report ("installed at..., service
	// running"). The banner's value proposition is different per case but the
	// real estate stays consistent so operators learn one shape.
	if info.WithAgent || info.EnableInstall {
		_, _ = fmt.Fprintln(w)
		if info.State.BinaryPresent {
			_, _ = fmt.Fprintln(w, "  Install status:")
			_, _ = fmt.Fprintf(w, "    binary  ✓ %s\n", info.State.BinaryPath)
			_, _ = fmt.Fprintf(w, "    certs   %s %s\n", stateGlyph(info.State.CertsDirExists), info.State.CertsDir)
			_, _ = fmt.Fprintf(w, "    enroll  %s %s\n", stateGlyph(info.State.CertsEnrolled), enrollmentSummary(info.State))
			_, _ = fmt.Fprintf(w, "    service %s\n", info.State.ServiceState)
			if info.State.NextAction != "" && info.State.NextAction != installer.ActionReady {
				_, _ = fmt.Fprintf(w, "    next    → %s (see /onboarding)\n", info.State.NextAction)
			}
		} else {
			_, _ = fmt.Fprintln(w, "  Install would target:")
			_, _ = fmt.Fprintf(w, "    binary  → %s\n", d.Options.BinaryPath())
			_, _ = fmt.Fprintf(w, "    certs   → %s\n", d.Options.CertsDir)
		}
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "  Database:           %s\n", info.DB)
	if info.CertsDir != "" && info.CertsDir != d.Options.CertsDir {
		_, _ = fmt.Fprintf(w, "  Certs (override):   %s\n", info.CertsDir)
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "  Press Ctrl+C to stop.")
	_, _ = fmt.Fprintln(w, border)
	_, _ = fmt.Fprintln(w)
}

// stateGlyph maps a bool to a one-char status glyph: ✓ for present, ✗ for
// missing. Surfaces presence/absence in the install status block without
// adding word-noise to each line.
func stateGlyph(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}

// enrollmentSummary returns the per-row label for the "enroll" line in the
// status report. Mirrors the cmd-layer enrollmentLabel helper but kept
// banner-scoped so the banner can evolve without touching install.go.
func enrollmentSummary(st installer.State) string {
	switch {
	case st.CertsEnrolled:
		return "agent.pem + ca.pem + agent-key.pem present"
	case st.CertsDirExists:
		return "(empty — run `enroll` to populate)"
	default:
		return "(certs dir missing)"
	}
}

// privilegeSuffix returns the parenthesized privilege hint appended to the
// "Detected host:" line. Empty when privileges are absent so the line stays
// uncluttered on the (more common) non-privileged dev case.
func privilegeSuffix(priv bool) string {
	if priv {
		return " (privileged)"
	}
	return " (non-privileged — system install may fail; prefer --user mode)"
}
