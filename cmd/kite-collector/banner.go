package main

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// Vulnertrack brand: primary red #ff3131 on contrast text #f5f5f5.
// Source of truth: internal/dashboard/static/style.css palette tokens.
//
// brandANSI styles the Vulnertrack wordmark with the brand-red background
// (--palette-primary-main) and the brand contrast-text foreground
// (--palette-primary-contrastText), bold. We use 24-bit truecolor escapes
// (CSI 38;2;R;G;B / 48;2;R;G;B) which are supported by every modern
// terminal; the no-color / non-tty branch in printBrandBanner covers the
// rest.
const brandANSI = "\x1b[1;38;2;245;245;245;48;2;255;49;49m Vulnertrack \x1b[0m"

// printBrandBanner prints a two-line startup banner identifying the build and
// crediting Vulnertrack. The Vulnertrack wordmark is rendered with ANSI
// styling on TTYs that opt into color, and as plain text elsewhere.
//
// Color is suppressed when:
//   - w is not a writable file descriptor (test buffers, pipes, files)
//   - os.Stderr is not a terminal
//   - the NO_COLOR environment variable is set (per https://no-color.org)
func printBrandBanner(w io.Writer, version, commit string) {
	// Banner writes are best-effort UX — a failed write to stderr is not
	// actionable from this call site, so the errors are intentionally
	// discarded.
	_, _ = fmt.Fprintf(w, "kite-collector v%s (%s)\n", version, commit)

	if useColor(w) {
		_, _ = fmt.Fprintf(w, "Powered by%s— https://vulnertrack.com\n", brandANSI)
		return
	}
	_, _ = fmt.Fprintln(w, "Powered by Vulnertrack — https://vulnertrack.com")
}

// useColor returns true when ANSI styling is appropriate for w. We require
// both that w is a TTY-backed *os.File and that os.Stderr is a TTY (the
// banner is a UX surface, not a structured stream — if either is redirected
// we play it safe). NO_COLOR always wins.
func useColor(w io.Writer) bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	if !term.IsTerminal(int(f.Fd())) { //#nosec G115 -- *os.File.Fd() is a kernel fd, fits in int on every supported platform
		return false
	}
	return term.IsTerminal(int(os.Stderr.Fd())) //#nosec G115 -- same as above
}
