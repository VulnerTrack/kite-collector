package main

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// brandANSI styles the Vulnertrack wordmark with a navy background and bright
// white bold text. xterm-256 color 17 is a near match for the brand
// `--vt-navy-900` (#1a1a2e) used in the dashboard CSS.
const brandANSI = "\x1b[1;97;48;5;17m Vulnertrack \x1b[0m"

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
