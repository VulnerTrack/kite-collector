package main

import (
	"fmt"
	"io"
	"strings"
)

const (
	enrollANSIReset  = "\x1b[0m"
	enrollANSIBold   = "\x1b[1m"
	enrollANSIGreen  = "\x1b[38;2;34;197;94m"
	enrollANSICyan   = "\x1b[38;2;56;189;248m"
	enrollANSIYellow = "\x1b[38;2;250;204;21m"
	enrollANSIMuted  = "\x1b[38;2;148;163;184m"
)

type enrollmentSuccessDetails struct {
	agentCode     string
	certsDir      string
	serviceAction string
	dashboardURL  string
}

func printEnrollmentSuccess(out io.Writer, details enrollmentSuccessDetails) error {
	return printEnrollmentSuccessStyled(out, details, useColor(out))
}

func printEnrollmentSuccessStyled(out io.Writer, details enrollmentSuccessDetails, color bool) error {
	style := func(code, value string) string {
		if !color {
			return value
		}
		return code + value + enrollANSIReset
	}
	w := &enrollWriter{out: out}
	row := func(label, value string) {
		if value == "" {
			return
		}
		w.printf("   %s  %s\n",
			style(enrollANSIMuted, fmt.Sprintf("%-13s", label)),
			style(enrollANSICyan, value),
		)
	}

	w.printf("\n%s\n", style(enrollANSIBold+enrollANSIGreen, "✅  Enrollment complete."))
	w.printf("   %s\n\n", style(enrollANSIBold, "Welcome to Kite! Your collector is connected to VulnerTrack."))
	row("Collector", details.agentCode)
	row("Certificates", details.certsDir)
	row("Service", enrollmentServiceStatus(details.serviceAction))
	row("Dashboard", strings.TrimRight(details.dashboardURL, "/"))
	w.printf("\n   %s  %s\n\n",
		style(enrollANSIYellow, "Next step →"),
		style(enrollANSIBold, "kite-collector integrations"),
	)
	return w.err
}

// enrollWriter is a sticky-error writer: the first failed write is kept and
// every later printf is a no-op. The summary then reads as the sequence of
// lines it is, instead of six identical "if write failed, return" branches,
// and the caller still sees the first write error.
type enrollWriter struct {
	out io.Writer
	err error
}

func (w *enrollWriter) printf(format string, args ...any) {
	if w.err != nil {
		return
	}
	if _, err := fmt.Fprintf(w.out, format, args...); err != nil {
		w.err = fmt.Errorf("write enrollment summary: %w", err)
	}
}

func enrollmentServiceStatus(action string) string {
	switch action {
	case "started":
		return "Started"
	case "restarted":
		return "Restarted with the new credentials"
	case "":
		return "Credentials saved; service not installed"
	default:
		return action
	}
}
