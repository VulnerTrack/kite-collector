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
	row := func(label, value string) error {
		if value == "" {
			return nil
		}
		_, err := fmt.Fprintf(out, "   %s  %s\n",
			style(enrollANSIMuted, fmt.Sprintf("%-13s", label)),
			style(enrollANSICyan, value),
		)
		return err
	}

	heading := style(enrollANSIBold+enrollANSIGreen, "✅  Enrollment complete.")
	if _, err := fmt.Fprintf(out, "\n%s\n", heading); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "   %s\n\n", style(enrollANSIBold, "Welcome to Kite! Your collector is connected to VulnerTrack.")); err != nil {
		return err
	}
	if err := row("Collector", details.agentCode); err != nil {
		return err
	}
	if err := row("Certificates", details.certsDir); err != nil {
		return err
	}
	if err := row("Service", enrollmentServiceStatus(details.serviceAction)); err != nil {
		return err
	}
	if err := row("Dashboard", strings.TrimRight(details.dashboardURL, "/")); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "\n   %s  %s\n\n",
		style(enrollANSIYellow, "Next step →"),
		style(enrollANSIBold, "kite-collector integrations"),
	)
	return err
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
