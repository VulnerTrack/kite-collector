package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintEnrollmentSuccessPlain(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, printEnrollmentSuccess(&out, enrollmentSuccessDetails{
		agentCode:     "kite-server",
		certsDir:      "/var/lib/kite-collector",
		serviceAction: "started",
	}))

	text := out.String()
	assert.Contains(t, text, "✅  Enrollment complete.")
	assert.Contains(t, text, "Welcome to Kite! Your collector is connected to VulnerTrack.")
	assert.Contains(t, text, "Collector      kite-server")
	assert.Contains(t, text, "Certificates   /var/lib/kite-collector")
	assert.Contains(t, text, "Service        Started")
	assert.Contains(t, text, "Next step →  kite-collector integrations")
	assert.NotContains(t, text, "\x1b[")
}

func TestPrintEnrollmentSuccessUsesColorWhenEnabled(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, printEnrollmentSuccessStyled(&out, enrollmentSuccessDetails{
		serviceAction: "restarted",
		dashboardURL:  "http://127.0.0.1:9090/",
	}, true))

	text := out.String()
	assert.Contains(t, text, enrollANSIGreen)
	assert.Contains(t, text, enrollANSICyan)
	assert.Contains(t, text, enrollANSIYellow)
	assert.Contains(t, text, "Restarted with the new credentials")
	assert.Contains(t, text, "http://127.0.0.1:9090")
	assert.NotContains(t, text, "http://127.0.0.1:9090/")
}
