package main

import (
	"bytes"
	"errors"
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

// failingWriter fails every write and counts attempts.
type failingWriter struct{ writes int }

func (f *failingWriter) Write(p []byte) (int, error) {
	f.writes++
	return 0, errors.New("broken pipe")
}

// A closed stdout (`kite-collector enroll | head -1`) must surface as the first
// write error, wrapped, with no further writes attempted — the summary printer
// keeps a sticky error rather than plowing through every remaining line.
func TestPrintEnrollmentSuccessReturnsFirstWriteError(t *testing.T) {
	out := &failingWriter{}
	err := printEnrollmentSuccessStyled(out, enrollmentSuccessDetails{
		agentCode:     "kite-server",
		certsDir:      "/var/lib/kite-collector",
		serviceAction: "started",
	}, false)

	require.Error(t, err)
	assert.ErrorContains(t, err, "write enrollment summary")
	assert.ErrorContains(t, err, "broken pipe")
	assert.Equal(t, 1, out.writes, "writes stop after the first failure")
}
