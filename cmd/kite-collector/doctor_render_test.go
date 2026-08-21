package main

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestRenderDoctorChecks_MarksEveryStatusAndHints(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	renderDoctorChecks(cmd, []doctorCheck{
		{Name: "service", Status: doctorPass, Detail: "running"},
		{
			Name: "config", Status: doctorWarn, Detail: "using defaults",
			Hint: "create kite-collector.yaml",
		},
		{
			Name: "certificates", Status: doctorFail, Detail: "agent.pem missing",
			Hint: "run kite-collector enroll",
		},
		{Name: "otlp-ping", Status: doctorSkip, Detail: "not reached (earlier stage failed)"},
	})

	out := buf.String()
	assert.Contains(t, out, "✔ pass")
	assert.Contains(t, out, "! warn")
	assert.Contains(t, out, "✖ fail")
	assert.Contains(t, out, "- skip")
	assert.Contains(t, out, "service")
	assert.Contains(t, out, "running")
	assert.Contains(t, out, "↳ create kite-collector.yaml")
	assert.Contains(t, out, "↳ run kite-collector enroll")
	assert.Contains(t, out, "not reached (earlier stage failed)")
}

func TestRenderDoctorChecks_NoHintOmitsArrowLine(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	renderDoctorChecks(cmd, []doctorCheck{
		{Name: "database", Status: doctorPass, Detail: "1.5 KB"},
	})

	assert.NotContains(t, buf.String(), "↳")
}
