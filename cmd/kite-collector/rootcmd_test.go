package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
)

func TestNewRootCmd_RegistersExpectedCommands(t *testing.T) {
	root := newRootCmd()
	assert.Equal(t, "kite-collector", root.Name())

	names := map[string]bool{}
	for _, c := range root.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{
		"scan", "agent", "status", "doctor", "stream", "diff", "report",
		"discover-services", "storage-fingerprint", "web-fingerprint",
		"query", "db", "migrate", "dashboard", "version", "error",
		"enroll", "unenroll", "endpoints", "trust", "check-otlp", "fleet",
		"install", "uninstall", "service",
	} {
		assert.True(t, names[want], "root must register %q", want)
	}
}

func TestRootHelp_AppendsCurrentStateBlock(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"--help"})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)

	require.NoError(t, root.Execute())

	out := buf.String()
	assert.Contains(t, out, "Available Commands:")
	assert.Contains(t, out, "Current state:")
	assert.Contains(t, out, "config file:     kite-collector.yaml")
	assert.Contains(t, out, "enrollment:")
}

func TestSubcommandHelp_OmitsCurrentStateBlock(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"version", "--help"})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)

	require.NoError(t, root.Execute())

	assert.NotContains(t, buf.String(), "Current state:",
		"the live state block belongs to the root help only")
}

func TestVersionCommand_PrintsBuildAndSchemaInfo(t *testing.T) {
	out := captureStdout(t, func() {
		root := newRootCmd()
		root.SetArgs([]string{"version"})
		require.NoError(t, root.Execute())
	})

	assert.Contains(t, out, "kite-collector dev")
	assert.Contains(t, out, "commit:  none")
	assert.Contains(t, out, "built:   unknown")
	assert.Contains(t, out, "go:      go1.")
	assert.Contains(t, out, "os/arch: linux/")
	assert.Contains(t, out, "schema:  v")
	assert.Contains(t, out, "migrations embedded)")
}

func TestErrorCommand_NoArgsListsKnownCodes(t *testing.T) {
	codes := kiteerrors.Codes()
	require.NotEmpty(t, codes, "the error catalogue must not be empty")

	out := captureStdout(t, func() {
		root := newRootCmd()
		root.SetArgs([]string{"error"})
		root.SetErr(&bytes.Buffer{})
		require.NoError(t, root.Execute())
	})

	assert.Contains(t, out, "Usage: kite-collector error <code>")
	assert.Contains(t, out, "Known error codes:")
	for _, code := range codes {
		assert.Contains(t, out, code)
	}
}

func TestErrorCommand_ListFlagAndLookup(t *testing.T) {
	codes := kiteerrors.Codes()
	require.NotEmpty(t, codes)
	first := codes[0]

	listOut := captureStdout(t, func() {
		root := newRootCmd()
		root.SetArgs([]string{"error", "--list"})
		root.SetErr(&bytes.Buffer{})
		require.NoError(t, root.Execute())
	})
	assert.Contains(t, listOut, first)
	assert.NotContains(t, listOut, "Usage: kite-collector error <code>")

	lookupOut := captureStdout(t, func() {
		root := newRootCmd()
		root.SetArgs([]string{"error", first})
		root.SetErr(&bytes.Buffer{})
		require.NoError(t, root.Execute())
	})
	assert.Contains(t, lookupOut, first)
}

func TestErrorCommand_UnknownCodeFails(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"error", "KITE-E999999"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})

	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown error code: KITE-E999999")
}
