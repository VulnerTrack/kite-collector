package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// TestParseSetupArgs_RecognizedSwitches covers the vocabulary SCCM/Intune/GPO
// packages actually emit (RFC-0156 R13).
func TestParseSetupArgs_RecognizedSwitches(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want setupArgs
	}{
		{
			name: "silent",
			argv: []string{"/SILENT"},
			want: setupArgs{Silent: true},
		},
		{
			name: "very silent implies silent",
			argv: []string{"/VERYSILENT"},
			want: setupArgs{Silent: true, VerySilent: true},
		},
		{
			name: "lowercase is accepted",
			argv: []string{"/silent"},
			want: setupArgs{Silent: true},
		},
		{
			name: "posix spelling",
			argv: []string{"--unattended"},
			want: setupArgs{Silent: true},
		},
		{
			name: "dir with quotes stripped",
			argv: []string{"/SILENT", `/DIR="C:\Program Files\Kite Collector"`},
			want: setupArgs{Silent: true, InstallDir: `C:\Program Files\Kite Collector`},
		},
		{
			name: "log destination",
			argv: []string{"/VERYSILENT", `/LOG=C:\temp\kite.log`},
			want: setupArgs{
				Silent:     true,
				VerySilent: true,
				LogPath:    `C:\temp\kite.log`,
			},
		},
		{
			name: "noise switches are tolerated",
			argv: []string{"/SILENT", "/NORESTART", "/SUPPRESSMSGBOXES"},
			want: setupArgs{Silent: true},
		},
		{
			name: "help",
			argv: []string{"/?"},
			want: setupArgs{Help: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSetupArgs(tc.argv)
			require.True(t, ok, "must be recognized as a setup command line")
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestParseSetupArgs_FallsThroughToCLI is the safety property. An elevated
// binary that mistook `kite-collector install --user` for an unattended setup
// invocation would silently do the wrong privileged thing, so recognition is
// all-or-nothing: one unknown token and the whole command line goes to cobra.
func TestParseSetupArgs_FallsThroughToCLI(t *testing.T) {
	for _, argv := range [][]string{
		{},
		{"install"},
		{"install", "--user"},
		{"service", "status"},
		{"/SILENT", "install"},
		{"/SILENT", "--certs-dir", "/tmp/x"},
		{"/DIR"},
		{"/DIR="},
		{"/LOG="},
		{"/UNKNOWNSWITCH"},
	} {
		_, ok := parseSetupArgs(argv)
		assert.False(t, ok, "argv %v must fall through to the CLI parser", argv)
	}
}

func TestParseSetupArgs_IgnoresBlankTokens(t *testing.T) {
	got, ok := parseSetupArgs([]string{"", "  ", "/SILENT"})
	require.True(t, ok)
	assert.True(t, got.Silent)
}

func TestSplitSetupToken(t *testing.T) {
	name, value, hasValue := splitSetupToken("/SILENT")
	assert.Equal(t, "/SILENT", name)
	assert.Empty(t, value)
	assert.False(t, hasValue)

	name, value, hasValue = splitSetupToken(`/DIR="C:\x=y"`)
	assert.Equal(t, "/DIR", name)
	assert.Equal(t, `C:\x=y`, value, "only the first = separates name from value")
	assert.True(t, hasValue)
}

// TestRealInstaller_OptionalSinksDefaultToNil pins the property the dashboard
// depends on: the install path it drives must stay exactly as silent as it was
// before the wizard/unattended flows started passing a log and a writer.
func TestRealInstaller_OptionalSinksDefaultToNil(t *testing.T) {
	plain := newRealInstaller()
	assert.Nil(t, plain.log, "dashboard install must not open an install log")
	assert.Nil(t, plain.out, "dashboard install must not narrate to a writer")

	var buf bytes.Buffer
	wired := newRealInstallerWithLog(nil, &buf)
	assert.NotNil(t, wired.out)
}

func TestSetupVariant_MatchesBuildTag(t *testing.T) {
	want := "plain"
	if installer.BundleAvailable() {
		want = "osquery_bundle"
	}
	assert.Equal(t, want, setupVariant(),
		"the reported variant is the build tag, never a runtime toggle")
}

func TestSetupUsage_DocumentsEverySwitch(t *testing.T) {
	usage := setupUsage()
	for _, sw := range []string{
		"/SILENT", "/VERYSILENT", "/DIR=", "/LOG=",
		"/NORESTART", "/SUPPRESSMSGBOXES", "/HELP",
	} {
		assert.Contains(t, usage, sw, "usage must document %s", sw)
	}
}
