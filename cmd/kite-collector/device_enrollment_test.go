package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/enrollment"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

func TestSSHEnrollmentUsesDeviceFlowEvenWithDisplay(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "remote session")
	t.Setenv("DISPLAY", ":0")
	called := false
	cmd := newEnrollCmdWithDevice(func(_ io.Writer, code, db, certs string, user bool) error {
		called = true
		require.Equal(t, "kite-server", code)
		require.Equal(t, "/tmp/ssh-certs", certs)
		return nil
	})
	cmd.SetArgs([]string{"--agent-code", "kite-server", "--certs-dir", "/tmp/ssh-certs"})
	require.NoError(t, cmd.Execute())
	require.True(t, called)
}

func TestNoBrowserEnrollmentDoesNotNeedStdin(t *testing.T) {
	called := false
	cmd := newEnrollCmdWithDevice(func(_ io.Writer, _, _, _ string, _ bool) error { called = true; return nil })
	cmd.SetArgs([]string{"--no-browser"})
	require.NoError(t, cmd.Execute())
	require.True(t, called)
}

func TestDeviceEnrollmentPersistsCertificateIdentityBeforeServiceStart(t *testing.T) {
	root := t.TempDir()
	db := filepath.Join(root, "kite.db")
	started := false
	err := runDeviceEnrollmentWithDeps(io.Discard, "kite-server", db, root, false,
		func(context.Context, string, func(enrollment.DeviceAuthorization) error) (*enrollment.Result, error) {
			return &enrollment.Result{Status: "enrolled", CACertificate: []byte("ca"), ClientCertificate: []byte("certificate"), ClientKey: []byte("private-key")}, nil
		}, func(bool) (string, error) {
			cert, err := os.ReadFile(filepath.Join(root, "agent.pem"))
			require.NoError(t, err)
			require.Equal(t, "certificate", string(cert))
			started = true
			return "started", nil
		})
	require.NoError(t, err)
	require.True(t, started)
	st, err := openSQLiteStore(db, config.IdentityConfig{})
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	record, err := st.Store.(*sqlite.SQLiteStore).GetEnrolledIdentity(context.Background())
	require.NoError(t, err)
	require.Contains(t, record.ApiKeyFingerprint, "certificate:")
	require.Empty(t, record.ApiKeyWrapped, "consumed device tokens must not be saved")
}

func TestFailedDeviceEnrollmentDoesNotMarkLocalIdentityOrStartService(t *testing.T) {
	root := t.TempDir()
	db := filepath.Join(root, "kite.db")
	err := runDeviceEnrollmentWithDeps(io.Discard, "kite-server", db, root, false,
		func(context.Context, string, func(enrollment.DeviceAuthorization) error) (*enrollment.Result, error) {
			return nil, errors.New("denied")
		},
		func(bool) (string, error) { t.Fatal("must not start service"); return "", nil })
	require.ErrorContains(t, err, "denied")
	st, err := openSQLiteStore(db, config.IdentityConfig{})
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	_, err = st.Store.(*sqlite.SQLiteStore).GetEnrolledIdentity(context.Background())
	require.ErrorIs(t, err, sqlite.ErrNoIdentity)
}

func TestNonInteractiveEnrollmentUsesDeviceFlowLocallyAndOverSSH(t *testing.T) {
	for _, sshVar := range []string{"", "SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		t.Run(sshVar, func(t *testing.T) {
			for _, name := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
				t.Setenv(name, "")
			}
			t.Setenv("DISPLAY", ":0")
			if sshVar != "" {
				t.Setenv(sshVar, "remote-session")
			}
			device, browser := false, false
			cmd := newEnrollCmdWithFlows(func(_ io.Writer, _, _, _ string, _ bool) error { device = true; return nil }, func(_, _, _ string, _, _ bool) error { browser = true; return nil })
			cmd.SetArgs([]string{})
			require.NoError(t, cmd.Execute())
			require.True(t, device)
			require.False(t, browser)
		})
	}
}

func TestInteractiveEnrollmentOptions(t *testing.T) {
	for _, tc := range []struct {
		name        string
		input       string
		wantBrowser bool
		wantDevice  bool
	}{
		{name: "default keeps local dashboard flow", input: "\n", wantBrowser: true},
		{name: "one keeps local dashboard flow", input: "1\n", wantBrowser: true},
		{name: "two uses remote device flow", input: "2\n", wantDevice: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			out := &strings.Builder{}
			cmd.SetIn(strings.NewReader(tc.input))
			cmd.SetOut(out)
			browser, device := false, false
			err := runInteractiveEnrollWithTTY(cmd, interactiveEnrollDeps{
				addr:      "127.0.0.1:9090",
				dbPath:    "/tmp/kite.db",
				certsDir:  "/tmp/certs",
				agentCode: "kite-test",
				browserEnroll: func(string, string, string, bool, bool) error {
					browser = true
					return nil
				},
				deviceEnroll: func(io.Writer, string, string, string, bool) error {
					device = true
					return nil
				},
			}, true)

			require.NoError(t, err)
			require.Equal(t, tc.wantBrowser, browser)
			require.Equal(t, tc.wantDevice, device)
			assert.Contains(t, out.String(), "Choose how to enroll:")
			assert.Contains(t, out.String(), "[1] Local browser sign-in")
			assert.Contains(t, out.String(), "[2] Remote browser sign-in")
			assert.Contains(t, out.String(), "app.vulnertrack.com/auth/device")
		})
	}
}
