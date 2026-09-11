package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

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

func TestPlainEnrollmentUsesDeviceFlowWhenLocalBrowserIsUnavailable(t *testing.T) {
	for _, sshVar := range []string{"", "SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		t.Run(sshVar, func(t *testing.T) {
			for _, name := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
				t.Setenv(name, "")
			}
			t.Setenv("DISPLAY", ":0")
			t.Setenv("PATH", t.TempDir())
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

func TestPlainEnrollmentUsesLocalFlowWhenBrowserIsAvailable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux browser prerequisite test")
	}
	for _, name := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		t.Setenv(name, "")
	}
	t.Setenv("DISPLAY", ":0")
	t.Setenv("WAYLAND_DISPLAY", "")
	binDir := t.TempDir()
	for _, name := range []string{"xdg-open", "firefox"} {
		require.NoError(t, os.WriteFile(filepath.Join(binDir, name), []byte("#!/bin/sh\n"), 0o755))
	}
	t.Setenv("PATH", binDir)

	device, browser := false, false
	cmd := newEnrollCmdWithFlows(
		func(_ io.Writer, _, _, _ string, _ bool) error { device = true; return nil },
		func(_, _, _ string, noBrowser, _ bool) error {
			browser = true
			require.False(t, noBrowser)
			return nil
		},
	)
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	require.True(t, browser)
	require.False(t, device)
}

func TestPlainEnrollmentUsesRemoteFlowOverSSHEvenWithBrowser(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux browser prerequisite test")
	}
	t.Setenv("SSH_CONNECTION", "remote session")
	t.Setenv("DISPLAY", ":0")
	binDir := t.TempDir()
	for _, name := range []string{"xdg-open", "firefox"} {
		require.NoError(t, os.WriteFile(filepath.Join(binDir, name), []byte("#!/bin/sh\n"), 0o755))
	}
	t.Setenv("PATH", binDir)

	device, browser := false, false
	cmd := newEnrollCmdWithFlows(
		func(_ io.Writer, _, _, _ string, _ bool) error { device = true; return nil },
		func(_, _, _ string, _, _ bool) error { browser = true; return nil },
	)
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	require.True(t, device)
	require.False(t, browser)
}
