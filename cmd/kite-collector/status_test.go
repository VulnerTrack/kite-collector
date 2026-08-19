package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// writeTestEnrollmentPEMs writes a self-signed cert as agent.pem + ca.pem and
// its key as agent-key.pem — the three files installer.EnrollmentFiles
// expects — with the given expiry.
func writeTestEnrollmentPEMs(t *testing.T, dir string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kite-test-agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	require.NoError(t, os.WriteFile(filepath.Join(dir, "agent.pem"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.pem"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "agent-key.pem"), keyPEM, 0o600))
}

func TestBuildStatusReport_FreshHost(t *testing.T) {
	certsDir := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "kite.db")

	r := buildStatusReport(context.Background(), certsDir, dbPath, "", false, false)

	assert.Equal(t, "not enrolled", r.Enrollment.State)
	assert.False(t, r.Enrollment.Enrolled)
	assert.False(t, r.Database.Exists)
	assert.Nil(t, r.LastScan)
	assert.Equal(t, certsDir, r.Enrollment.CertsDir)
	assert.Equal(t, dbPath, r.Database.Path)
	// status must never create the database as a side effect.
	_, err := os.Stat(dbPath)
	assert.True(t, os.IsNotExist(err), "status must be read-only")
}

func TestBuildStatusReport_EnrolledWithCertExpiry(t *testing.T) {
	certsDir := t.TempDir()
	writeTestEnrollmentPEMs(t, certsDir, time.Now().Add(60*24*time.Hour))
	dbPath := filepath.Join(t.TempDir(), "kite.db")

	r := buildStatusReport(context.Background(), certsDir, dbPath, "", false, false)

	assert.Equal(t, "enrolled", r.Enrollment.State)
	assert.True(t, r.Enrollment.Enrolled)
	assert.NotEmpty(t, r.Enrollment.CertNotAfter)
	assert.InDelta(t, 59, r.Enrollment.CertDaysLeft, 1)
}

func TestBuildStatusReport_ExpiredCertStillReports(t *testing.T) {
	certsDir := t.TempDir()
	writeTestEnrollmentPEMs(t, certsDir, time.Now().Add(-24*time.Hour))
	dbPath := filepath.Join(t.TempDir(), "kite.db")

	r := buildStatusReport(context.Background(), certsDir, dbPath, "", false, false)
	assert.True(t, r.Enrollment.Enrolled)
	assert.Negative(t, r.Enrollment.CertDaysLeft)
}

func TestCertNotAfter_Errors(t *testing.T) {
	_, err := certNotAfter(filepath.Join(t.TempDir(), "missing.pem"))
	require.Error(t, err)

	bad := filepath.Join(t.TempDir(), "bad.pem")
	require.NoError(t, os.WriteFile(bad, []byte("not a pem"), 0o600))
	_, err = certNotAfter(bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM block")
}

func TestStatusCommand_JSONOutput(t *testing.T) {
	certsDir := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "kite.db")

	cmd := newStatusCmd()
	cmd.SetArgs([]string{"--json", "--certs-dir", certsDir, "--db", dbPath})
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.Execute())

	var r statusReport
	require.NoError(t, json.Unmarshal(out.Bytes(), &r))
	assert.Equal(t, "not enrolled", r.Enrollment.State)
	assert.Equal(t, dbPath, r.Database.Path)
}

func TestInstallEvidenceScore_RunningServiceDominatesEmptyDir(t *testing.T) {
	running := installer.State{ServiceState: installer.ServiceRunning}
	nothing := installer.State{ServiceState: installer.ServiceNotInstalled, CertsDirExists: true}

	assert.Greater(t, installEvidenceScore(running), installEvidenceScore(nothing),
		"a running service outweighs nothing")
	assert.Equal(t, 0, installEvidenceScore(nothing),
		"an existing-but-empty certs dir is no evidence")
	assert.Greater(t,
		installEvidenceScore(installer.State{CertsEnrolled: true, BinaryPresent: true}),
		installEvidenceScore(installer.State{BinaryPresent: true}),
		"enrollment is stronger evidence than a bare binary")
}

func TestNextActionHint_MapsTokensToCommands(t *testing.T) {
	assert.Contains(t, nextActionHint("install"), "kite-collector install")
	assert.Contains(t, nextActionHint("enroll"), "kite-collector enroll")
	assert.Contains(t, nextActionHint("start_service"), "service start")
	assert.Equal(t, "ready", nextActionHint("ready"))
	assert.Equal(t, "custom-token", nextActionHint("custom-token"))
}
