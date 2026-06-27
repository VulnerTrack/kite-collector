package enrollment

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/identity"
)

func TestStoreCertificates(t *testing.T) {
	dir := t.TempDir()

	result := &Result{
		CACertificate:     []byte("--- CA CERT ---"),
		ClientCertificate: []byte("--- CLIENT CERT ---"),
		ClientKey:         []byte("--- CLIENT KEY ---"),
	}

	err := StoreCertificates(dir, result)
	require.NoError(t, err)

	// Verify files exist with correct content.
	ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	require.NoError(t, err)
	assert.Equal(t, result.CACertificate, ca)

	cert, err := os.ReadFile(filepath.Join(dir, "agent.pem"))
	require.NoError(t, err)
	assert.Equal(t, result.ClientCertificate, cert)

	key, err := os.ReadFile(filepath.Join(dir, "agent-key.pem"))
	require.NoError(t, err)
	assert.Equal(t, result.ClientKey, key)

	// Verify private key has restrictive permissions.
	info, err := os.Stat(filepath.Join(dir, "agent-key.pem"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestMachineFingerprint(t *testing.T) {
	fp := identity.MachineFingerprint()
	assert.NotEmpty(t, fp)
}
