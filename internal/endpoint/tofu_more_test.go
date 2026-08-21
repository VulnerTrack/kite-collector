package endpoint

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckTOFU_PinWriteFailureSurfaces(t *testing.T) {
	t.Parallel()

	cert := selfSignedCert(t)
	missingDir := filepath.Join(t.TempDir(), "never-created")

	err := CheckTOFU(missingDir, cert, nil) // nil logger must default, not panic
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pin server fingerprint")
}

func TestCheckTOFU_UnreadableStoredFingerprint(t *testing.T) {
	t.Parallel()

	cert := selfSignedCert(t)
	credDir := t.TempDir()
	// A directory where the fingerprint file should be: ReadFile fails with
	// something other than not-exist, which must surface, not re-pin.
	require.NoError(t, os.Mkdir(filepath.Join(credDir, "server-fingerprint.sha256"), 0o755))

	err := CheckTOFU(credDir, cert, testLogger())
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrFingerprintMismatch,
		"an IO failure must not masquerade as a MITM verdict")
	assert.Contains(t, err.Error(), "read stored fingerprint")
}

func TestAcceptNewFingerprint_NilLoggerAndMissingFile(t *testing.T) {
	t.Parallel()

	// Nothing pinned yet: removing is a no-op success even with no logger.
	require.NoError(t, AcceptNewFingerprint(t.TempDir(), nil))
}

func TestAcceptNewFingerprint_RemovesExistingPin(t *testing.T) {
	t.Parallel()

	credDir := t.TempDir()
	fpPath := filepath.Join(credDir, "server-fingerprint.sha256")
	require.NoError(t, os.WriteFile(fpPath, []byte("sha256:deadbeef"), 0o600))

	require.NoError(t, AcceptNewFingerprint(credDir, testLogger()))
	_, err := os.Stat(fpPath)
	assert.True(t, os.IsNotExist(err), "the old pin must be gone so the next connection re-pins")
}

func TestAcceptNewFingerprint_RemoveFailureSurfaces(t *testing.T) {
	t.Parallel()

	credDir := t.TempDir()
	// A non-empty directory at the fingerprint path makes os.Remove fail
	// with something other than not-exist.
	fpPath := filepath.Join(credDir, "server-fingerprint.sha256")
	require.NoError(t, os.MkdirAll(filepath.Join(fpPath, "child"), 0o755))

	err := AcceptNewFingerprint(credDir, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove old fingerprint")
}
