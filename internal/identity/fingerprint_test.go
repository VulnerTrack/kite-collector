package identity

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMachineFingerprint_Format(t *testing.T) {
	fp := MachineFingerprint()
	require.NotEmpty(t, fp)

	// Must start with "sha256:" prefix.
	assert.True(t, strings.HasPrefix(fp, "sha256:"),
		"fingerprint must start with sha256: prefix, got %q", fp)

	// SHA-256 hex = 64 chars after prefix.
	parts := strings.SplitN(fp, ":", 2)
	require.Len(t, parts, 2)
	assert.Len(t, parts[1], 64, "SHA-256 hex digest must be 64 characters")
}

func TestMachineFingerprint_Deterministic(t *testing.T) {
	fp1 := MachineFingerprint()
	fp2 := MachineFingerprint()
	assert.Equal(t, fp1, fp2, "repeated calls must return the same fingerprint")
}

func TestSortedMACs_NoLoopback(t *testing.T) {
	macs := sortedMACs()
	for _, mac := range macs {
		assert.NotEqual(t, "00:00:00:00:00:00", mac,
			"loopback interfaces should be excluded")
	}
}
