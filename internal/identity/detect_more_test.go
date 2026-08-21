package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Every preference resolves to SOME backend, never nil — TPM/keyring
// availability is host-dependent, so pin the invariant that holds on
// any host, plus the explicit fallback warnings paths.
func TestDetectKeyBackend_EveryPreferenceYieldsBackend(t *testing.T) {
	dir := t.TempDir()
	for _, pref := range []string{"tpm", "keyring", "file", "auto", ""} {
		assert.NotNil(t, DetectKeyBackend(pref, dir, nil),
			"preference %q must always yield a backend", pref)
	}
}

func TestReadMachineID_NeverEmptyOnRealHost(t *testing.T) {
	assert.NotEmpty(t, readMachineID(),
		"machine-id file or hostname — a stable identifier always comes back")
}
