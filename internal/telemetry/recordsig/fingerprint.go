package recordsig

import (
	"crypto/sha256"
	"encoding/hex"
)

// fingerprintOf mirrors identity.Fingerprint: "sha256:" + hex of the raw
// public key bytes. Duplicated rather than imported so a receiver-side
// verifier does not have to pull the agent identity package in.
func fingerprintOf(pub []byte) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}
