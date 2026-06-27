// Package sshkeys enumerates SSH key + known-host inventory across
// every user's ~/.ssh directory plus the system host keys in /etc/ssh.
// The collector is the credential side of the lateral-movement story:
// who can SSH IN (authorized_keys), what credentials live ON this box
// (id_*), and where this user HAS SSHed (known_hosts).
//
// Every collector is **read-only** — it parses key files, never edits
// authorized_keys, generates new keys, or modifies sshd_config.
//
// Key rows feed the MITRE ATT&CK + CWE audit pipeline:
//
//   - T1098.004 (Account Manipulation: SSH Authorized Keys) — every
//     `role='authorized'` row is a persistent access grant. Drift
//     between scans = new key landed; rotation event triggers.
//   - T1552.004 (Unsecured Credentials: Private Keys) —
//     `role='identity-private' AND has_passphrase=0` is a passwordless
//     private key sitting on disk: the canonical credential-theft win.
//   - CWE-327 (Broken/Risky Crypto) — ssh-rsa < 2048 bits, ssh-dss
//     (DSA, removed from OpenSSH 7.0+).
//   - Lateral-movement graph — `role='known-host'` rows trace where
//     this user *has* SSHed; combined with authorized_keys rows on the
//     target hosts, this builds credential-reachability across the fleet.
package sshkeys

import (
	"context"
	"crypto/md5" //#nosec G501 -- legacy fingerprint column for cross-tool joins, not for new crypto
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxKeys bounds per-scan output. A multi-user dev server with many
// machine accounts can carry hundreds of authorized_keys lines. The
// 4096 ceiling protects the SQLite write path.
const MaxKeys = 4096

// Role classifies why this key is on disk. Strings pinned to the
// host_ssh_keys.role CHECK enum.
type Role string

const (
	RoleAuthorized      Role = "authorized"
	RoleIdentityPublic  Role = "identity-public"
	RoleIdentityPrivate Role = "identity-private"
	RoleKnownHost       Role = "known-host"
	RoleHostKey         Role = "host-key"
	RoleUnknown         Role = "unknown"
)

// Key is the cross-source record produced by every collector. Mirrors
// host_ssh_keys' column shape.
type Key struct {
	SourcePath        string `json:"source_path"`
	OwnerUser         string `json:"owner_user,omitempty"`
	KeyType           string `json:"key_type,omitempty"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	FingerprintMD5    string `json:"fingerprint_md5,omitempty"`
	Comment           string `json:"comment,omitempty"`
	Options           string `json:"options,omitempty"`
	Hostname          string `json:"hostname,omitempty"`
	Role              Role   `json:"role"`
	KeyBits           int    `json:"key_bits,omitempty"`
	LineNo            int    `json:"line_no,omitempty"`
	HasPassphrase     bool   `json:"has_passphrase"`
	IsWeak            bool   `json:"is_weak"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Key, error)
}

// FingerprintBlob returns OpenSSH's canonical SHA256 + MD5 fingerprints
// of a public-key wire blob (the binary form, not the base64 wrapper).
// OpenSSH prints `SHA256:<base64-unpadded>` and `MD5:<colon-hex>`; we
// emit the digest values without the prefix so the column reads
// uniformly across tooling.
func FingerprintBlob(blob []byte) (sha string, md5hex string) {
	sum := sha256.Sum256(blob)
	sha = base64.RawStdEncoding.EncodeToString(sum[:])

	m := md5.Sum(blob) //#nosec G401 -- legacy fingerprint, not a crypto decision
	md5hex = hex.EncodeToString(m[:])
	return sha, md5hex
}

// IsWeakKeyType classifies a (key_type, key_bits) pair as deprecated
// per the OpenSSH 9.x guidance:
//
//   - ssh-dss (DSA) was removed from OpenSSH 7.0 (2015).
//   - ssh-rsa with SHA-1 signature is disabled by default since OpenSSH
//     8.8 (2021); RSA < 3072 is increasingly flagged. We use 2048 as
//     the strict-NIST minimum — anything below is hard-rejected.
//   - ecdsa-sha2-nistp256 is borderline (NIST curve, debated trust);
//     we don't flag it here — leave to a stricter audit profile.
func IsWeakKeyType(keyType string, bits int) bool {
	switch keyType {
	case "ssh-dss":
		return true
	case "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512":
		return bits > 0 && bits < 2048
	}
	return false
}

// SortKeys returns a deterministic ordering: role, source path, line
// number. Useful for golden-file tests and stable diff output.
func SortKeys(ks []Key) {
	sort.Slice(ks, func(i, j int) bool {
		if ks[i].Role != ks[j].Role {
			return ks[i].Role < ks[j].Role
		}
		if ks[i].SourcePath != ks[j].SourcePath {
			return ks[i].SourcePath < ks[j].SourcePath
		}
		if ks[i].LineNo != ks[j].LineNo {
			return ks[i].LineNo < ks[j].LineNo
		}
		return ks[i].FingerprintSHA256 < ks[j].FingerprintSHA256
	})
}

// trim is a tiny dep-free strings.TrimSpace equivalent; we inline it
// here to keep the package's strings dep at minimum.
func trim(s string) string { return strings.TrimSpace(s) }
