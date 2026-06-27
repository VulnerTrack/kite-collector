// Package winauthkeys inventories OpenSSH `authorized_keys` files
// across the canonical Windows and POSIX locations:
//
//	Windows admin:  C:\ProgramData\ssh\administrators_authorized_keys
//	Windows user:   C:\Users\<u>\.ssh\authorized_keys
//	Linux/macOS:    /root/.ssh/authorized_keys
//	Linux/macOS:    /home/<u>/.ssh/authorized_keys
//	macOS:          /Users/<u>/.ssh/authorized_keys
//
// File-based discovery is the deliberate design choice — the SSH
// daemon walks the same files at login. A new entry that wasn't
// approved is the canonical MITRE T1098.004 (Account Manipulation:
// SSH Authorized Keys) persistence shape; this collector emits one
// row per key entry so the audit pipeline can diff between scans.
//
// Headline finding shapes:
//
//   - `is_high_privilege_target=1` — key lives in an admin-scope
//     file (Windows administrators_authorized_keys or
//     /root/.ssh/authorized_keys). One key here = root-equivalent
//     login.
//   - `is_weak_key_type=1` — DSA (broken since 2015), ssh-rsa
//     under 2048 bits, ECDSA on the nistp192 curve.
//   - `is_no_comment=1` — anonymous key with no `user@host`
//     trailer. Legitimate ssh-keygen always appends one.
//   - `has_dangerous_options=1` — options that broaden access
//     (no `command=` lock, port-forwarding allowed, …) on a
//     high-privilege key.
//
// Read-only by intent — we parse the files only, never invoke
// ssh-add / ssh-keygen. (Project guideline 4.2.)
package winauthkeys

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxKeys bounds per-scan output. Most users have 0-3 entries; an
// admin authorized_keys with 30+ entries is enterprise territory.
// The 4096 ceiling covers shared-jumphost installs.
const MaxKeys = 4096

// KeyScope tags which file (and thus security tier) the key
// belongs to. Pinned to the host_authorized_keys.key_scope CHECK
// enum.
type KeyScope string

const (
	ScopeAdmin   KeyScope = "admin" // Windows administrators_authorized_keys
	ScopeRoot    KeyScope = "root"  // /root/.ssh/authorized_keys
	ScopeUser    KeyScope = "user"  // per-user files
	ScopeUnknown KeyScope = "unknown"
)

// KeyType is the normalised algorithm family pinned to the
// host_authorized_keys.key_type CHECK enum.
type KeyType string

const (
	KeyTypeRSA       KeyType = "rsa"
	KeyTypeEd25519   KeyType = "ed25519"
	KeyTypeECDSA     KeyType = "ecdsa"
	KeyTypeDSA       KeyType = "dsa"
	KeyTypeRSASHA2   KeyType = "rsa-sha2"
	KeyTypeSKEd25519 KeyType = "sk-ed25519"
	KeyTypeSKECDSA   KeyType = "sk-ecdsa"
	KeyTypeUnknown   KeyType = "unknown"
)

// MinRSABits is the SHA-2-era floor for ssh-rsa key length. Keys
// shorter than this flag is_weak_key_type=1.
const MinRSABits = 2048

// Key mirrors host_authorized_keys' column shape exactly.
type Key struct {
	Comment               string   `json:"comment,omitempty"`
	FileHash              string   `json:"file_hash"`
	Options               string   `json:"options,omitempty"`
	UserProfile           string   `json:"user_profile,omitempty"`
	KeyScope              KeyScope `json:"key_scope"`
	KeyType               KeyType  `json:"key_type"`
	KeyTypeRaw            string   `json:"key_type_raw"`
	KeyFingerprint        string   `json:"key_fingerprint,omitempty"`
	FilePath              string   `json:"file_path"`
	KeyBits               int      `json:"key_bits,omitempty"`
	LineNo                int      `json:"line_no"`
	HasOptions            bool     `json:"has_options"`
	IsAdministratorsKey   bool     `json:"is_administrators_key"`
	IsRootKey             bool     `json:"is_root_key"`
	IsWeakKeyType         bool     `json:"is_weak_key_type"`
	IsNoComment           bool     `json:"is_no_comment"`
	HasDangerousOptions   bool     `json:"has_dangerous_options"`
	IsHighPrivilegeTarget bool     `json:"is_high_privilege_target"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Key, error)
}

// HashContents returns the SHA-256 hex of the entire file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NormalizeKeyType maps a raw key-type token (e.g. `ssh-rsa`,
// `ssh-ed25519`, `ecdsa-sha2-nistp256`, `rsa-sha2-256`) to our
// KeyType enum. Empty input returns KeyTypeUnknown.
func NormalizeKeyType(raw string) KeyType {
	r := strings.ToLower(strings.TrimSpace(raw))
	switch r {
	case "ssh-rsa":
		return KeyTypeRSA
	case "ssh-dss":
		return KeyTypeDSA
	case "ssh-ed25519":
		return KeyTypeEd25519
	case "sk-ssh-ed25519@openssh.com":
		return KeyTypeSKEd25519
	}
	switch {
	case strings.HasPrefix(r, "ecdsa-sha2-"):
		return KeyTypeECDSA
	case strings.HasPrefix(r, "sk-ecdsa-sha2-"):
		return KeyTypeSKECDSA
	case strings.HasPrefix(r, "rsa-sha2-"):
		return KeyTypeRSASHA2
	}
	return KeyTypeUnknown
}

// FingerprintKey returns a short (12 hex chars) prefix of
// sha256(base64-decoded key blob). Non-base64 input returns "".
// Sufficient for cross-scan join + audit-pipeline correlation
// without persisting the full key.
func FingerprintKey(b64Blob string) string {
	body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64Blob))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:6])
}

// ExtractRSABits attempts to recover the RSA modulus bit-length
// from the SSH wire format embedded in the base64 blob. The
// format is:
//
//	uint32 len, bytes (algo name)
//	uint32 len, bytes (e — public exponent, mpint)
//	uint32 len, bytes (n — modulus, mpint)
//
// The modulus length in bits is approximately
// `8 * len(n) - leading_zero_bits(n)`; we approximate as
// `8 * (len(n) - 1)` to drop the single leading zero byte SSH
// always prepends for non-negative mpints. Returns 0 when parsing
// fails or the algorithm isn't ssh-rsa.
func ExtractRSABits(b64Blob string) int {
	body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64Blob))
	if err != nil || len(body) < 4 {
		return 0
	}
	cursor := 0
	read := func(n int) []byte {
		if cursor+n > len(body) {
			return nil
		}
		out := body[cursor : cursor+n]
		cursor += n
		return out
	}
	readMpint := func() []byte {
		lenBytes := read(4)
		if lenBytes == nil {
			return nil
		}
		ln := int(binary.BigEndian.Uint32(lenBytes))
		if ln < 0 || cursor+ln > len(body) {
			return nil
		}
		return read(ln)
	}
	algo := readMpint()
	if algo == nil || string(algo) != "ssh-rsa" {
		return 0
	}
	// Skip e.
	if e := readMpint(); e == nil {
		return 0
	}
	n := readMpint()
	if len(n) < 2 {
		return 0
	}
	// SSH prepends a 0x00 byte to non-negative mpints. Skip when
	// present so the bit count reflects the actual modulus.
	if n[0] == 0x00 {
		n = n[1:]
	}
	return 8 * len(n)
}

// DangerousOptionTokens is the curated set of authorized_keys
// options that broaden access. We don't flag the *absence* of
// `command=` directly — that's normal for interactive use; we
// flag the presence of explicit "permit-everything" options.
func DangerousOptionTokens() []string {
	return []string{
		"permitlocalcommand",
		"agent-forwarding",
		"port-forwarding",
		"x11-forwarding",
		"pty",
	}
}

// HasDangerousOptions reports whether the options string contains
// at least one explicitly permissive token. Empty options return
// false — no options is the safer default.
func HasDangerousOptions(options string) bool {
	if strings.TrimSpace(options) == "" {
		return false
	}
	lower := strings.ToLower(options)
	for _, t := range DangerousOptionTokens() {
		if strings.Contains(lower, t) {
			// Only flag when the token isn't prefixed with `no-`.
			// E.g. `no-port-forwarding` is a HARDENING option,
			// not a dangerous one.
			if !strings.Contains(lower, "no-"+t) {
				return true
			}
		}
	}
	return false
}

// AnnotateSecurity sets the derived booleans on a Key that has
// its raw fields populated.
func AnnotateSecurity(k *Key) {
	k.HasOptions = strings.TrimSpace(k.Options) != ""
	k.IsAdministratorsKey = k.KeyScope == ScopeAdmin
	k.IsRootKey = k.KeyScope == ScopeRoot
	k.IsNoComment = strings.TrimSpace(k.Comment) == ""
	k.HasDangerousOptions = HasDangerousOptions(k.Options)
	switch k.KeyType {
	case KeyTypeDSA:
		k.IsWeakKeyType = true
	case KeyTypeRSA, KeyTypeRSASHA2:
		if k.KeyBits > 0 && k.KeyBits < MinRSABits {
			k.IsWeakKeyType = true
		}
	case KeyTypeECDSA:
		// `ecdsa-sha2-nistp192` is the only weak ECDSA variant we
		// see in the wild. The raw type string carries the curve.
		if strings.Contains(strings.ToLower(k.KeyTypeRaw), "nistp192") {
			k.IsWeakKeyType = true
		}
	case KeyTypeEd25519, KeyTypeSKEd25519, KeyTypeSKECDSA:
		// Modern algorithms — never flagged weak.
	case KeyTypeUnknown:
		// Unknown algorithm — leave the flag cleared and let the
		// audit pipeline decide.
	}
	k.IsHighPrivilegeTarget = k.IsAdministratorsKey || k.IsRootKey
}

// SortKeys returns a deterministic ordering by file path then
// line number.
func SortKeys(ks []Key) {
	sort.Slice(ks, func(i, j int) bool {
		if ks[i].FilePath != ks[j].FilePath {
			return ks[i].FilePath < ks[j].FilePath
		}
		return ks[i].LineNo < ks[j].LineNo
	})
}
