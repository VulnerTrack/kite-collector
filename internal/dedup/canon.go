package dedup

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// Sep is the unit-separator byte (ASCII US, 0x1f) used to delimit fields
// inside SHA-256 pre-images. It is never legal in a canonical signal value
// produced by this file, which keeps the digest space free of the classic
// 'foo|bar' vs 'fo|obar' separator-collision class.
const Sep = "\x1f"

// CanonFQDN normalizes a hostname or fully-qualified domain name: lowercase,
// trailing dot stripped, repeated/empty labels rejected. Returns "" for any
// input that cannot be safely treated as a DNS-style name.
func CanonFQDN(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return ""
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return ""
		}
	}
	return s
}

// CanonMAC returns the 12-char lowercase-hex form of a MAC address. Accepts
// colon-, hyphen-, dot-separated and bare-hex inputs. Returns "" when the
// input is not a valid 6-byte MAC.
func CanonMAC(s string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return ""
	}
	return hex.EncodeToString(hw)
}

// CanonSortedMACs canonicalizes each MAC, deduplicates, sorts ascending,
// and joins with Sep. Returns nil when no MACs survive canonicalization.
func CanonSortedMACs(in []string) []byte {
	seen := make(map[string]struct{}, len(in))
	for _, m := range in {
		if c := CanonMAC(m); c != "" {
			seen[c] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return []byte(strings.Join(out, Sep))
}

// CanonUUID returns the lowercase hyphenated 8-4-4-4-12 form of a UUID.
// Returns "" for non-UUID input.
func CanonUUID(s string) string {
	u, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return u.String()
}

// CanonLowerHex trims, lowercases, and validates a hex string. Returns ""
// if the input contains any non-hex character or has odd length.
func CanonLowerHex(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}

// CanonProvider returns a normalized cloud-provider tag, or "" when the
// input is not in the recognized allowlist. The allowlist is intentional:
// silent acceptance of unknown providers would let typo'd values ("aws " vs
// "aws") collide in the digest space.
func CanonProvider(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "aws", "azure", "gcp", "oci", "linode", "digitalocean", "vultr", "hetzner":
		return s
	default:
		return ""
	}
}

// CanonAccount canonicalizes a cloud account identifier per provider rules.
// AWS: 12-digit zero-padded numeric string.
// GCP: lowercase project_id (RFC 1035 form, 6–30 chars, starts with letter).
// Azure: lowercase hyphenated subscription UUID.
// Returns "" for any other provider or invalid input.
func CanonAccount(provider, raw string) string {
	raw = strings.TrimSpace(raw)
	switch CanonProvider(provider) {
	case "aws":
		if raw == "" || len(raw) > 12 || !isDigits(raw) {
			return ""
		}
		return strings.Repeat("0", 12-len(raw)) + raw
	case "azure":
		return CanonUUID(raw)
	case "gcp":
		raw = strings.ToLower(raw)
		if len(raw) < 6 || len(raw) > 30 {
			return ""
		}
		if raw[0] < 'a' || raw[0] > 'z' {
			return ""
		}
		for _, r := range raw {
			if !(r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
				return ""
			}
		}
		return raw
	default:
		return ""
	}
}

// CanonVCSURL normalizes a VCS URL: force https scheme, lowercase host,
// drop user:pass, drop default port, drop query/fragment, strip trailing
// slash, strip ".git" suffix. Accepts the SSH-shorthand form
// "git@host:org/repo" and rewrites it to "https://host/org/repo".
// Returns "" when the input cannot be parsed.
func CanonVCSURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// SSH shorthand rewrite: git@host:path -> https://host/path
	if !strings.Contains(raw, "://") {
		if at := strings.IndexByte(raw, '@'); at >= 0 {
			if colon := strings.IndexByte(raw[at+1:], ':'); colon >= 0 {
				host := raw[at+1 : at+1+colon]
				path := raw[at+1+colon+1:]
				raw = "https://" + host + "/" + path
			}
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	u.Scheme = "https"
	u.Host = strings.ToLower(u.Host)
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	// Strip default-port suffix from host.
	if h, p, err := net.SplitHostPort(u.Host); err == nil && (p == "443" || p == "80") {
		u.Host = h
	}
	p := strings.TrimSuffix(u.Path, "/")
	p = strings.TrimSuffix(p, ".git")
	u.Path = p
	return u.String()
}

// CanonOCIDigest validates that s is a canonical "sha256:<64 hex>" reference
// and returns it lowercased. Tag-only references ("nginx:latest") are
// rejected — they are mutable and would break content-addressable identity.
func CanonOCIDigest(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 7+64 || s[:7] != "sha256:" {
		return ""
	}
	if _, err := hex.DecodeString(s[7:]); err != nil {
		return ""
	}
	return s
}

// CanonSSHHostKey returns the SHA-256 hex digest of an SSH public key's
// wire bytes. Accepts the OpenSSH single-line format
// ("ssh-ed25519 AAAA… [comment]"); the middle field is base64-decoded and
// hashed. Returns "" for unparseable input.
func CanonSSHHostKey(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// OpenSSH form: "<type> <base64> [comment]"
	parts := strings.Fields(raw)
	if len(parts) < 2 {
		return ""
	}
	wire, err := decodeBase64(parts[1])
	if err != nil || len(wire) == 0 {
		return ""
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

// CanonTLSCertSPKI parses a PEM- or DER-encoded X.509 certificate and
// returns the SHA-256 hex digest of its SubjectPublicKeyInfo. SPKI is
// stable across certificate reissuance with the same keypair, which is
// the property we want for asset identity. Returns "" on parse failure.
func CanonTLSCertSPKI(raw []byte) string {
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// CanonStringSet canonicalizes a set of opaque strings: trim, lowercase,
// deduplicate, sort, and join with Sep. Returns nil if no element survives.
// Useful for mDNS service sets and similar order-independent collections.
func CanonStringSet(in []string) []byte {
	seen := make(map[string]struct{}, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return []byte(strings.Join(out, Sep))
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// decodeBase64 accepts both standard and URL-safe base64 with or without
// padding. SSH wire keys use standard base64 with padding; we accept the
// rest defensively to be lenient at the boundary.
func decodeBase64(s string) ([]byte, error) {
	// Standard with padding is the SSH default. Fall back to no-padding
	// when present (a single round of trimming covers both URL-safe and
	// standard variants).
	if b, err := stdB64Decode(s); err == nil {
		return b, nil
	}
	return stdB64Decode(strings.TrimRight(s, "="))
}
