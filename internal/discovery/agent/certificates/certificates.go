// Package certificates enumerates X.509 certificates from per-host trust
// stores: Linux PEM directories (/etc/ssl/certs, /etc/pki/ca-trust),
// macOS Keychain, Windows CertStore. The same certificate may be
// referenced under multiple symlinks (Debian uses both the Common Name
// and the OpenSSL subject-hash) — we dedupe on sha256 fingerprint so each
// logical cert appears exactly once.
//
// Every collector is **read-only** — it reads PEM files and queries
// keychains, never installs, removes, or trusts/untrusts any cert.
// Read-only is enforced by guideline 4.2 of the kite-collector project.
//
// Certificate rows feed the CWE/CAPEC audit pipeline:
//
//   - CWE-295 (Improper Certificate Validation) — self-signed certs in
//     `system-root` other than recognised anchor CAs.
//   - CWE-477 (Use of Obsolete Function) — sha1WithRSA signatures and
//     RSA-1024 / RSA-512 key sizes are deprecated.
//   - Expiry tracking — `not_after < now + 30d` drives proactive
//     rotation alerts before the outage.
//   - Rogue CA detection — `is_ca=1` certs whose fingerprint isn't in
//     the Mozilla bundle indicate MitM injection (corporate or hostile).
package certificates

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
)

// MaxCertificates bounds per-scan output. Debian's ca-certificates ships
// ~150 trusted roots; a corporate-managed host adds another 50-200 via
// MDM. The 4096 ceiling protects the SQLite write path.
const MaxCertificates = 4096

// Store classifies where the cert lives. Pinned to the
// host_certificates.store CHECK enum.
type Store string

const (
	StoreSystemRoot         Store = "system-root"
	StoreSystemIntermediate Store = "system-intermediate"
	StoreUserRoot           Store = "user-root"
	StoreUserIntermediate   Store = "user-intermediate"
	StoreCodeSigning        Store = "code-signing"
	StoreMDM                Store = "mdm"
	StoreWebhost            Store = "webhost"
	StoreOther              Store = "other"
)

// Certificate is the cross-source record produced by every collector.
// Mirrors host_certificates' column shape (slice fields serialise to JSON
// arrays via Encode helpers; string-list shape kept here for ergonomics).
type Certificate struct {
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
	Issuer            string   `json:"issuer"`
	SerialHex         string   `json:"serial_hex,omitempty"`
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	FingerprintSHA1   string   `json:"fingerprint_sha1,omitempty"`
	SignatureAlgo     string   `json:"signature_algo,omitempty"`
	KeyAlgorithm      string   `json:"key_algorithm,omitempty"`
	Subject           string   `json:"subject"`
	SourcePath        string   `json:"source_path,omitempty"`
	Store             Store    `json:"store"`
	SANIP             []string `json:"san_ip,omitempty"`
	KeyUsage          []string `json:"key_usage,omitempty"`
	SANDNS            []string `json:"san_dns,omitempty"`
	ExtKeyUsage       []string `json:"ext_key_usage,omitempty"`
	IsCA              bool     `json:"is_ca"`
	IsSelfSigned      bool     `json:"is_self_signed"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Certificate, error)
}

// ParsePEMBundle decodes every CERTIFICATE PEM block in raw and returns
// the parsed certs. Non-CERTIFICATE blocks (PRIVATE KEY, CRL) are
// skipped silently — bundle files often interleave them.
func ParsePEMBundle(raw []byte) []*x509.Certificate {
	var out []*x509.Certificate
	rest := raw
	for {
		block, remain := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remain
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue // skip malformed entries rather than fail the whole file
		}
		out = append(out, c)
	}
	return out
}

// FromX509 converts a parsed *x509.Certificate into our portable record.
// Store + SourcePath are caller-supplied since they're discovery-context.
func FromX509(c *x509.Certificate, store Store, sourcePath string) Certificate {
	cert := Certificate{
		Store:             store,
		Subject:           c.Subject.String(),
		Issuer:            c.Issuer.String(),
		SerialHex:         strings.ToLower(c.SerialNumber.Text(16)),
		FingerprintSHA256: sha256Fingerprint(c.Raw),
		FingerprintSHA1:   sha1Fingerprint(c.Raw),
		SignatureAlgo:     c.SignatureAlgorithm.String(),
		KeyAlgorithm:      keyAlgorithmString(c),
		KeyUsage:          keyUsageList(c.KeyUsage),
		ExtKeyUsage:       extKeyUsageList(c.ExtKeyUsage),
		SANDNS:            append([]string(nil), c.DNSNames...),
		SANIP:             ipStrings(c.IPAddresses),
		NotBefore:         c.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:          c.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		SourcePath:        sourcePath,
		IsCA:              c.IsCA,
		IsSelfSigned:      isSelfSigned(c),
	}
	sort.Strings(cert.KeyUsage)
	sort.Strings(cert.ExtKeyUsage)
	sort.Strings(cert.SANDNS)
	sort.Strings(cert.SANIP)
	return cert
}

// IsWeak reports whether a certificate uses deprecated crypto. Drives the
// CWE-477 audit query. SHA-1 signatures + RSA keys ≤ 1024 bits qualify.
func IsWeak(c Certificate) bool {
	sa := strings.ToLower(c.SignatureAlgo)
	if strings.Contains(sa, "sha1") || strings.Contains(sa, "md5") {
		return true
	}
	if strings.HasPrefix(c.KeyAlgorithm, "RSA-") {
		// Extract bit count: "RSA-1024" → 1024
		var bits int
		if _, err := fmt.Sscanf(c.KeyAlgorithm, "RSA-%d", &bits); err == nil {
			if bits <= 1024 {
				return true
			}
		}
	}
	return false
}

// SortCertificates returns a deterministic ordering: by store, then
// fingerprint (the natural key). Useful for golden tests + stable diffs.
func SortCertificates(cs []Certificate) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Store != cs[j].Store {
			return cs[i].Store < cs[j].Store
		}
		return cs[i].FingerprintSHA256 < cs[j].FingerprintSHA256
	})
}
